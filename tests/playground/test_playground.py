"""Local safety and recovery contracts for the disposable Vault launcher."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("secretwright_playground_runtime_test", ROOT / "scripts/playground.py")
playground = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = playground
SPEC.loader.exec_module(playground)


class PlaygroundTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.directory = self.root / ".playground"
        self.patch = patch.object(playground, "STATE_DIR", self.directory)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.output = io.StringIO()
        self.error = io.StringIO()
        self.calls = []
        self.provisions = 0

    def state(self, ready=True):
        return {"version": 1, "owner": "abc12345" * 4,
                "name": "secretwright-playground-" + "abc12345" * 4,
                "address": "http://127.0.0.1:32123", "ready": ready}

    def prepare(self, ready=True):
        self.directory.mkdir(mode=0o700)
        state = self.state(ready)
        playground.save_state(state, new=True)
        playground.write_private(self.directory / "root-token", "private-test-root-never-print")
        return state

    def container(self, state=None):
        state = state or playground.load_state()
        return {"Id": "d" * 64, "Name": "/" + state["name"], "Config": {"Labels": {playground.LABEL: state["owner"]}},
                "State": {"Running": True},
                "NetworkSettings": {"Ports": {"8200/tcp": [{"HostIp": "127.0.0.1", "HostPort": "32123"}]}}}

    def fake_docker(self, arguments, *, env=None, check=True):
        self.calls.append((list(arguments), env))
        if arguments[0] == "run":
            # Even if Docker creation loses its response, down must have enough
            # durable ownership information to recover the exact resource.
            state = playground.load_state()
            self.assertFalse(state["ready"])
            self.assertIsNone(state["address"])
            token = playground.read_private(self.directory / "root-token")
            self.assertNotIn(token, " ".join(arguments))
            self.assertEqual(env["VAULT_DEV_ROOT_TOKEN_ID"], token)
        body = json.dumps([self.container()]) if arguments[:2] == ["container", "inspect"] else ""
        return subprocess.CompletedProcess(arguments, 0, body, "")

    @contextlib.contextmanager
    def fixture(self, *, provision_error=None):
        def provision(_runtime, state):
            self.provisions += 1
            self.assertFalse(state["ready"])
            if provision_error:
                raise playground.PlaygroundError(provision_error)

        with patch.object(playground, "local_docker"), \
             patch.object(playground, "docker", side_effect=self.fake_docker), \
             patch.object(playground, "find_binary", return_value="/trusted/secretwright"), \
             patch.object(playground, "wait_ready"), \
             patch.object(playground, "vault_request"), \
             patch.object(playground, "scenario", return_value=types.SimpleNamespace(provision=provision)), \
             contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.error):
            yield

    def test_up_records_private_ownership_before_start_and_does_not_print_root(self):
        with self.fixture():
            self.assertEqual(playground.main(["up"]), 0)
        state = playground.load_state()
        self.assertTrue(state["ready"])
        self.assertEqual(state["address"], "http://127.0.0.1:32123")
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        for path in (self.directory / "state.json", self.directory / "root-token", self.directory / "env.sh"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        token = playground.read_private(self.directory / "root-token")
        self.assertNotIn(token, self.output.getvalue() + self.error.getvalue())
        run = next(arguments for arguments, _ in self.calls if arguments[0] == "run")
        self.assertIn("127.0.0.1::8200", run)
        self.assertNotIn("--volume", run)
        self.assertNotIn("logs", [arguments[0] for arguments, _ in self.calls])

    def test_repeated_up_preserves_edits_tokens_and_exercise_files(self):
        with self.fixture():
            playground.up()
            token = (self.directory / "root-token").read_bytes()
            state = (self.directory / "state.json").read_bytes()
            sentinel = self.directory / "user-edited-secret.json"
            sentinel.write_text("a user's exercise result")
            playground.up()
        self.assertEqual(self.provisions, 1)
        self.assertEqual(len([arguments for arguments, _ in self.calls if arguments[0] == "run"]), 1)
        self.assertEqual((self.directory / "root-token").read_bytes(), token)
        self.assertEqual((self.directory / "state.json").read_bytes(), state)
        self.assertEqual(sentinel.read_text(), "a user's exercise result")

    def test_repeated_up_restores_missing_environment_without_reseeding(self):
        with self.fixture():
            playground.up()
            original = (self.directory / "env.sh").read_bytes()
            (self.directory / "env.sh").unlink()
            playground.up()
        self.assertEqual(self.provisions, 1)
        self.assertEqual((self.directory / "env.sh").read_bytes(), original)

    def test_environment_refuses_links_loose_permissions_and_modified_content(self):
        state = self.prepare()
        environment = self.directory / "env.sh"
        outside = self.root / "unrelated"
        outside.write_text("preserve me")
        with patch.object(playground, "find_binary", return_value="/trusted/secretwright"):
            environment.symlink_to(outside)
            with self.assertRaises(playground.PlaygroundError):
                playground.ensure_environment(state)
            self.assertEqual(outside.read_text(), "preserve me")
            environment.unlink()
            environment.write_text("unrelated file")
            with self.assertRaises(playground.PlaygroundError):
                playground.ensure_environment(state)
            self.assertEqual(environment.read_text(), "unrelated file")
            environment.chmod(0o600)
            with self.assertRaisesRegex(playground.PlaygroundError, "differs"):
                playground.ensure_environment(state)
            self.assertEqual(environment.read_text(), "unrelated file")

    def test_sourced_environment_runs_the_cli_directly_and_quotes_shell_metacharacters(self):
        # Both the token file and executable directory contain characters that
        # would run shell substitutions if the generated file quoted them badly.
        special = self.root / "lab ' $(touch injected-dollar) `touch injected-backtick`"
        special.mkdir(mode=0o700)
        self.directory = special / ".playground"
        binary_directory = special / "bin"
        binary_directory.mkdir()
        binary = binary_directory / "secretwright"
        binary.write_text("#!" + sys.executable + "\n" +
                          "import json, os, sys\n" +
                          "print(json.dumps({'binary':sys.argv[0], 'arguments':sys.argv[1:],\n" +
                          " 'address':os.environ.get('VAULT_ADDR'),\n" +
                          " 'namespace':os.environ.get('VAULT_NAMESPACE'),\n" +
                          " 'token_matches':os.environ.get('VAULT_TOKEN')=='private-test-root-never-print',\n" +
                          " 'vault_names':sorted(k for k in os.environ if k.startswith('VAULT_')),\n" +
                          " 'proxy':os.environ.get('HTTP_PROXY'),\n" +
                          " 'no_proxy':os.environ.get('no_proxy')}))\n")
        binary.chmod(0o700)
        with patch.object(playground, "STATE_DIR", self.directory), \
             patch.object(playground, "find_binary", return_value=str(binary)):
            state = self.prepare()
            playground.ensure_environment(state)
        body = (self.directory / "env.sh").read_text()
        self.assertNotIn("private-test-root-never-print", body)
        inherited = dict(os.environ, VAULT_ADDR="https://production.example",
                         VAULT_AGENT_ADDR="https://agent.example", VAULT_NAMESPACE="operator",
                         VAULT_TOKEN="operator-token", VAULT_SKIP_VERIFY="true",
                         VAULT_CACERT="/missing/ca", VAULT_CACERT_BYTES="invalid",
                         VAULT_CAPATH="/missing/ca-dir", VAULT_CLIENT_CERT="/missing/client-cert",
                         VAULT_CLIENT_KEY="/missing/client-key", VAULT_TLS_SERVER_NAME="production.example",
                         VAULT_CLIENT_TIMEOUT="invalid", HTTP_PROXY="http://proxy.example:8080",
                         no_proxy="existing.internal")
        # Source the file once, then invoke the normal executable. There is no
        # playground process or Docker invocation on this command path.
        command = ". " + shlex.quote(str(self.directory / "env.sh")) + "\nsecretwright tree /playground\n"
        result = subprocess.run(["/bin/sh", "-c", command], cwd=self.root, env=inherited,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["binary"], str(binary))
        self.assertEqual(report["arguments"], ["tree", "/playground"])
        self.assertEqual(report["address"], state["address"])
        self.assertEqual(report["namespace"], "")
        self.assertTrue(report["token_matches"])
        self.assertEqual(report["vault_names"], ["VAULT_ADDR", "VAULT_NAMESPACE", "VAULT_TOKEN"])
        self.assertEqual(report["proxy"], inherited["HTTP_PROXY"])
        self.assertEqual(report["no_proxy"], "existing.internal,127.0.0.1,localhost")
        self.assertNotIn("private-test-root-never-print", result.stdout + result.stderr)
        self.assertFalse((self.root / "injected-dollar").exists())
        self.assertFalse((self.root / "injected-backtick").exists())

    def test_source_failure_clears_previous_connection_instead_of_exporting_empty_token(self):
        state = self.prepare()
        with patch.object(playground, "find_binary", return_value="/trusted/secretwright"):
            playground.ensure_environment(state)
        token_file = self.directory / "root-token"
        for missing in (True, False):
            if missing:
                token_file.unlink()
            else:
                playground.write_private(token_file, "")
            with self.subTest(missing=missing):
                command = (". " + shlex.quote(str(self.directory / "env.sh")) + "; result=$?\n"
                           "[ \"$result\" -eq 1 ] && [ -z \"${VAULT_ADDR+x}\" ] && "
                           "[ -z \"${VAULT_AGENT_ADDR+x}\" ] && [ -z \"${VAULT_NAMESPACE+x}\" ] && "
                           "[ -z \"${VAULT_TOKEN+x}\" ]\n")
                inherited = dict(os.environ, VAULT_ADDR="https://production.example",
                                 VAULT_AGENT_ADDR="https://agent.example", VAULT_NAMESPACE="operator",
                                 VAULT_TOKEN="operator-token")
                result = subprocess.run(["/bin/sh", "-c", command], env=inherited,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("operator-token", result.stdout + result.stderr)

    def test_public_commands_do_not_include_a_cli_wrapper(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                playground.main(["run", "status"])
        self.assertEqual(error.exception.code, 2)

    def test_failed_provisioning_stays_recoverable_and_cannot_silently_reseed(self):
        with self.fixture(provision_error="Fixture provisioning failed."):
            self.assertEqual(playground.main(["up"]), 1)
            self.assertFalse(playground.load_state()["ready"])
            self.assertEqual(playground.main(["up"]), 1)
            self.assertEqual(self.provisions, 1)
            self.assertIn("down, then up", self.error.getvalue())
            state = playground.load_state()
            self.assertEqual(playground.main(["down"]), 0)
        self.assertFalse(self.directory.exists())
        self.assertIn((["rm", "--force", "d" * 64], None), self.calls)

    def test_down_refuses_an_unowned_container_and_preserves_local_state(self):
        state = self.prepare()
        impostor = self.container(state)
        impostor["Config"]["Labels"][playground.LABEL] = "another-project-owner"
        with patch.object(playground, "local_docker"), \
             patch.object(playground, "docker", return_value=subprocess.CompletedProcess([], 0, json.dumps([impostor]), "")) as docker:
            with self.assertRaisesRegex(playground.PlaygroundError, "ownership"):
                playground.down()
        self.assertEqual(docker.call_count, 1)
        self.assertTrue((self.directory / "root-token").exists())

    def test_down_removes_only_the_owned_resource_and_unlinks_exercise_symlinks(self):
        state = self.prepare()
        outside = self.root / "outside-project"
        outside.mkdir()
        (outside / "important").write_text("preserve me")
        (self.directory / "external-link").symlink_to(outside, target_is_directory=True)
        with patch.object(playground, "local_docker"), \
             patch.object(playground, "docker", side_effect=self.fake_docker):
            playground.down()
            playground.down()
        self.assertEqual((outside / "important").read_text(), "preserve me")
        self.assertFalse(self.directory.exists())
        self.assertEqual([arguments for arguments, _ in self.calls if arguments[0] == "rm"],
                         [["rm", "--force", "d" * 64]])

    def test_state_directory_symlink_is_rejected_before_deleting_anything(self):
        target = self.root / "elsewhere"
        target.mkdir(mode=0o700)
        marker = target / "marker"
        marker.write_text("preserve")
        self.directory.symlink_to(target, target_is_directory=True)
        with patch.object(playground, "docker") as docker:
            with self.assertRaises(playground.PlaygroundError):
                playground.down()
        docker.assert_not_called()
        self.assertEqual(marker.read_text(), "preserve")

    def test_private_token_refuses_symlinks_hardlinks_and_loose_modes(self):
        self.prepare()
        token = self.directory / "root-token"
        token.chmod(0o644)
        with self.assertRaises(playground.PlaygroundError):
            playground.read_private(token)
        token.chmod(0o600)
        alias = self.directory / "alias"
        os.link(token, alias)
        with self.assertRaises(playground.PlaygroundError):
            playground.read_private(token)
        alias.unlink()
        token.unlink()
        token.symlink_to(self.directory / "state.json")
        with self.assertRaises(playground.PlaygroundError):
            playground.read_private(token)

    def test_environment_ignores_production_vault_and_keeps_proxy_credentials(self):
        state = self.prepare()
        inherited = {"VAULT_ADDR": "https://production.example", "VAULT_AGENT_ADDR": "https://agent.example",
                     "VAULT_TOKEN": "production-token", "VAULT_NAMESPACE": "production", "VAULT_CACERT": "/missing/ca",
                     "VAULT_SKIP_VERIFY": "true", "VAULT_CLIENT_TIMEOUT": "invalid",
                     "HTTP_PROXY": "http://proxy-user:proxy-password@proxy.example", "DOCKER_CONFIG": "/trusted/docker"}
        with patch.dict(os.environ, inherited, clear=True):
            environment = playground.secretwright_environment(state)
        self.assertEqual({key for key in environment if key.startswith("VAULT_")},
                         {"VAULT_ADDR", "VAULT_NAMESPACE", "VAULT_TOKEN"})
        self.assertEqual(environment["VAULT_ADDR"], state["address"])
        self.assertEqual(environment["VAULT_NAMESPACE"], "")
        self.assertEqual(environment["VAULT_TOKEN"], "private-test-root-never-print")
        self.assertEqual(environment["HTTP_PROXY"], inherited["HTTP_PROXY"])
        self.assertEqual(environment["DOCKER_CONFIG"], inherited["DOCKER_CONFIG"])
        self.assertIn("127.0.0.1", environment["NO_PROXY"].split(","))
        self.assertIn("127.0.0.1", environment["no_proxy"].split(","))

    def test_run_supports_bootstrap_without_putting_credentials_in_arguments(self):
        state = self.prepare(ready=False)
        with patch.object(playground, "running_state", return_value=state), \
             patch.object(playground, "find_binary", return_value="/trusted/secretwright"), \
             patch.object(playground.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "report", "")) as run:
            result = playground.run_secretwright(["blueprint", "apply", "--file", "fixture.yaml"], capture_output=True)
        self.assertEqual(result.stdout, "report")
        words = run.call_args.args[0]
        self.assertNotIn("private-test-root-never-print", " ".join(words))
        self.assertTrue(run.call_args.kwargs["capture_output"])
        self.assertEqual(run.call_args.kwargs["env"]["VAULT_ADDR"], state["address"])

    def test_connection_override_spellings_fail_before_launching_any_process(self):
        for flag in ("--address", "-address", "--namespace=production", "--token-file", "-token-file=other"):
            with self.subTest(flag=flag), patch.object(playground, "running_state") as state:
                with self.assertRaisesRegex(playground.PlaygroundError, "overrides"):
                    playground.run_secretwright(["cat", flag, "/playground/app"])
                state.assert_not_called()

    def test_remote_docker_is_refused_before_contacting_daemon(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "tcp://remote.example:2376"}, clear=True), \
             patch.object(playground, "docker") as docker:
            with self.assertRaisesRegex(playground.PlaygroundError, "local Docker"):
                playground.local_docker()
        docker.assert_not_called()

    def test_explicit_remote_context_cannot_hide_behind_local_docker_host(self):
        with patch.dict(os.environ, {"DOCKER_HOST": "unix:///local.sock", "DOCKER_CONTEXT": "remote"}, clear=True), \
             patch.object(playground, "docker", return_value=subprocess.CompletedProcess([], 0, "ssh://remote.example\n", "")) as docker:
            with self.assertRaisesRegex(playground.PlaygroundError, "local Docker"):
                playground.local_docker()
        self.assertEqual(docker.call_count, 1)
        self.assertEqual(docker.call_args.args[0][:3], ["context", "inspect", "remote"])

    def test_missing_binary_creates_no_local_state_and_calls_no_docker(self):
        with patch.object(playground, "find_binary", side_effect=playground.PlaygroundError("Install Secretwright.")), \
             patch.object(playground, "docker") as docker:
            with self.assertRaises(playground.PlaygroundError):
                playground.up()
        self.assertFalse(self.directory.exists())
        docker.assert_not_called()

    def test_down_cleans_empty_directory_without_contacting_docker(self):
        self.directory.mkdir(mode=0o700)
        with patch.object(playground, "docker") as docker:
            playground.down()
        self.assertFalse(self.directory.exists())
        docker.assert_not_called()

    def test_captured_timeout_is_bounded_and_does_not_expose_partial_output(self):
        state = self.prepare()
        timeout = subprocess.TimeoutExpired(["secretwright"], 120, output="private-test-root-never-print")
        with patch.object(playground, "running_state", return_value=state), \
             patch.object(playground, "find_binary", return_value="/trusted/secretwright"), \
             patch.object(playground.subprocess, "run", side_effect=timeout) as run:
            with self.assertRaises(playground.PlaygroundError) as raised:
                playground.run_secretwright(["auth", "check"], capture_output=True)
        self.assertEqual(run.call_args.kwargs["timeout"], 120)
        self.assertNotIn("private-test-root-never-print", str(raised.exception))

    def test_unexpected_port_binding_is_rejected_even_with_matching_ownership(self):
        for address in ("0.0.0.0", "::", "192.168.1.8"):
            container = self.container(self.state())
            container["NetworkSettings"]["Ports"]["8200/tcp"][0]["HostIp"] = address
            with self.subTest(address=address):
                with self.assertRaises(playground.PlaygroundError):
                    playground.bound_address(container)

    def test_api_never_uses_inherited_proxies_or_follows_redirects(self):
        state = self.prepare()
        from unittest.mock import MagicMock
        stream = MagicMock()
        stream.__enter__.return_value.read.return_value = b'{"initialized": true}'
        opener = MagicMock()
        opener.open.return_value = stream
        with patch.object(playground, "build_opener", return_value=opener) as build:
            self.assertEqual(playground.vault_request(state, "/sys/health", authenticated=False), {"initialized": True})
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsNone(build.call_args.args[1].redirect_request(None, None, 302, "redirect", {}, "http://elsewhere"))
        request = opener.open.call_args.args[0]
        self.assertNotIn("X-vault-token", request.headers)
        self.assertEqual(request.full_url, state["address"] + "/v1/sys/health")

    def test_nonlocal_state_is_rejected_before_network_use(self):
        state = self.prepare()
        state["address"] = "https://production.example:8200"
        playground.save_state(state)
        with patch.object(playground, "build_opener") as opener:
            with self.assertRaises(playground.PlaygroundError):
                playground.load_state()
            with self.assertRaises(playground.PlaygroundError):
                playground.vault_request(state, "/sys/health")
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
