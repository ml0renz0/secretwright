"""Control-flow checks; the CI playground job exercises the real CLI and Vault."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "examples" / "playground" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


provision = load("provision")
demo = load("demo")


class ScenarioError(Exception):
    pass


class FixtureRuntime:
    """Models observable CLI replies and protects privilege distinctions."""

    PlaygroundError = ScenarioError

    def __init__(self, directory):
        self.ROOT = ROOT
        self.STATE_DIR = Path(directory)
        self.calls = []
        self.fail_at = None
        self.plan_changes = []
        self.write_revision = None
        self.allow_denied = False
        self.bad_role_read = False
        self.tokens = set()

    def load_state(self):
        return {"ready": True}

    def run_secretwright(self, args, *, capture_output=False, token_file=None):
        assert capture_output, "Sensitive scenario output must always be captured."
        args = list(args)
        self.calls.append((args, token_file))
        if self.fail_at is not None and len(self.calls) == self.fail_at:
            return subprocess.CompletedProcess(args, 5, "private-credential-marker", "private-credential-marker")
        code, body = 0, {}
        if args[:2] == ["blueprint", "plan"]:
            body = {"changes": self.plan_changes}
        elif args[0] == "put":
            if token_file is not None:
                code = 0 if self.allow_denied else 2
            else:
                version = int(args[args.index("--kv-version") + 1])
                body = {"path": args[-1], "kv_version": version}
                if version == 2:
                    body["version"] = self.write_revision or (2 if "--cas" in args else 1)
        elif args[0] == "status":
            body = {"initialized": True, "sealed": False}
        elif args[:2] == ["auth", "check"]:
            body = {"authenticated": True}
        elif args[0] == "ls":
            body = ["catalog/", "payments/"]
        elif args[0] == "versions":
            body = {"current_version": 2, "versions": [{"version": 1}, {"version": 2}]}
        elif args[0] == "cat":
            if token_file is not None and args[-1] == "/legacy/demo":
                code = 0 if self.allow_denied else 2
            else:
                fixture = {
                    "/playground/apps/payments/database": "database-v1.json" if "--version" in args else "database-v2.json",
                    "/playground/apps/payments/config": "config.json",
                    "/playground/apps/catalog/api": "api-key.json",
                    "/legacy/demo": "legacy.json",
                }[args[-1]]
                body = json.loads((provision.EXAMPLES / "secrets" / fixture).read_text())
                if token_file is not None and self.bad_role_read:
                    body = {"unexpected": True}
        elif args[:2] in (["approle", "credentials"], ["approle", "login"]):
            path = Path(args[args.index("--out") + 1])
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w") as stream:
                stream.write("private-credential-marker")
            if args[1] == "login":
                self.tokens.add(path)
        elif args[:2] == ["token", "revoke"]:
            self.tokens.remove(Path(args[args.index("--file") + 1]))
        return subprocess.CompletedProcess(args, code, json.dumps(body), "private-credential-marker" if code else "")


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime = FixtureRuntime(self.temporary.name)

    def provision(self):
        with contextlib.redirect_stdout(io.StringIO()):
            provision.provision(self.runtime, {"ready": False})

    def test_infrastructure_precedes_values_and_second_database_write_is_conditional(self):
        self.provision()
        commands = [args for args, _ in self.runtime.calls]
        self.assertEqual([args[:2] for args in commands[:3]],
                         [["blueprint", "validate"], ["blueprint", "adopt"], ["blueprint", "apply"]])
        writes = [args for args in commands if args[0] == "put"]
        self.assertEqual(len(writes), 5)
        database = [args for args in writes if args[-1] == "/playground/apps/payments/database"]
        self.assertNotIn("--cas", database[0])
        self.assertEqual(database[1][database[1].index("--cas") + 1], "1")
        self.assertTrue(all(Path(args[args.index("--file") + 1]).is_file() for args in writes))
        self.assertNotIn("--force", writes[-1])
        self.assertEqual(commands[-1][:2], ["blueprint", "plan"])

    def test_existing_inventory_prevents_replaying_secret_writes(self):
        (self.runtime.STATE_DIR / "blueprint.state.json").write_text("already owned")
        with self.assertRaises(ScenarioError):
            self.provision()
        self.assertEqual(self.runtime.calls, [])

    def test_blueprint_failure_stops_before_secret_writes_without_exposing_output(self):
        self.runtime.fail_at = 3
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(ScenarioError) as error:
            provision.provision(self.runtime, {})
        self.assertEqual(len(self.runtime.calls), 3)
        self.assertNotIn("private-credential-marker", output.getvalue() + str(error.exception))

    def test_unconfirmed_write_revision_stops_before_next_secret(self):
        self.runtime.write_revision = 9
        with self.assertRaisesRegex(ScenarioError, "expected revision"):
            self.provision()
        self.assertEqual(len(self.runtime.calls), 4)

    def test_nonempty_final_plan_is_a_provisioning_failure(self):
        self.runtime.plan_changes = [{"id": "reader_role", "action": "update"}]
        with self.assertRaisesRegex(ScenarioError, "empty plan"):
            self.provision()


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.runtime = FixtureRuntime(self.temporary.name)

    def run_demo(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            result = demo.demo(self.runtime)
        self.assertNotIn("private-credential-marker", output.getvalue())
        return result

    def test_demo_repeats_with_fresh_files_and_revokes_each_issued_token(self):
        self.assertEqual(self.run_demo(), 0)
        self.assertEqual(self.run_demo(), 0)
        self.assertEqual(self.runtime.tokens, set())
        tokens = [Path(args[args.index("--out") + 1]) for args, _ in self.runtime.calls
                  if args[:2] == ["approle", "login"]]
        self.assertEqual(len(set(tokens)), 2)
        self.assertTrue(all(not path.exists() for path in tokens))
        denials = [(args, token) for args, token in self.runtime.calls
                   if token is not None and (args[0] == "put" or args[-1] == "/legacy/demo")]
        self.assertEqual(len(denials), 4)
        self.assertTrue(all(token in tokens for _, token in denials))

    def test_missing_access_denial_fails_and_still_revokes_token(self):
        self.runtime.allow_denied = True
        with self.assertRaisesRegex(ScenarioError, "exit status"):
            self.run_demo()
        self.assertEqual(self.runtime.tokens, set())

    def test_wrong_role_read_fails_and_still_revokes_token(self):
        self.runtime.bad_role_read = True
        with self.assertRaisesRegex(ScenarioError, "reader could not read"):
            self.run_demo()
        self.assertEqual(self.runtime.tokens, set())

    def test_changed_blueprint_does_not_issue_another_credential(self):
        self.runtime.plan_changes = [{"id": "reader_role", "action": "update"}]
        with self.assertRaisesRegex(ScenarioError, "contains changes"):
            self.run_demo()
        self.assertFalse(any(args[:2] == ["approle", "credentials"] for args, _ in self.runtime.calls))


if __name__ == "__main__":
    unittest.main()
