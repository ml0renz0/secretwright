#!/usr/bin/env python3
"""Disposable, preloaded local Vault for exploring Secretwright."""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
STATE_DIR = ROOT / ".playground"
IMAGE = "hashicorp/vault:2.2.0"
LABEL = "io.secretwright.playground"


class PlaygroundError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise PlaygroundError(message)


def private_directory(create=False):
    if create:
        try:
            STATE_DIR.mkdir(mode=0o700)
        except FileExistsError:
            pass
    try:
        metadata = STATE_DIR.lstat()
    except FileNotFoundError:
        raise PlaygroundError("Playground is not running; use playground.py up.") from None
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700,
            "The playground directory must be an owned, private directory (0700), without symlinks.")


def read_private(path, limit=65536):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1,
                    "Playground files must be owned regular files (0600), without links.")
            body = stream.read(limit + 1)
            require(len(body) <= limit, "A playground file exceeds its size limit.")
            return body.decode("utf-8")
    except (OSError, UnicodeError):
        raise PlaygroundError("Could not read a private playground file; use down before starting again.") from None


def write_private(path, body):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(body)


def save_state(state, *, new=False):
    path = STATE_DIR / "state.json"
    body = json.dumps(state, sort_keys=True) + "\n"
    if new:
        write_private(path, body)
        return
    read_private(path, 4096)
    temporary = STATE_DIR / ("state-" + secrets.token_hex(8) + ".tmp")
    try:
        write_private(temporary, body)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def load_state():
    private_directory()
    try:
        state = json.loads(read_private(STATE_DIR / "state.json", 4096))
    except (ValueError, TypeError):
        raise PlaygroundError("Invalid playground state; no container has been modified.") from None
    require(isinstance(state, dict) and set(state) == {"version", "owner", "name", "address", "ready"}
            and state["version"] == 1 and isinstance(state["owner"], str)
            and re.fullmatch(r"[0-9a-f]{32}", state["owner"]) is not None
            and state["name"] == "secretwright-playground-" + state["owner"]
            and isinstance(state["ready"], bool),
            "Invalid playground ownership state; no container has been modified.")
    address = state["address"]
    require(address is None or (isinstance(address, str)
            and re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", address) is not None
            and int(address.rsplit(":", 1)[1]) <= 65535),
            "Invalid playground loopback address.")
    require(not state["ready"] or address is not None, "Invalid playground readiness state.")
    return state


def docker(arguments, *, env=None, check=True):
    try:
        result = subprocess.run(["docker", *arguments], env=env, capture_output=True,
                                text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise PlaygroundError("Docker is unavailable or timed out; private container logs are withheld.") from None
    require(not check or result.returncode == 0,
            "A Docker operation failed; private container logs are withheld.")
    return result


def local_docker():
    # Docker gives an explicit context precedence over DOCKER_HOST. Validate
    # that same effective selector instead of trusting a shadowed local host.
    context = os.environ.get("DOCKER_CONTEXT")
    endpoint = None if context else os.environ.get("DOCKER_HOST")
    if context:
        result = docker(["context", "inspect", context, "--format", "{{.Endpoints.docker.Host}}"])
        endpoint = result.stdout.strip()
    elif not endpoint:
        result = docker(["context", "inspect", "--format", "{{.Endpoints.docker.Host}}"])
        endpoint = result.stdout.strip()
    require(endpoint.startswith("unix://"), "The playground requires a local Docker Unix socket.")
    docker(["info", "--format", "{{.ServerVersion}}"])


def inspect_container(state):
    result = docker(["container", "inspect", state["name"]], check=False)
    if result.returncode:
        # A failed daemon request must not be mistaken for an absent container.
        docker(["info", "--format", "{{.ServerVersion}}"])
        return None
    try:
        values = json.loads(result.stdout)
        require(isinstance(values, list) and len(values) == 1, "Invalid Docker inspection response.")
        value = values[0]
        require(value["Name"] == "/" + state["name"]
                and value["Config"]["Labels"].get(LABEL) == state["owner"]
                and isinstance(value["Id"], str) and re.fullmatch(r"[0-9a-f]{64}", value["Id"]) is not None,
                "Container ownership does not match; no container has been modified.")
        return value
    except (ValueError, KeyError, TypeError, AttributeError):
        raise PlaygroundError("Invalid Docker ownership response; no container has been modified.") from None


def bound_address(container):
    try:
        bindings = container["NetworkSettings"]["Ports"]["8200/tcp"]
        require(isinstance(bindings, list) and len(bindings) == 1, "Unexpected Vault port bindings.")
        binding = bindings[0]
        require(binding["HostIp"] == "127.0.0.1" and isinstance(binding["HostPort"], str)
                and binding["HostPort"].isdigit() and 0 < int(binding["HostPort"]) <= 65535,
                "Vault must be published only on a loopback port.")
        return "http://127.0.0.1:" + binding["HostPort"]
    except (KeyError, TypeError):
        raise PlaygroundError("Docker returned an invalid Vault loopback binding.") from None


def running_state():
    state = load_state()
    local_docker()
    container = inspect_container(state)
    require(container is not None and container.get("State", {}).get("Running") is True,
            "The playground container is stopped or missing; use down, then up.")
    require(bound_address(container) == state["address"], "The playground port changed; use down, then up.")
    return state


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def vault_request(state, path, data=None, authenticated=True):
    require(isinstance(state.get("address"), str)
            and re.fullmatch(r"http://127\.0\.0\.1:[1-9][0-9]{0,4}", state["address"]) is not None
            and int(state["address"].rsplit(":", 1)[1]) <= 65535,
            "Refusing a non-loopback playground request.")
    require(isinstance(path, str) and path.startswith("/") and not path.startswith("//")
            and not any(character in path for character in ("?", "#", "\\", "\r", "\n")),
            "Invalid playground API path.")
    headers = {"Content-Type": "application/json"}
    if authenticated:
        headers["X-Vault-Token"] = read_private(STATE_DIR / "root-token").strip()
    request = Request(state["address"] + "/v1" + path,
                      data=None if data is None else json.dumps(data).encode(), headers=headers)
    # The fixture is local regardless of the user's production proxy settings.
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=3) as response:
            body = response.read(2 * 1024 * 1024 + 1)
        require(len(body) <= 2 * 1024 * 1024, "A playground response exceeded its limit.")
        return json.loads(body) if body else None
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        raise PlaygroundError("The local Vault request failed; private response details are withheld.") from None


def wait_ready(state):
    for _ in range(60):
        try:
            health = vault_request(state, "/sys/health", authenticated=False)
            if health.get("initialized") is True and health.get("sealed") is False:
                return
        except PlaygroundError:
            pass
        time.sleep(0.5)
    raise PlaygroundError("Vault did not become ready; use down, then up. Private logs are withheld.")


def find_binary():
    local = ROOT / "bin" / "secretwright"
    selected = str(local) if local.is_file() and os.access(local, os.X_OK) else shutil.which("secretwright")
    require(selected is not None,
            "Secretwright is required: use make build, or install a verified release on PATH.")
    return selected


def secretwright_environment(state, token_file=None):
    environment = {name: value for name, value in os.environ.items() if not name.startswith("VAULT_")}
    environment.update(VAULT_ADDR=state["address"], VAULT_NAMESPACE="",
                       VAULT_TOKEN=read_private(STATE_DIR / "root-token" if token_file is None else Path(token_file)).strip())
    for name in ("NO_PROXY", "no_proxy"):
        environment[name] = environment.get(name, "") + ",127.0.0.1,localhost"
    return environment


def ensure_environment(state):
    """Prepare variables for the real CLI; sourcing needs neither Python nor Docker."""
    private_directory()
    read_private(STATE_DIR / "root-token")
    token_file = shlex.quote(str(STATE_DIR / "root-token"))
    binary_directory = shlex.quote(str(Path(find_binary()).absolute().parent))
    body = ("# Generated by Secretwright's disposable playground. Source this file.\n"
            "unset VAULT_ADDR VAULT_AGENT_ADDR VAULT_NAMESPACE VAULT_TOKEN\n"
            "unset VAULT_CACERT VAULT_CACERT_BYTES VAULT_CAPATH VAULT_CLIENT_CERT VAULT_CLIENT_KEY\n"
            "unset VAULT_TLS_SERVER_NAME VAULT_SKIP_VERIFY VAULT_CLIENT_TIMEOUT\n"
            "if ! VAULT_TOKEN=$(cat " + token_file + ") || [ -z \"$VAULT_TOKEN\" ]; then\n"
            "  unset VAULT_TOKEN\n"
            "  printf '%s\\n' 'The playground token is unavailable; start the playground again.' >&2\n"
            "  return 1\n"
            "fi\n"
            "export VAULT_TOKEN\n"
            "export VAULT_ADDR=" + shlex.quote(state["address"]) + "\n"
            "export VAULT_NAMESPACE=''\n"
            "export PATH=" + binary_directory + ":\"$PATH\"\n"
            "export NO_PROXY=\"${NO_PROXY:+${NO_PROXY},}127.0.0.1,localhost\"\n"
            "export no_proxy=\"${no_proxy:+${no_proxy},}127.0.0.1,localhost\"\n")
    path = STATE_DIR / "env.sh"
    if path.exists() or path.is_symlink():
        require(read_private(path) == body,
                "The playground environment file differs; inspect and remove env.sh before retrying up.")
    else:
        write_private(path, body)


def environment_instructions():
    print("Load: source .playground/env.sh")
    print("Explore: secretwright tree /playground")
    print("Shell: secretwright shell")


def run_secretwright(arguments, *, capture_output=False, token_file=None):
    """Invoke the CLI only for the automated provisioning and acceptance scenarios."""
    for argument in arguments:
        require(argument.split("=", 1)[0].lstrip("-") not in {"address", "namespace", "token-file"},
                "Connection overrides are disabled during automated playground scenarios.")
    state = running_state()
    try:
        return subprocess.run([find_binary(), *(arguments or ["shell"])],
                              cwd=ROOT, env=secretwright_environment(state, token_file),
                              capture_output=capture_output, text=True,
                              timeout=120 if capture_output else None)
    except (OSError, subprocess.TimeoutExpired):
        raise PlaygroundError("Secretwright could not complete the playground command; private output is withheld.") from None


def scenario(name):
    path = ROOT / "examples" / "playground" / (name + ".py")
    spec = importlib.util.spec_from_file_location("secretwright_playground_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def up():
    if not STATE_DIR.exists() and not STATE_DIR.is_symlink():
        # A missing executable must not leave a half-created playground.
        find_binary()
    local_docker()
    private_directory(create=True)
    if (STATE_DIR / "state.json").exists() or (STATE_DIR / "state.json").is_symlink():
        state = running_state()
        require(state["ready"], "Playground provisioning was incomplete; use down, then up.")
        wait_ready(state)
        ensure_environment(state)
        print("Playground already running at " + state["address"] + "; existing content was preserved.")
        environment_instructions()
        return
    find_binary()
    require(not any(STATE_DIR.iterdir()), "The playground directory has orphaned files; inspect it before starting again.")
    owner = secrets.token_hex(16)
    state = {"version": 1, "owner": owner, "name": "secretwright-playground-" + owner,
             "address": None, "ready": False}
    # Record ownership before creating Docker resources so interrupted starts
    # remain recoverable with down, without searching for other containers.
    save_state(state, new=True)
    write_private(STATE_DIR / "root-token", secrets.token_hex(32))
    environment = os.environ.copy()
    environment["VAULT_DEV_ROOT_TOKEN_ID"] = read_private(STATE_DIR / "root-token").strip()
    docker(["run", "--detach", "--name", state["name"], "--label", LABEL + "=" + owner,
            "--env", "VAULT_DEV_ROOT_TOKEN_ID", "--publish", "127.0.0.1::8200", IMAGE,
            "server", "-dev", "-dev-no-store-token", "-dev-listen-address=0.0.0.0:8200"], env=environment)
    container = inspect_container(state)
    require(container is not None and container.get("State", {}).get("Running") is True,
            "Vault exited during startup; use down, then up. Private logs are withheld.")
    state["address"] = bound_address(container)
    save_state(state)
    wait_ready(state)
    # F07 blueprints use an existing authentication mount; the playground owns
    # the disposable server and bootstraps only this prerequisite through API.
    vault_request(state, "/sys/auth/approle", {"type": "approle"})
    scenario("provision").provision(sys.modules[__name__], state)
    ensure_environment(state)
    state["ready"] = True
    save_state(state)
    print("Playground ready at " + state["address"] + ".")
    environment_instructions()
    print("Demo: python3 scripts/playground.py demo")
    print("Remove: python3 scripts/playground.py down")


def status():
    state = running_state()
    wait_ready(state)
    print(json.dumps({"address": state["address"], "ready": state["ready"],
                      "container": state["name"], "ephemeral": True}))


def down():
    if not STATE_DIR.exists() and not STATE_DIR.is_symlink():
        print("Playground already removed.")
        return
    private_directory()
    if not any(STATE_DIR.iterdir()):
        STATE_DIR.rmdir()
        print("Empty playground directory removed.")
        return
    state = load_state()
    local_docker()
    container = inspect_container(state)
    if container is not None:
        # Use the inspected immutable ID so a concurrent name reuse cannot
        # redirect cleanup to an unrelated container.
        docker(["rm", "--force", container["Id"]])
    # shutil.rmtree unlinks symlinks rather than following their destinations;
    # the selected root itself was checked with lstat above.
    shutil.rmtree(STATE_DIR)
    print("Playground removed, including its private exercise files.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("up", "status", "demo", "down"))
    options = parser.parse_args(argv)
    try:
        if options.action == "demo":
            state = running_state()
            require(state["ready"], "Playground provisioning was incomplete; use down, then up.")
            return scenario("demo").demo(sys.modules[__name__]) or 0
        {"up": up, "status": status, "down": down}[options.action]()
        return 0
    except (PlaygroundError, OSError):
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, PlaygroundError) else "A playground file operation failed.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Playground action interrupted; use down to remove the local fixture.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
