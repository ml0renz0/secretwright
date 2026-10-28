#!/usr/bin/env python3
"""Exercise the user's playground against real Docker/Vault in CI."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PLAYGROUND = ROOT / "scripts/playground.py"
PRIVATE = ROOT / ".playground"


def main():
    # Host operator configuration must never redirect the lab or block its HTTP
    # connection. None of these credentials belong to a real server.
    environment = dict(os.environ, VAULT_ADDR="https://must-not-contact.invalid",
                       VAULT_AGENT_ADDR="https://must-not-contact-agent.invalid",
                       VAULT_NAMESPACE="must-not-inherit", VAULT_TOKEN="operator-token-sentinel",
                       VAULT_SKIP_VERIFY="true", VAULT_CACERT="/does/not/exist",
                       VAULT_CLIENT_TIMEOUT="not-a-duration")
    tokens = [environment["VAULT_TOKEN"]]

    def command(*arguments, expected=0, cli=False):
        if cli:
            # Exercise exactly the documented user flow: load variables once
            # in a shell, then exec the real CLI directly. No Python wrapper
            # selects or rewrites the Secretwright command.
            words = ["/bin/sh", "-c", '. "$1" || exit $?\nshift\nexec secretwright "$@"',
                     "playground-acceptance", str(PRIVATE / "env.sh"), *arguments]
        else:
            words = [sys.executable, str(PLAYGROUND), *arguments]
        completed = subprocess.run(words,
                                   cwd=ROOT, env=environment, capture_output=True,
                                   text=True, timeout=180)
        token_file = PRIVATE / "root-token"
        if token_file.is_file():
            token = token_file.read_text().strip()
            if token and token not in tokens:
                tokens.append(token)
        output = completed.stdout + completed.stderr
        if any(token in output for token in tokens):
            raise RuntimeError("Playground exposed a credential; output withheld.")
        if completed.returncode != expected:
            # Dev Vault logs and credential-bearing error bodies are never
            # printed by this harness, even when acceptance fails.
            raise RuntimeError("Playground acceptance failed at " + arguments[0]
                               + "; command output withheld.")
        return completed.stdout

    def state():
        spec = importlib.util.spec_from_file_location("playground_acceptance", PLAYGROUND)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        return runtime.load_state()

    def require(condition, message):
        if not condition:
            raise RuntimeError(message)

    try:
        command("up")
        first = state()
        require(first["address"].startswith("http://127.0.0.1:"), "Vault is not bound to loopback.")
        print("PASS: provisioned blueprint and sample secrets with operator settings isolated.")
        command("demo")
        command("demo")
        print("PASS: the guided demo succeeds twice, including AppRole access checks.")

        database = "/playground/apps/payments/database"
        connection = json.loads(command("status", cli=True))
        require(connection.get("initialized") is True and connection.get("sealed") is False,
                "The native CLI did not connect through the exported environment.")
        authentication = json.loads(command("auth", "check", cli=True))
        require(authentication.get("authenticated") is True,
                "The native CLI did not authenticate through the exported environment.")
        original = json.loads(command("cat", database, cli=True))
        require(original["password"] == "fake-only-v2", "The expected sample secret is missing.")
        changed = dict(original, password="fake-user-experiment")
        probe = PRIVATE / "reuse-probe.json"
        descriptor = os.open(probe, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as output:
            json.dump(changed, output)
        command("put", "--file", str(probe), "--cas", "2", database, cli=True)
        command("up")
        require(state()["owner"] == first["owner"], "Repeated up replaced the lab.")
        require(json.loads(command("cat", database, cli=True)) == changed,
                "Repeated up overwrote a user's experiment.")
        command("status")
        print("PASS: repeated up preserves the same Vault and user changes.")

        print("PASS: the native CLI uses the exported environment directly.")
        command("down")
        command("down")
        command("up")
        require(state()["owner"] != first["owner"], "Reset reused the previous Vault.")
        require(json.loads(command("cat", database, cli=True)) == original,
                "Reset did not restore the example content.")
        print("PASS: down is repeatable and down/up resets the sample content.")
    finally:
        command("down")
    print("Playground acceptance passed; disposable Vault removed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print("playground acceptance: " + str(error), file=sys.stderr)
        raise SystemExit(1)
