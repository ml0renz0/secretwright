"""A repeatable acceptance tour of the provisioned playground."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile


EXAMPLES = Path(__file__).resolve().parent


def report(runtime, args, *, expected=0, token_file=None):
    print("$ playground run " + " ".join(args))
    result = runtime.run_secretwright(args, capture_output=True, token_file=token_file)
    if result.returncode != expected:
        raise runtime.PlaygroundError("Playground demo failed: unexpected command exit status.")
    if expected:
        print("  Access denied as expected (exit 2).")
        return None
    try:
        return json.loads(result.stdout)
    except (TypeError, ValueError):
        raise runtime.PlaygroundError("Playground demo failed: invalid CLI report.") from None


def expect(runtime, condition, message):
    if not condition:
        raise runtime.PlaygroundError("Playground demo failed: " + message)


def demo(runtime):
    """Validate seeded content and permissions without changing the fixtures."""
    runtime.load_state()
    status = report(runtime, ["status"])
    expect(runtime, isinstance(status, dict) and status.get("initialized") is True and
           status.get("sealed") is False, "Vault is not ready.")
    auth = report(runtime, ["auth", "check"])
    expect(runtime, isinstance(auth, dict) and auth.get("authenticated") is True,
           "the playground operator could not authenticate.")
    children = report(runtime, ["ls", "/playground/apps"])
    expect(runtime, children == ["catalog/", "payments/"], "the application folders changed.")
    history = report(runtime, ["versions", "/playground/apps/payments/database"])
    expect(runtime, isinstance(history, dict) and history.get("current_version") == 2 and
           isinstance(history.get("versions"), list) and
           all(isinstance(entry, dict) for entry in history["versions"]) and
           [entry.get("version") for entry in history["versions"]] == [1, 2],
           "the two database revisions are missing.")

    cases = [
        (["cat", "--version", "1", "/playground/apps/payments/database"], "database-v1.json"),
        (["cat", "/playground/apps/payments/database"], "database-v2.json"),
        (["cat", "/playground/apps/payments/config"], "config.json"),
        (["cat", "/playground/apps/catalog/api"], "api-key.json"),
        (["cat", "/legacy/demo"], "legacy.json"),
    ]
    for args, fixture in cases:
        values = report(runtime, args)
        expected = json.loads((EXAMPLES / "secrets" / fixture).read_text())
        expect(runtime, values == expected, "the seeded data changed; use down/up for a fresh tour.")
        print("  Fake fixture matches: " + fixture)

    plan = report(runtime, ["blueprint", "plan", "--file", str(EXAMPLES / "blueprint.yaml"),
                            "--state", str(runtime.STATE_DIR / "blueprint.state.json")])
    expect(runtime, isinstance(plan, dict) and plan.get("changes") == [],
           "the blueprint plan contains changes.")
    print("  Blueprint changes: []")

    # Every tour receives fresh private files. Issued tokens are revoked before
    # these files disappear, so repeated demos do not leave active credentials.
    with tempfile.TemporaryDirectory(prefix="demo-", dir=runtime.STATE_DIR) as private:
        bundle = Path(private) / "reader.bundle.json"
        token = Path(private) / "reader.token"
        try:
            report(runtime, ["approle", "credentials", "--out", str(bundle), "playground-reader"])
            report(runtime, ["approle", "login", "--file", str(bundle), "--out", str(token)])
            auth = report(runtime, ["auth", "check"], token_file=token)
            expect(runtime, isinstance(auth, dict) and auth.get("authenticated") is True,
                   "the AppRole token could not authenticate.")
            values = report(runtime, ["cat", "--mount", "playground", "--kv-version", "2",
                                      "/playground/apps/catalog/api"], token_file=token)
            expect(runtime, values == json.loads((EXAMPLES / "secrets" / "api-key.json").read_text()),
                   "the reader could not read the application API key.")
            report(runtime, ["cat", "--mount", "legacy", "--kv-version", "1", "/legacy/demo"],
                   expected=2, token_file=token)
            report(runtime, ["put", "--mount", "playground", "--kv-version", "2",
                             "--file", str(EXAMPLES / "secrets" / "api-key.json"),
                             "/playground/apps/catalog/denied-write"], expected=2, token_file=token)
        finally:
            if token.exists():
                result = runtime.run_secretwright(["token", "revoke", "--force", "--file", str(token)],
                                                   capture_output=True)
                if result.returncode:
                    raise runtime.PlaygroundError("The demo token could not be revoked; stop the playground with down.")
            elif bundle.exists():
                # A failed login may leave an unused SecretID. Cleanup is best
                # effort here; Vault is disposable and a used SecretID is gone.
                runtime.run_secretwright(["approle", "revoke-secret-id", "--file", str(bundle),
                                           "playground-reader"], capture_output=True)
    print("Demo passed: content, versions, blueprint convergence and AppRole permissions.")
    return 0


if __name__ == "__main__":
    spec = importlib.util.spec_from_file_location("secretwright_playground", EXAMPLES.parents[1] / "scripts" / "playground.py")
    runtime = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = runtime
    spec.loader.exec_module(runtime)
    try:
        raise SystemExit(demo(runtime))
    except runtime.PlaygroundError as error:
        raise SystemExit(str(error)) from None
