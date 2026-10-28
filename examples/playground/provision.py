"""Populate only the disposable playground, through the real Secretwright CLI.

The blueprint owns non-secret infrastructure. JSON fixtures are deliberately
fake secret values, written separately with ``secretwright put``.
"""

import json
from pathlib import Path


EXAMPLES = Path(__file__).resolve().parent
BLUEPRINT = EXAMPLES / "blueprint.yaml"


def checked(runtime, args):
    result = runtime.run_secretwright(args, capture_output=True)
    if result.returncode:
        # Never forward raw subprocess output from a credential operation.
        raise runtime.PlaygroundError("Playground provisioning failed at " + " ".join(args[:2]) +
                           "; inspect the playground or run down before starting again.")
    try:
        return json.loads(result.stdout)
    except (TypeError, ValueError):
        raise runtime.PlaygroundError("Playground provisioning returned an invalid CLI report.") from None


def provision(runtime, state):
    """Called once by playground up, after Vault and AppRole are ready."""
    inventory = runtime.STATE_DIR / "blueprint.state.json"
    if inventory.exists() or inventory.is_symlink():
        raise runtime.PlaygroundError("The playground inventory already exists; run down before provisioning again.")
    options = ["--file", str(BLUEPRINT), "--state", str(inventory)]
    checked(runtime, ["blueprint", "validate", "--file", str(BLUEPRINT)])
    checked(runtime, ["blueprint", "adopt", *options])
    checked(runtime, ["blueprint", "apply", *options])
    print("Blueprint applied: KV v1/v2, read policy and AppRole.")

    fixtures = [
        ("database-v1.json", "playground", 2, "/playground/apps/payments/database", None),
        ("database-v2.json", "playground", 2, "/playground/apps/payments/database", 1),
        ("config.json", "playground", 2, "/playground/apps/payments/config", None),
        ("api-key.json", "playground", 2, "/playground/apps/catalog/api", None),
        ("legacy.json", "legacy", 1, "/legacy/demo", None),
    ]
    for filename, mount, version, target, cas in fixtures:
        args = ["put", "--mount", mount, "--kv-version", str(version),
                "--file", str(EXAMPLES / "secrets" / filename)]
        if cas is not None:
            args.extend(["--cas", str(cas)])
        report = checked(runtime, [*args, target])
        expected_version = 2 if cas == 1 else 1
        if (not isinstance(report, dict) or report.get("path") != target or
                report.get("kv_version") != version or
                (version == 2 and report.get("version") != expected_version)):
            raise runtime.PlaygroundError("Playground secret write did not confirm the expected revision.")

    plan = checked(runtime, ["blueprint", "plan", *options])
    if not isinstance(plan, dict) or plan.get("changes") != []:
        raise runtime.PlaygroundError("The playground blueprint did not converge to an empty plan.")
    print("Fake database credentials (two revisions), configuration, API key and KV v1 data loaded.")


if __name__ == "__main__":
    raise SystemExit("Use python3 scripts/playground.py up to provision an owned playground.")
