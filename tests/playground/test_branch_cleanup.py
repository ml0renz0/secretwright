"""Exercise the workflow's real cleanup code without GitHub or YAML packages."""

import contextlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import textwrap
import types
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/cleanup-work-branch.yml").read_text()
SOURCE = textwrap.dedent(WORKFLOW.split("          # BEGIN cleanup Python\n", 1)[1]
                         .split("          # END cleanup Python\n", 1)[0])
GUARD = " ".join(re.search(r"^    if: >-\n((?:^      .+\n)+)", WORKFLOW, re.M)
                 .group(1).split())
REPOSITORY = "example/secretwright"
SHA = "a" * 40
TOKEN = "private-test-actions-token"
REF_URL = "https://api.github.com/repos/" + REPOSITORY + "/git/ref/heads/codex/work"
DELETE_URL = "https://api.github.com/repos/" + REPOSITORY + "/git/refs/heads/codex/work"


def namespace(value):
    return types.SimpleNamespace(**{key: namespace(item) for key, item in value.items()}) if isinstance(value, dict) else value


class Response(io.BytesIO):
    def __init__(self, status, body=None):
        super().__init__(json.dumps(body).encode())
        self.status = status


class BranchCleanupTests(unittest.TestCase):
    def event(self):
        return {"action": "closed", "repository": {"full_name": REPOSITORY},
                "pull_request": {"merged": True, "base": {"ref": "main"},
                                 "head": {"ref": "codex/work", "sha": SHA,
                                          "repo": {"full_name": REPOSITORY}}}}

    def ref(self, sha=SHA):
        return Response(200, {"ref": "refs/heads/codex/work",
                              "object": {"type": "commit", "sha": sha}})

    def job_allowed(self, event):
        github = namespace({"event": event, "repository": REPOSITORY})
        return eval(GUARD.replace("&&", " and ").replace(" true", " True"),
                    {"__builtins__": {}}, {"github": github})

    def run_cleanup(self, event, responses=(), **environment):
        calls, output, status = [], io.StringIO(), 0
        remaining = list(responses)

        def open_request(request, *, timeout):
            self.assertEqual(timeout, 10)
            calls.append((request.get_method(), request.full_url, dict(request.header_items())))
            self.assertTrue(remaining, "Unexpected API request")
            response = remaining.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        with tempfile.TemporaryDirectory() as directory:
            event_path = Path(directory) / "event.json"
            event_path.write_text(json.dumps(event))
            variables = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event_path),
                         "GITHUB_REPOSITORY": REPOSITORY, "GH_TOKEN": TOKEN, **environment}
            with patch.dict(os.environ, variables, clear=True), \
                 patch.object(urllib.request.OpenerDirector, "open", side_effect=open_request), \
                 contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                try:
                    exec(compile(SOURCE, "cleanup-work-branch.yml", "exec"), {"__name__": "__main__"})
                except SystemExit as error:
                    status = error.code
        self.assertNotIn(TOKEN, output.getvalue() + str(status))
        return calls, output.getvalue(), status

    def test_workflow_grants_write_only_to_guarded_job_without_checkout(self):
        self.assertIn("on:\n  pull_request:\n    types: [closed]\n", WORKFLOW)
        self.assertIn("permissions: {}\n\njobs:", WORKFLOW)
        self.assertIn("    permissions:\n      contents: write\n", WORKFLOW)
        self.assertEqual(WORKFLOW.count("contents: write"), 1)
        self.assertIn("GH_TOKEN: ${{ github.token }}", WORKFLOW)
        self.assertNotIn("uses:", WORKFLOW)
        self.assertNotIn("secrets.", WORKFLOW)
        self.assertTrue(self.job_allowed(self.event()))

    def test_matching_merged_head_deletes_only_exact_ref(self):
        calls, output, status = self.run_cleanup(self.event(), [self.ref(), Response(204)])
        self.assertEqual(status, 0)
        self.assertEqual([(method, url) for method, url, _ in calls],
                         [("GET", REF_URL), ("DELETE", DELETE_URL)])
        self.assertTrue(all(headers["Authorization"] == "Bearer " + TOKEN for _, _, headers in calls))
        self.assertIn("Deleted codex/work", output)

    def test_new_work_on_reused_branch_is_preserved(self):
        calls, output, status = self.run_cleanup(self.event(), [self.ref("b" * 40)])
        self.assertEqual(status, 0)
        self.assertEqual([(method, url) for method, url, _ in calls], [("GET", REF_URL)])
        self.assertIn("SHA has changed", output)

    def test_missing_ref_is_already_clean(self):
        missing = urllib.error.HTTPError(REF_URL, 404, "private-api-body", {}, io.BytesIO(b"private-api-body"))
        calls, output, status = self.run_cleanup(self.event(), [missing])
        self.assertEqual(status, 0)
        self.assertEqual(len(calls), 1)
        self.assertIn("already deleted", output)
        self.assertNotIn("private-api-body", output)

    def test_ineligible_events_fail_job_guard_and_inline_guard(self):
        for case in ("unmerged", "wrong branch", "fork", "wrong base"):
            with self.subTest(case=case):
                event = self.event()
                pr = event["pull_request"]
                if case == "unmerged":
                    pr["merged"] = False
                elif case == "wrong branch":
                    pr["head"]["ref"] = "main"
                elif case == "fork":
                    pr["head"]["repo"]["full_name"] = "someone/secretwright"
                else:
                    pr["base"]["ref"] = "release"
                self.assertFalse(self.job_allowed(event))
                calls, _, status = self.run_cleanup(event)
                self.assertEqual((calls, status), ([], 0))

    def test_inline_guard_also_rejects_other_event_or_repository(self):
        event = self.event()
        event["action"] = "opened"
        self.assertEqual(self.run_cleanup(event)[0], [])
        event = self.event()
        event["repository"]["full_name"] = "someone/secretwright"
        self.assertEqual(self.run_cleanup(event)[0], [])
        self.assertEqual(self.run_cleanup(self.event(), GITHUB_EVENT_NAME="workflow_dispatch")[0], [])
        self.assertEqual(self.run_cleanup(self.event(), GITHUB_REPOSITORY="owner/../../other")[0], [])

    def test_api_errors_fail_without_logging_body_or_trying_fallback_delete(self):
        for response in (
                urllib.error.HTTPError(REF_URL, 403, TOKEN, {}, io.BytesIO(b"private-api-body")),
                urllib.error.HTTPError(REF_URL, 500, TOKEN, {}, io.BytesIO(b"private-api-body")),
                urllib.error.URLError(TOKEN), TimeoutError(TOKEN),
                Response(200, {"unexpected": "private-api-body"})):
            with self.subTest(response=type(response).__name__):
                calls, output, status = self.run_cleanup(self.event(), [response])
                self.assertNotEqual(status, 0)
                self.assertEqual([(method, url) for method, url, _ in calls], [("GET", REF_URL)])
                self.assertNotIn("private-api-body", output + str(status))

    def test_delete_failure_is_sanitized_and_not_retried(self):
        failure = urllib.error.HTTPError(DELETE_URL, 422, TOKEN, {}, io.BytesIO(b"private-api-body"))
        calls, output, status = self.run_cleanup(self.event(), [self.ref(), failure])
        self.assertNotEqual(status, 0)
        self.assertEqual([(method, url) for method, url, _ in calls],
                         [("GET", REF_URL), ("DELETE", DELETE_URL)])
        self.assertNotIn("private-api-body", output + str(status))

    def test_redirect_handler_blocks_token_forwarding(self):
        definitions = {"__name__": "test_definitions"}
        exec(compile(SOURCE, "cleanup-work-branch.yml", "exec"), definitions)
        redirect = definitions["NoRedirect"]()
        self.assertIsNone(redirect.redirect_request(None, None, 302, "Found", {}, "https://other.example/"))


if __name__ == "__main__":
    unittest.main()
