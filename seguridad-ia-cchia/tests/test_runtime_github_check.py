from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.catalog import applicability, load_check
from cchia_engine.collectors import CollectorValidationError, collect_requested
from cchia_engine.fixtures import validate_package_fixtures
from cchia_engine.runner import run_check


PACKAGE_PATH = SKILL_ROOT / "checks" / "DEVSECOPS" / "CCHIA-GH-REPO-006"
PACKAGE = load_check(PACKAGE_PATH)
FIXTURES = PACKAGE_PATH / "fixtures"
GH_EXECUTABLE = str((Path(tempfile.gettempdir()) / "cchia-test-tools" / "gh.exe").resolve())
API_HEADERS = [
    "-H",
    "Accept: application/vnd.github+json",
    "-H",
    "X-GitHub-Api-Version: 2022-11-28",
]


def _fixture(case: str) -> dict:
    return json.loads((FIXTURES / f"{case}.json").read_text(encoding="utf-8"))


def _context(case: str = "negative") -> dict:
    return copy.deepcopy(_fixture(case)["context"])


def _collector(context: dict) -> dict:
    return context["collectors"][0]


def _evidence(collector: dict, command_id: str) -> dict:
    return next(row for row in collector["evidence"] if row["command_id"] == command_id)


class GitHubCollectorTests(unittest.TestCase):
    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=GH_EXECUTABLE)
    def test_collector_uses_only_four_exact_fixed_read_only_commands(self, which, run):
        outputs = [
            {
                "nameWithOwner": "fixture-org/fixture-repo",
                "defaultBranchRef": {"name": "main"},
                "visibility": "PUBLIC",
                "isArchived": False,
            },
            {
                "full_name": "fixture-org/fixture-repo",
                "default_branch": "main",
                "visibility": "public",
                "archived": False,
                "private": False,
            },
            [],
            {
                "default_workflow_permissions": "read",
                "can_approve_pull_request_reviews": False,
            },
        ]
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=json.dumps(output), stderr="")
            for output in outputs
        ]

        [result] = collect_requested(
            ["gh-repo-security"],
            target=SKILL_ROOT,
            options={"github_repo": "fixture-org/fixture-repo", "timeout_seconds": 17},
        )

        self.assertEqual("AVAILABLE", result["status"])
        self.assertEqual("github", result["provenance"]["provider"])
        self.assertEqual("GitHub CLI", result["provenance"]["interface"]["sdk"])
        self.assertEqual(GH_EXECUTABLE, result["provenance"]["interface"]["resolved_executable"])
        self.assertEqual(
            [
                ("repo-view", "gh.repo.view.v1", [
                    "gh", "repo", "view", "fixture-org/fixture-repo", "--json",
                    "nameWithOwner,defaultBranchRef,visibility,isArchived",
                ]),
                ("repo-metadata", "gh.api.repo.v1", [
                    "gh", "api", "repos/fixture-org/fixture-repo", *API_HEADERS,
                ]),
                ("repo-rulesets", "gh.api.repo.rulesets.v1", [
                    "gh", "api", "repos/fixture-org/fixture-repo/rulesets", *API_HEADERS,
                ]),
                ("actions-workflow-permissions", "gh.api.repo.actions-workflow-permissions.v1", [
                    "gh", "api", "repos/fixture-org/fixture-repo/actions/permissions/workflow", *API_HEADERS,
                ]),
            ],
            [
                (row["command_id"], row["policy_id"], row["argv"])
                for row in result["provenance"]["commands"]
            ],
        )
        self.assertEqual(4, run.call_count)
        neutral_directories = set()
        for call in run.call_args_list:
            self.assertEqual(GH_EXECUTABLE, call.args[0][0])
            self.assertFalse(call.kwargs["shell"])
            self.assertIs(subprocess.DEVNULL, call.kwargs["stdin"])
            self.assertEqual(17, call.kwargs["timeout"])
            self.assertNotIn("env", call.kwargs)
            neutral_directories.add(Path(call.kwargs["cwd"]))
        self.assertEqual(1, len(neutral_directories))
        self.assertTrue(all(not path.exists() for path in neutral_directories))
        which.assert_called_once_with("gh")

    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which")
    def test_missing_or_malformed_repository_is_rejected_before_discovery(self, which, run):
        invalid = (None, "", "owner", "owner/repo/extra", "https://github.com/o/r", "--repo=o/r", "o/../r", "o/r x")
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(CollectorValidationError):
                collect_requested(["gh-repo-security"], options={"github_repo": value})
        which.assert_not_called()
        run.assert_not_called()

    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=None)
    def test_missing_gh_reports_unavailable_without_invocation(self, _which, run):
        [result] = collect_requested(
            ["gh-repo-security"], options={"github_repo": "fixture-org/fixture-repo"}
        )
        self.assertEqual("UNAVAILABLE", result["status"])
        self.assertEqual(4, len(result["provenance"]["commands"]))
        self.assertTrue(all(row["status"] == "UNAVAILABLE" for row in result["provenance"]["commands"]))
        self.assertEqual([], result["evidence"])
        run.assert_not_called()

    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=GH_EXECUTABLE)
    def test_403_or_invalid_json_is_error_or_non_json_and_never_fabricated(self, _which, run):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout="{}", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="{}", stderr=""),
            subprocess.CompletedProcess([], 1, stdout="", stderr="HTTP 403 token=secret-value"),
            subprocess.CompletedProcess([], 0, stdout="not-json", stderr=""),
        ]
        [result] = collect_requested(
            ["gh-repo-security"], options={"github_repo": "fixture-org/fixture-repo"}
        )
        self.assertEqual("ERROR", result["status"])
        self.assertIn("[REDACTED]", json.dumps(result))
        self.assertNotIn("secret-value", json.dumps(result))
        self.assertEqual("text/plain", result["evidence"][3]["content_type"])


class GitHubControlTests(unittest.TestCase):
    def test_applicability_accepts_runtime_or_requested_signal(self):
        self.assertTrue(applicability(PACKAGE, {"runtime-github-repo-security"})[0])
        self.assertTrue(applicability(PACKAGE, {"collector-gh-repo-security-requested"})[0])
        self.assertFalse(applicability(PACKAGE, set())[0])
        self.assertEqual("1.0.0", PACKAGE.control["version"])

    def test_fixtures_execute_exact_fail_pass_not_assessed_matrix(self):
        with patch("cchia_engine.collectors.executor.subprocess.run") as process:
            results = validate_package_fixtures(PACKAGE)
        process.assert_not_called()
        self.assertEqual(
            {"positive": "FAIL", "negative": "PASS", "no_evidence": "NOT_ASSESSED"},
            {row["case"]: row["actual_status"] for row in results},
        )

    def test_complete_safe_snapshot_passes_without_exposing_repository_identity(self):
        result = run_check(PACKAGE, _context("negative"))
        evaluation = result["evaluation"]
        self.assertEqual("PASS", evaluation["status"])
        self.assertEqual("E4", evaluation["evidence_level"])
        self.assertEqual(2, evaluation["evidence"][0]["required_approvals"])
        serialized = json.dumps(evaluation)
        self.assertNotIn("fixture-org", serialized)
        self.assertNotIn("fixture-repo", serialized)
        self.assertNotIn("main", serialized)

    def test_public_direct_gaps_fail_but_private_or_archived_gaps_are_partial(self):
        public_result = run_check(PACKAGE, _context("positive"))["evaluation"]
        self.assertEqual("FAIL", public_result["status"])
        patterns = {row["pattern"] for row in public_result["evidence"]}
        self.assertEqual(
            {
                "pull-request-approvals-not-required",
                "default-workflow-token-write",
                "actions-can-approve-pull-requests",
            },
            patterns,
        )

        private_context = _context("positive")
        private = _collector(private_context)
        view = _evidence(private, "repo-view")["data"]
        metadata = _evidence(private, "repo-metadata")["data"]
        view["visibility"] = "PRIVATE"
        metadata["visibility"] = "private"
        metadata["private"] = True
        self.assertEqual("PARTIAL", run_check(PACKAGE, private_context)["evaluation"]["status"])

        archived_context = _context("positive")
        archived = _collector(archived_context)
        _evidence(archived, "repo-view")["data"]["isArchived"] = True
        _evidence(archived, "repo-metadata")["data"]["archived"] = True
        self.assertEqual("PARTIAL", run_check(PACKAGE, archived_context)["evaluation"]["status"])

    def test_missing_ruleset_is_partial_because_legacy_protection_is_unproven(self):
        context = _context("negative")
        _evidence(_collector(context), "repo-rulesets")["data"] = []
        evaluation = run_check(PACKAGE, context)["evaluation"]
        self.assertEqual("PARTIAL", evaluation["status"])
        self.assertEqual("default-branch-ruleset-not-observed", evaluation["evidence"][0]["pattern"])

    def test_unavailable_error_missing_or_text_evidence_never_passes(self):
        contexts = [_context("no_evidence"), {"collectors": [], "collection": {"complete": True}}]
        error_context = _context("negative")
        _collector(error_context)["status"] = "ERROR"
        contexts.append(error_context)
        missing_context = _context("negative")
        _collector(missing_context)["evidence"].pop()
        contexts.append(missing_context)
        text_context = _context("negative")
        _evidence(_collector(text_context), "repo-rulesets")["content_type"] = "text/plain"
        contexts.append(text_context)
        for context in contexts:
            with self.subTest(context=contexts.index(context)):
                self.assertEqual("NOT_ASSESSED", run_check(PACKAGE, context)["evaluation"]["status"])

    def test_version_hash_redaction_interface_policy_or_argv_drift_is_not_assessed(self):
        mutations = []
        version = _context()
        _collector(version)["collector_version"] = "2.0.0"
        mutations.append(version)
        bad_hash = _context()
        _collector(bad_hash)["evidence_sha256"] = "invalid"
        mutations.append(bad_hash)
        redaction = _context()
        _collector(redaction)["redaction"]["applied"] = False
        mutations.append(redaction)
        provider = _context()
        _collector(provider)["provenance"]["provider"] = "gcp"
        mutations.append(provider)
        interface = _context()
        _collector(interface)["provenance"]["interface"]["resolved_executable"] = None
        mutations.append(interface)
        policy = _context()
        _collector(policy)["provenance"]["commands"][2]["policy_id"] = "gh.api.unknown.v1"
        mutations.append(policy)
        argv = _context()
        _collector(argv)["provenance"]["commands"][2]["argv"].append("--paginate")
        mutations.append(argv)
        missing = _context()
        _collector(missing)["provenance"]["commands"].pop()
        mutations.append(missing)
        for context in mutations:
            with self.subTest(context=mutations.index(context)):
                self.assertEqual("NOT_ASSESSED", run_check(PACKAGE, context)["evaluation"]["status"])

    def test_identity_mismatch_unknown_shape_and_redacted_critical_value_are_not_assessed(self):
        contexts = []
        selector_mismatch = _context()
        _collector(selector_mismatch)["provenance"]["commands"][0]["argv"][3] = "other/repo"
        contexts.append(selector_mismatch)
        identity_mismatch = _context()
        _evidence(_collector(identity_mismatch), "repo-metadata")["data"]["full_name"] = "other/repo"
        contexts.append(identity_mismatch)
        redacted = _context()
        _evidence(_collector(redacted), "repo-view")["data"]["defaultBranchRef"]["name"] = "[REDACTED]"
        contexts.append(redacted)
        private_mismatch = _context()
        _evidence(_collector(private_mismatch), "repo-metadata")["data"]["private"] = True
        contexts.append(private_mismatch)
        malformed = _context()
        _evidence(_collector(malformed), "actions-workflow-permissions")["data"] = {"default_workflow_permissions": "read"}
        contexts.append(malformed)
        for context in contexts:
            with self.subTest(context=contexts.index(context)):
                self.assertEqual("NOT_ASSESSED", run_check(PACKAGE, context)["evaluation"]["status"])

    def test_ruleset_detail_omission_and_possible_pagination_are_not_assessed(self):
        detail_missing = _context()
        ruleset = _evidence(_collector(detail_missing), "repo-rulesets")["data"][0]
        ruleset.pop("rules")
        paginated = _context()
        base = _evidence(_collector(paginated), "repo-rulesets")["data"][0]
        _evidence(_collector(paginated), "repo-rulesets")["data"] = [copy.deepcopy(base) for _ in range(30)]
        for context in (detail_missing, paginated):
            self.assertEqual("NOT_ASSESSED", run_check(PACKAGE, context)["evaluation"]["status"])

    def test_untrusted_payload_values_are_not_reflected_in_error_evidence(self):
        context = _context()
        _collector(context)["provenance"]["commands"][0]["command_id"] = ["sensitive-marker"]
        evaluation = run_check(PACKAGE, context)["evaluation"]
        self.assertEqual("NOT_ASSESSED", evaluation["status"])
        self.assertNotIn("sensitive-marker", json.dumps(evaluation))


if __name__ == "__main__":
    unittest.main()
