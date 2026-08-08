from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.catalog import applicability, load_check
from cchia_engine.fixtures import validate_package_fixtures
from cchia_engine.runner import run_check


CHECK_ROOT = SKILL_ROOT / "checks" / "CLOUD" / "CCHIA-AZURE-IAM-005"


def _fixture(case: str) -> dict:
    return json.loads(
        (CHECK_ROOT / "fixtures" / f"{case}.json").read_text(encoding="utf-8")
    )


def _collector(case: str = "negative") -> dict:
    return copy.deepcopy(_fixture(case)["context"]["collectors"][0])


def _payload(collector: dict, command_id: str):
    for item in collector["evidence"]:
        if item["command_id"] == command_id:
            return item["data"]
    raise AssertionError(f"No payload for {command_id}")


def _assignment(collector: dict) -> dict:
    return _payload(collector, "role-assignments")[0]


def _context(collector: dict) -> dict:
    return {
        "signals": ["runtime-azure-role-assignments"],
        "collectors": [collector],
        "collection": {"complete": True},
    }


class RuntimeAzureIamCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package = load_check(CHECK_ROOT)

    def evaluate(self, collector: dict) -> dict:
        return run_check(self.package, _context(collector))["evaluation"]

    def test_applicability_requires_runtime_or_requested_signal(self):
        self.assertEqual("1.0.0", self.package.control_version)
        self.assertTrue(self.package.mapping["sources"])
        runtime, _ = applicability(
            self.package, {"runtime-azure-role-assignments"}
        )
        requested, _ = applicability(
            self.package, {"collector-az-role-assignments-requested"}
        )
        generic, _ = applicability(self.package, {"azure"})
        self.assertTrue(runtime)
        self.assertTrue(requested)
        self.assertFalse(generic)

    def test_fixture_matrix_and_canonical_collector_hashes_validate(self):
        results = validate_package_fixtures(self.package)
        self.assertEqual(
            [
                ("positive", "FAIL"),
                ("negative", "PASS"),
                ("no_evidence", "NOT_ASSESSED"),
            ],
            [(item["case"], item["actual_status"]) for item in results],
        )

    def test_complete_clean_snapshot_passes_without_principal_data(self):
        collector = _collector()
        evaluation = self.evaluate(collector)

        self.assertEqual("PASS", evaluation["status"])
        self.assertEqual("HIGH", evaluation["confidence"])
        self.assertEqual("E4", evaluation["evidence_level"])
        self.assertEqual(2, evaluation["evidence"][0]["commands_verified"])
        self.assertEqual(1, evaluation["evidence"][0]["assignments_evaluated"])
        serialized = json.dumps(evaluation)
        self.assertNotIn("fixture-platform-readers", serialized)
        self.assertNotIn("44444444-4444-4444-4444-444444444444", serialized)
        self.assertNotIn("fixture-observability", serialized)

    def test_privileged_roles_at_subscription_or_root_fail(self):
        cases = (
            (
                "Owner",
                "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
                "/subscriptions/11111111-1111-1111-1111-111111111111",
                "subscription",
            ),
            (
                "User Access Administrator",
                "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                "/",
                "root",
            ),
        )
        for role, role_id, scope, expected_scope in cases:
            with self.subTest(role=role, scope=scope):
                collector = _collector()
                assignment = _assignment(collector)
                assignment["roleDefinitionName"] = role
                assignment["roleDefinitionId"] = (
                    "/subscriptions/11111111-1111-1111-1111-111111111111/"
                    f"providers/Microsoft.Authorization/roleDefinitions/{role_id}"
                )
                assignment["scope"] = scope

                evaluation = self.evaluate(collector)

                self.assertEqual("FAIL", evaluation["status"])
                self.assertIn(
                    "privileged-role-broad-scope",
                    evaluation["evidence"][0]["patterns"],
                )
                self.assertEqual(expected_scope, evaluation["evidence"][0]["broad_scope"])

    def test_privileged_role_at_resource_group_is_outside_this_failure_pattern(self):
        collector = _collector()
        assignment = _assignment(collector)
        assignment["roleDefinitionName"] = "Owner"
        assignment["roleDefinitionId"] = (
            "/subscriptions/11111111-1111-1111-1111-111111111111/"
            "providers/Microsoft.Authorization/roleDefinitions/"
            "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        )

        self.assertEqual("PASS", self.evaluate(collector)["status"])

    def test_unknown_and_public_like_principals_fail_without_pii(self):
        cases = (
            ("FuturePrincipalType", "fixture-private@example.invalid", "unknown-principal"),
            ("Group", "Everyone", "public-like-principal"),
        )
        for principal_type, principal_name, pattern in cases:
            with self.subTest(pattern=pattern):
                collector = _collector()
                assignment = _assignment(collector)
                assignment["principalType"] = principal_type
                assignment["principalName"] = principal_name

                evaluation = self.evaluate(collector)

                self.assertEqual("FAIL", evaluation["status"])
                self.assertIn(pattern, evaluation["evidence"][0]["patterns"])
                self.assertNotIn(principal_name, json.dumps(evaluation))
                self.assertNotIn(assignment["principalId"], json.dumps(evaluation))

    def test_unavailable_error_or_absent_collector_is_not_assessed(self):
        for status in ("UNAVAILABLE", "ERROR"):
            with self.subTest(status=status):
                collector = _collector("no_evidence")
                collector["status"] = status
                evaluation = self.evaluate(collector)
                self.assertEqual("NOT_ASSESSED", evaluation["status"])
                self.assertEqual("E0", evaluation["evidence_level"])
        absent = run_check(
            self.package,
            {
                "signals": ["collector-az-role-assignments-requested"],
                "collectors": [],
                "collection": {"complete": True},
            },
        )["evaluation"]
        self.assertEqual("NOT_ASSESSED", absent["status"])

    def test_incomplete_command_payload_and_text_output_are_not_assessed(self):
        missing_command = _collector()
        missing_command["provenance"]["commands"].pop()
        missing_payload = _collector()
        missing_payload["evidence"].pop()
        truncated = _collector()
        truncated["evidence"][1]["content_type"] = "text/plain"
        truncated["evidence"][1]["data"] = "[TRUNCATED 200 CHARACTERS]"

        for collector in (missing_command, missing_payload, truncated):
            with self.subTest(records=len(collector.get("evidence", []))):
                self.assertEqual("NOT_ASSESSED", self.evaluate(collector)["status"])

    def test_invalid_hash_metadata_policy_or_selector_is_not_assessed(self):
        invalid_hash = _collector()
        invalid_hash["evidence_sha256"] = "not-a-hash"
        invalid_policy = _collector()
        invalid_policy["provenance"]["commands"][0]["policy_id"] = "az.account.delete.v1"
        mutating_argv = _collector()
        mutating_argv["provenance"]["commands"][1]["argv"] = [
            "az", "role", "assignment", "delete", "--assignee", "principal-must-not-leak"
        ]
        selector_mismatch = _collector()
        selector_mismatch["provenance"]["commands"][0]["argv"] = [
            "az", "account", "show", "--subscription", "audit-prod", "--output", "json"
        ]

        for collector in (invalid_hash, invalid_policy, mutating_argv, selector_mismatch):
            evaluation = self.evaluate(collector)
            self.assertEqual("NOT_ASSESSED", evaluation["status"])
            self.assertNotIn("principal-must-not-leak", json.dumps(evaluation))

    def test_redacted_or_incomplete_critical_payload_is_not_assessed(self):
        redacted = _collector()
        _assignment(redacted)["principalId"] = "[REDACTED]"
        incomplete = _collector()
        del _assignment(incomplete)["principalType"]
        bad_account = _collector()
        _payload(bad_account, "azure-account")["tenantId"] = "not-a-uuid"

        for collector in (redacted, incomplete, bad_account):
            self.assertEqual("NOT_ASSESSED", self.evaluate(collector)["status"])

    def test_findings_are_capped_and_never_include_raw_principals(self):
        collector = _collector()
        template = _assignment(collector)
        assignments = []
        for index in range(25):
            assignment = copy.deepcopy(template)
            assignment["principalType"] = f"UnknownType{index}"
            assignment["principalName"] = f"private-{index}@example.invalid"
            assignment["principalId"] = f"00000000-0000-0000-0000-{index:012d}"
            assignments.append(assignment)
        collector["evidence"][1]["data"] = assignments

        evaluation = self.evaluate(collector)

        self.assertEqual("FAIL", evaluation["status"])
        self.assertEqual(21, len(evaluation["evidence"]))
        self.assertEqual("finding-evidence-truncated", evaluation["evidence"][-1]["issue"])
        self.assertEqual(25, evaluation["evidence"][-1]["total_findings"])
        serialized = json.dumps(evaluation)
        self.assertNotIn("private-0@example.invalid", serialized)
        self.assertNotIn("00000000-0000-0000-0000-000000000000", serialized)


if __name__ == "__main__":
    unittest.main()
