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
from cchia_engine.collectors import verify_collector_evidence_hash
from cchia_engine.fixtures import validate_package_fixtures
from cchia_engine.runner import run_check


CHECK_ROOT = SKILL_ROOT / "checks" / "CLOUD" / "CCHIA-AWS-IAM-004"


def _fixture(case: str) -> dict:
    return json.loads(
        (CHECK_ROOT / "fixtures" / f"{case}.json").read_text(encoding="utf-8")
    )


def _collector(case: str = "negative") -> dict:
    return copy.deepcopy(_fixture(case)["context"]["collectors"][0])


def _payload(collector: dict, command_id: str) -> dict:
    for item in collector["evidence"]:
        if item["command_id"] == command_id:
            return item["data"]
    raise AssertionError(f"No payload for {command_id}")


def _context(collector: dict) -> dict:
    return {
        "signals": ["runtime-aws-iam"],
        "collectors": [collector],
        "collection": {"complete": True},
    }


class RuntimeAwsIamCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package = load_check(CHECK_ROOT)

    def evaluate(self, collector: dict) -> dict:
        return run_check(self.package, _context(collector))["evaluation"]

    def test_applicability_selects_runtime_or_requested_signal_only(self):
        self.assertEqual("1.0.0", self.package.control_version)
        self.assertTrue(self.package.mapping["sources"])
        runtime, _ = applicability(self.package, {"runtime-aws-iam"})
        requested, _ = applicability(self.package, {"collector-aws-iam-requested"})
        generic, _ = applicability(self.package, {"aws"})
        self.assertTrue(runtime)
        self.assertTrue(requested)
        self.assertFalse(generic)

    def test_package_fixture_matrix_and_canonical_collector_hashes_validate(self):
        results = validate_package_fixtures(self.package)
        self.assertEqual(
            {"positive": "FAIL", "negative": "PASS", "no_evidence": "NOT_ASSESSED"},
            {item["case"]: item["actual_status"] for item in results},
        )
        tampered = _collector()
        _payload(tampered, "account-summary")["SummaryMap"]["AccountMFAEnabled"] = 0
        with self.assertRaises(ValueError):
            verify_collector_evidence_hash(tampered)

    def test_root_mfa_and_access_key_risks_fail_independently(self):
        for field, unsafe_value, pattern in (
            ("AccountMFAEnabled", 0, "root-mfa-disabled"),
            ("AccountAccessKeysPresent", 1, "root-access-keys-present"),
        ):
            with self.subTest(field=field):
                collector = _collector()
                summary = _payload(collector, "account-summary")["SummaryMap"]
                summary[field] = unsafe_value
                evaluation = self.evaluate(collector)
                self.assertEqual("FAIL", evaluation["status"])
                self.assertIn(pattern, {item["pattern"] for item in evaluation["evidence"]})

    def test_administrator_access_fails_without_leaking_principal(self):
        collector = _collector()
        authorization = _payload(collector, "account-authorization-details")
        user = authorization["UserDetailList"][0]
        user["UserName"] = "principal-must-not-leak"
        user["AttachedManagedPolicies"] = [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            }
        ]

        evaluation = self.evaluate(collector)

        self.assertEqual("FAIL", evaluation["status"])
        self.assertEqual("administrator-access-attached", evaluation["evidence"][0]["pattern"])
        self.assertNotIn("principal-must-not-leak", json.dumps(evaluation))
        self.assertNotIn("UserName", json.dumps(evaluation))

    def test_inline_and_local_wildcards_fail_with_bounded_evidence(self):
        collector = _collector()
        authorization = _payload(collector, "account-authorization-details")
        authorization["UserDetailList"][0]["UserPolicyList"][0]["PolicyDocument"]["Statement"] = {
            "Effect": "Allow",
            "NotAction": ["iam:DeleteUser"],
            "Resource": "*",
        }
        authorization["Policies"][0]["PolicyVersionList"][0]["Document"]["Statement"] = {
            "Effect": "Allow",
            "Action": "ec2:*",
            "Resource": "*",
        }

        evaluation = self.evaluate(collector)

        self.assertEqual("FAIL", evaluation["status"])
        patterns = {item["pattern"] for item in evaluation["evidence"]}
        self.assertEqual({"allow-not-action", "allow-action-wildcard"}, patterns)
        self.assertNotIn("fixture-inline-read", json.dumps(evaluation))
        self.assertNotIn("fixture-local-read", json.dumps(evaluation))

    def test_unattached_local_wildcard_and_local_policy_name_collision_do_not_false_fail(self):
        unattached = _collector()
        authorization = _payload(unattached, "account-authorization-details")
        authorization["UserDetailList"][0]["AttachedManagedPolicies"] = [
            authorization["UserDetailList"][0]["AttachedManagedPolicies"][0]
        ]
        authorization["Policies"][0]["PolicyVersionList"][0]["Document"]["Statement"] = {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
        self.assertEqual("PASS", self.evaluate(unattached)["status"])

        name_collision = _collector()
        authorization = _payload(name_collision, "account-authorization-details")
        local_arn = "arn:aws:iam::123456789012:policy/AdministratorAccess"
        authorization["UserDetailList"][0]["AttachedManagedPolicies"] = [
            {"PolicyName": "AdministratorAccess", "PolicyArn": local_arn}
        ]
        authorization["Policies"][0]["PolicyName"] = "AdministratorAccess"
        authorization["Policies"][0]["Arn"] = local_arn
        self.assertEqual("PASS", self.evaluate(name_collision)["status"])

    def test_complete_clean_snapshot_passes_without_principal_data(self):
        collector = _collector()
        evaluation = self.evaluate(collector)

        self.assertEqual("PASS", evaluation["status"])
        self.assertEqual("HIGH", evaluation["confidence"])
        self.assertEqual("E4", evaluation["evidence_level"])
        self.assertEqual(3, evaluation["evidence"][0]["commands_verified"])
        self.assertEqual(3, evaluation["evidence"][0]["principals_scanned"])
        serialized = json.dumps(evaluation)
        for sensitive in ("fixture-user", "fixture-role", "fixture-group", "123456789012"):
            self.assertNotIn(sensitive, serialized)

    def test_unavailable_error_or_missing_collector_never_passes(self):
        unavailable = _collector("no_evidence")
        error = _collector("no_evidence")
        error["status"] = "ERROR"
        contexts = [unavailable, error]
        for collector in contexts:
            with self.subTest(status=collector["status"]):
                self.assertEqual("NOT_ASSESSED", self.evaluate(collector)["status"])
        empty = run_check(
            self.package,
            {"signals": ["collector-aws-iam-requested"], "collectors": [], "collection": {"complete": True}},
        )["evaluation"]
        self.assertEqual("NOT_ASSESSED", empty["status"])

    def test_truncated_or_paginated_inventory_is_not_assessed(self):
        for field, value in (("IsTruncated", True), ("NextToken", "token-must-not-leak")):
            with self.subTest(field=field):
                collector = _collector()
                _payload(collector, "account-authorization-details")[field] = value
                evaluation = self.evaluate(collector)
                self.assertEqual("NOT_ASSESSED", evaluation["status"])
                self.assertNotIn("token-must-not-leak", json.dumps(evaluation))

    def test_invalid_hash_command_metadata_or_missing_payload_is_not_assessed(self):
        invalid_hash = _collector()
        invalid_hash["evidence_sha256"] = "not-a-hash"
        invalid_argv = _collector()
        invalid_argv["provenance"]["commands"][0]["argv"] = [
            "aws", "iam", "delete-user", "--user-name", "principal-must-not-leak"
        ]
        missing_command = _collector()
        missing_command["provenance"]["commands"].pop()
        missing_payload = _collector()
        missing_payload["evidence"].pop()

        for collector in (invalid_hash, invalid_argv, missing_command, missing_payload):
            evaluation = self.evaluate(collector)
            self.assertEqual("NOT_ASSESSED", evaluation["status"])
            self.assertNotIn("principal-must-not-leak", json.dumps(evaluation))

    def test_redacted_or_structurally_incomplete_critical_fields_are_not_assessed(self):
        redacted = _collector()
        _payload(redacted, "account-summary")["SummaryMap"]["AccountMFAEnabled"] = "[REDACTED]"
        incomplete = _collector()
        del _payload(incomplete, "account-authorization-details")["RoleDetailList"][0][
            "AttachedManagedPolicies"
        ]

        self.assertEqual("NOT_ASSESSED", self.evaluate(redacted)["status"])
        self.assertEqual("NOT_ASSESSED", self.evaluate(incomplete)["status"])


if __name__ == "__main__":
    unittest.main()
