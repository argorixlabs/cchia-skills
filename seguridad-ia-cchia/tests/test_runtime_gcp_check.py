from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.catalog import applicability, load_check
from cchia_engine.runner import run_check


CHECK_ROOT = SKILL_ROOT / "checks" / "CLOUD" / "CCHIA-GCP-IAM-003"


def _command(command_id: str, policy_id: str, *, status: str = "AVAILABLE", exit_code: int | None = 0) -> dict:
    return {
        "command_id": command_id,
        "policy_id": policy_id,
        "argv": ["gcloud", command_id],
        "status": status,
        "exit_code": exit_code,
        "duration_ms": 1,
        "stdout_sha256": "b" * 64,
        "stderr": "",
    }


def _evidence(command_id: str, data, *, status: str = "AVAILABLE") -> dict:
    return {
        "command_id": command_id,
        "status": status,
        "content_type": "application/json",
        "data": data,
    }


def _collector(*, status: str = "AVAILABLE", bindings: list | None = None) -> dict:
    command_status = status if status != "UNAVAILABLE" else "UNAVAILABLE"
    exit_code = 0 if status == "AVAILABLE" else None
    commands = [
        _command("project-description", "gcloud.projects.describe.v1", status=command_status, exit_code=exit_code),
        _command("project-iam-policy", "gcloud.projects.get-iam-policy.v1", status=command_status, exit_code=exit_code),
        _command("service-accounts", "gcloud.iam.service-accounts.list.v1", status=command_status, exit_code=exit_code),
    ]
    evidence = []
    if status != "UNAVAILABLE":
        evidence = [
            _evidence("project-description", {"projectId": "demo-project"}, status=status),
            _evidence("project-iam-policy", {"bindings": bindings or []}, status=status),
            _evidence("service-accounts", [{"email": "runtime@demo-project.iam.gserviceaccount.com"}], status=status),
        ]
    return {
        "schema_version": "1.0",
        "collector_id": "gcloud-iam",
        "collector_version": "1.0.0",
        "mode": "read_only",
        "status": status,
        "collected_at": "2026-08-07T22:00:00Z",
        "provenance": {
            "target": str(SKILL_ROOT),
            "provider": "gcp",
            "interface": {
                "kind": "command",
                "tool": "gcloud",
                "sdk": "Google Cloud CLI",
                "sdk_version": None,
                "executable_available": status != "UNAVAILABLE",
                "resolved_executable": None if status == "UNAVAILABLE" else "C:/mock/gcloud.exe",
            },
            "commands": commands,
        },
        "evidence": evidence,
        "redaction": {
            "applied": True,
            "strategy": "cchia-default-v1",
            "replacement": "[REDACTED]",
        },
        "limitations": ["Snapshot puntual; no prueba ausencia de drift."],
        "evidence_sha256": "a" * 64,
    }


def _context(collector: dict) -> dict:
    return {
        "signals": ["runtime-gcp-iam"],
        "collectors": [collector],
        "collection": {"complete": True},
    }


class RuntimeGcpIamCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.package = load_check(CHECK_ROOT)

    def evaluate(self, collector: dict) -> dict:
        return run_check(self.package, _context(collector))["evaluation"]

    def test_applicability_selects_runtime_or_requested_collector_signal(self):
        self.assertEqual("1.0.0", self.package.control["version"])
        self.assertTrue(self.package.mapping["sources"])
        applies_runtime, _ = applicability(self.package, {"runtime-gcp-iam"})
        applies_requested, _ = applicability(self.package, {"collector-gcloud-iam-requested"})
        excluded, _ = applicability(self.package, {"gcp"})

        self.assertTrue(applies_runtime)
        self.assertTrue(applies_requested)
        self.assertFalse(excluded)

    def test_unavailable_or_error_collector_is_never_pass(self):
        for status in ("UNAVAILABLE", "ERROR"):
            with self.subTest(status=status):
                evaluation = self.evaluate(_collector(status=status))
                self.assertEqual("NOT_ASSESSED", evaluation["status"])
                self.assertEqual("E0", evaluation["evidence_level"])

    def test_missing_required_command_or_payload_is_not_assessed(self):
        missing_command = _collector()
        missing_command["provenance"]["commands"] = missing_command["provenance"]["commands"][:-1]
        missing_payload = _collector()
        missing_payload["evidence"] = missing_payload["evidence"][:-1]

        for collector in (missing_command, missing_payload):
            with self.subTest(records=len(collector.get("evidence", []))):
                self.assertEqual("NOT_ASSESSED", self.evaluate(collector)["status"])

    def test_unknown_contract_or_unresolved_executable_is_not_assessed(self):
        unknown_contract = _collector()
        unknown_contract["collector_version"] = "2.0.0"
        unresolved = _collector()
        unresolved["provenance"]["interface"]["resolved_executable"] = None

        self.assertEqual("NOT_ASSESSED", self.evaluate(unknown_contract)["status"])
        self.assertEqual("NOT_ASSESSED", self.evaluate(unresolved)["status"])

    def test_malformed_untrusted_command_metadata_is_not_reflected(self):
        collector = _collector()
        collector["provenance"]["commands"][0]["command_id"] = ["sensitive-marker"]
        collector["provenance"]["commands"][0]["status"] = "ERROR"

        evaluation = self.evaluate(collector)

        self.assertEqual("NOT_ASSESSED", evaluation["status"])
        self.assertNotIn("sensitive-marker", json.dumps(evaluation))

    def test_incomplete_or_redacted_binding_is_not_assessed(self):
        incomplete = _collector(bindings=[{"role": "roles/customRole"}])
        redacted = _collector(bindings=[{"role": "[REDACTED]", "members": ["user:a@example.com"]}])

        self.assertEqual("NOT_ASSESSED", self.evaluate(incomplete)["status"])
        self.assertEqual("NOT_ASSESSED", self.evaluate(redacted)["status"])

    def test_each_basic_role_fails(self):
        for role in ("roles/owner", "roles/editor", "roles/viewer"):
            with self.subTest(role=role):
                evaluation = self.evaluate(
                    _collector(bindings=[{"role": role, "members": ["user:a@example.com"]}])
                )
                self.assertEqual("FAIL", evaluation["status"])
                self.assertEqual(role, evaluation["evidence"][0]["basic_role"])
                self.assertIn("basic-role", evaluation["evidence"][0]["patterns"])

    def test_each_public_principal_fails_without_leaking_other_members(self):
        for member in ("allUsers", "allAuthenticatedUsers"):
            with self.subTest(member=member):
                collector = _collector(bindings=[{
                    "role": "roles/custom.applicationReader",
                    "members": ["user:private@example.com", member],
                }])
                evaluation = self.evaluate(collector)
                self.assertEqual("FAIL", evaluation["status"])
                self.assertIn(member, evaluation["evidence"][0]["public_members"])
                self.assertNotIn("private@example.com", json.dumps(evaluation))

    def test_complete_clean_snapshot_passes_with_bounded_evidence(self):
        collector = _collector(bindings=[{
            "role": "roles/compute.viewer",
            "members": ["group:platform@example.com"],
        }])

        evaluation = self.evaluate(collector)

        self.assertEqual("PASS", evaluation["status"])
        self.assertEqual("HIGH", evaluation["confidence"])
        self.assertEqual("E4", evaluation["evidence_level"])
        self.assertEqual(3, evaluation["evidence"][0]["commands_verified"])
        self.assertEqual(1, evaluation["evidence"][0]["bindings_evaluated"])
        self.assertNotIn("platform@example.com", json.dumps(evaluation))


if __name__ == "__main__":
    unittest.main()
