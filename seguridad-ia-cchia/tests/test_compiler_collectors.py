from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.compiler import compile_assessment
from cchia_engine.contracts import validate_contract
from cchia_engine.models import ContractError
from cchia_engine.utils import canonical_hash, sha256_file


def _collector_result(
    collector_id: str = "gcloud-iam",
    *,
    status: str = "AVAILABLE",
    limitations: list[str] | None = None,
) -> dict:
    tool = "gcloud" if collector_id == "gcloud-iam" else "kubectl"
    provider = "gcp" if tool == "gcloud" else "kubernetes"
    sdk = "Google Cloud CLI" if tool == "gcloud" else "Kubernetes kubectl client"
    command_status = status
    evidence = []
    if status != "UNAVAILABLE":
        evidence = [
            {
                "command_id": "runtime-inventory",
                "status": status,
                "content_type": "application/json",
                "data": {"bindings": [{"role": "roles/viewer"}]},
            }
        ]
    result = {
        "schema_version": "1.0",
        "collector_id": collector_id,
        "collector_version": "1.0.0",
        "mode": "read_only",
        "status": status,
        "collected_at": "2026-08-07T22:00:00Z",
        "provenance": {
            "target": str(SKILL_ROOT / "examples" / "demo-target"),
            "provider": provider,
            "interface": {
                "kind": "command",
                "tool": tool,
                "sdk": sdk,
                "sdk_version": None,
                "executable_available": status != "UNAVAILABLE",
                "resolved_executable": (
                    None if status == "UNAVAILABLE" else str(Path("C:/mock") / f"{tool}.exe")
                ),
            },
            "commands": [
                {
                    "command_id": "runtime-inventory",
                    "policy_id": f"{tool}.test.read-only.v1",
                    "argv": [tool, "version" if tool == "kubectl" else "projects", "--help"],
                    "status": command_status,
                    "exit_code": None if status == "UNAVAILABLE" else 0,
                    "duration_ms": 0,
                }
            ],
        },
        "evidence": evidence,
        "redaction": {
            "applied": True,
            "strategy": "cchia-default-v1",
            "replacement": "[REDACTED]",
        },
        "limitations": limitations or [],
    }
    result["evidence_sha256"] = canonical_hash(
        {
            "collector_id": result["collector_id"],
            "collector_version": result["collector_version"],
            "evidence": result["evidence"],
        }
    )
    return result


class CompilerCollectorIntegrationTests(unittest.TestCase):
    def test_opt_in_persists_evidence_summary_assessment_and_manifest_hash(self):
        collector = _collector_result()
        validate_contract("collector-result.schema.json", collector)

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "assessment"
            target = SKILL_ROOT / "examples" / "demo-target"
            with (
                patch("cchia_engine.compiler.collect_requested", return_value=[collector]) as collect,
                patch("cchia_engine.compiler.run_checks", return_value=[]),
                patch(
                    "cchia_engine.compiler.validate_contract", wraps=validate_contract
                ) as validate,
            ):
                result = compile_assessment(
                    target=target,
                    catalog_root=SKILL_ROOT / "checks",
                    output=output,
                    collector_names=["gcloud-iam"],
                    collector_options={"gcp_project": "demo-project", "timeout_seconds": 12},
                )

            collect.assert_called_once_with(
                ["gcloud-iam"],
                target=target.resolve(),
                options={"gcp_project": "demo-project", "timeout_seconds": 12},
            )
            validated_contracts = [call.args[0] for call in validate.call_args_list]
            self.assertIn("collector-request.schema.json", validated_contracts)
            self.assertIn("collector-result.schema.json", validated_contracts)
            self.assertIn("plan.schema.json", validated_contracts)
            self.assertIn("assessment.schema.json", validated_contracts)

            collector_path = output / "collector-evidence" / "gcloud-iam.json"
            self.assertTrue(collector_path.is_file())
            self.assertEqual(collector, json.loads(collector_path.read_text(encoding="utf-8")))

            expected_summary = {
                "collector_id": "gcloud-iam",
                "collector_version": "1.0.0",
                "status": "AVAILABLE",
                "collected_at": "2026-08-07T22:00:00Z",
                "mode": "read_only",
                "evidence_sha256": collector["evidence_sha256"],
            }
            context = json.loads((output / "context.json").read_text(encoding="utf-8"))
            self.assertEqual([expected_summary], context["collectors"])
            self.assertNotIn("evidence", context["collectors"][0])
            self.assertNotIn("provenance", context["collectors"][0])
            self.assertEqual([expected_summary], result["plan"]["scope"]["collectors"])
            self.assertEqual([collector], result["assessment"]["collector_evidence"])

            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            artifacts = {item["path"]: item["sha256"] for item in manifest["artifacts"]}
            relative_path = "collector-evidence/gcloud-iam.json"
            self.assertIn(relative_path, artifacts)
            self.assertEqual(sha256_file(collector_path), artifacts[relative_path])

    def test_default_compile_does_not_call_collect_requested(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "plan"
            with patch("cchia_engine.compiler.collect_requested") as collect:
                result = compile_assessment(
                    target=SKILL_ROOT / "examples" / "demo-target",
                    catalog_root=SKILL_ROOT / "checks",
                    output=output,
                    plan_only=True,
                )
            collect.assert_not_called()
            self.assertEqual([], result["plan"]["scope"]["collectors"])
            context = json.loads((output / "context.json").read_text(encoding="utf-8"))
            self.assertEqual([], context["collectors"])
            self.assertFalse((output / "collector-evidence").exists())

    def test_unavailable_collector_adds_explicit_assessment_limitations(self):
        collector = _collector_result(
            "kubectl-cluster",
            status="UNAVAILABLE",
            limitations=["kubectl no disponible; no se consultó el API server."],
        )
        validate_contract("collector-result.schema.json", collector)

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "assessment"
            with (
                patch("cchia_engine.compiler.collect_requested", return_value=[collector]),
                patch("cchia_engine.compiler.run_checks", return_value=[]),
            ):
                result = compile_assessment(
                    target=SKILL_ROOT / "examples" / "demo-target",
                    catalog_root=SKILL_ROOT / "checks",
                    output=output,
                    collector_names=["kubectl-cluster"],
                )

            self.assertEqual([collector], result["assessment"]["collector_evidence"])
            limitations = result["assessment"]["limitations"]
            self.assertTrue(
                any("kubectl-cluster terminó UNAVAILABLE" in item for item in limitations),
                limitations,
            )
            self.assertIn(
                "Collector kubectl-cluster: kubectl no disponible; no se consultó el API server.",
                limitations,
            )

    def test_invalid_collector_result_is_rejected_by_runtime_contract(self):
        invalid = _collector_result()
        invalid["mode"] = "write"
        with tempfile.TemporaryDirectory() as temp:
            with patch("cchia_engine.compiler.collect_requested", return_value=[invalid]):
                with self.assertRaises(ContractError) as raised:
                    compile_assessment(
                        target=SKILL_ROOT / "examples" / "demo-target",
                        catalog_root=SKILL_ROOT / "checks",
                        output=Path(temp) / "invalid",
                        collector_names=["gcloud-iam"],
                        collector_options={"gcp_project": "demo-project"},
                        plan_only=True,
                    )
        self.assertIn("collector-result.schema.json", str(raised.exception))
        self.assertIn("read_only", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
