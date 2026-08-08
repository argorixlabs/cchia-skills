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


CASES = (
    (
        "aws-iam",
        "CCHIA-AWS-IAM-004",
        "CLOUD",
        "runtime-aws-iam",
        {"aws_profile": "audit-prod"},
    ),
    (
        "az-role-assignments",
        "CCHIA-AZURE-IAM-005",
        "CLOUD",
        "runtime-azure-role-assignments",
        {"azure_subscription": "audit-subscription"},
    ),
    (
        "gh-repo-security",
        "CCHIA-GH-REPO-006",
        "DEVSECOPS",
        "runtime-github-repo-security",
        {"github_repo": "acme/platform"},
    ),
)


def _fixture(domain: str, control_id: str, case: str) -> dict:
    path = SKILL_ROOT / "checks" / domain / control_id / "fixtures" / f"{case}.json"
    return json.loads(path.read_text(encoding="utf-8"))


class ProviderRuntimeCompilerTests(unittest.TestCase):
    def _compile(self, collector: dict, collector_id: str, options: dict) -> dict:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "assessment"
        with patch("cchia_engine.compiler.collect_requested", return_value=[collector]):
            result = compile_assessment(
                target=SKILL_ROOT / "examples" / "demo-target",
                catalog_root=SKILL_ROOT / "checks",
                output=output,
                collector_names=[collector_id],
                collector_options=options,
            )
        self.assertTrue((output / "collector-evidence" / f"{collector_id}.json").is_file())
        return result

    def test_available_safe_snapshots_auto_select_and_pass_provider_checks(self):
        for collector_id, control_id, domain, runtime_signal, options in CASES:
            with self.subTest(collector_id=collector_id):
                fixture = _fixture(domain, control_id, "negative")
                result = self._compile(
                    fixture["context"]["collectors"][0], collector_id, options
                )
                self.assertIn(runtime_signal, result["plan"]["scope"]["signals"])
                self.assertIn(control_id, result["plan"]["selected_controls"])
                evaluations = {
                    item["control_id"]: item["evaluation"]["status"]
                    for item in result["assessment"]["results"]
                }
                self.assertEqual("PASS", evaluations[control_id])

    def test_unavailable_snapshots_remain_visible_and_never_pass(self):
        for collector_id, control_id, domain, runtime_signal, options in CASES:
            with self.subTest(collector_id=collector_id):
                fixture = _fixture(domain, control_id, "no_evidence")
                result = self._compile(
                    fixture["context"]["collectors"][0], collector_id, options
                )
                signals = result["plan"]["scope"]["signals"]
                self.assertIn(f"collector-{collector_id}-requested", signals)
                self.assertNotIn(runtime_signal, signals)
                self.assertIn(control_id, result["plan"]["selected_controls"])
                evaluations = {
                    item["control_id"]: item["evaluation"]["status"]
                    for item in result["assessment"]["results"]
                }
                self.assertEqual("NOT_ASSESSED", evaluations[control_id])


if __name__ == "__main__":
    unittest.main()
