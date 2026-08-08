from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.catalog import CheckSafetyError, load_catalog, validate_check_source
from cchia_engine.compiler import compile_assessment
from cchia_engine.scaffold import scaffold_check


class CatalogTests(unittest.TestCase):
    def test_catalog_contracts_and_sources_are_valid(self):
        packages = load_catalog(SKILL_ROOT / "checks")
        self.assertEqual(11, len(packages))
        self.assertEqual(11, len({item.control_id for item in packages}))
        self.assertTrue(all(item.control_version == "1.0.0" for item in packages))
        self.assertTrue(all(item.control["execution"]["mode"] == "read_only" for item in packages))
        self.assertTrue(all(item.mapping["sources"] for item in packages))

    def test_unsafe_check_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "check.py"
            path.write_text("import os\ndef evaluate(context):\n    os.remove('target')\n", encoding="utf-8")
            with self.assertRaises(CheckSafetyError):
                validate_check_source(path)

    def test_scaffold_creates_a_complete_package(self):
        with tempfile.TemporaryDirectory() as temp:
            catalog = Path(temp) / "checks"
            path = scaffold_check(catalog, "CCHIA-API-999", "API", "Validación de ejemplo")
            self.assertEqual(
                {"control.yaml", "check.py", "expected.json", "mapping.yaml", "README.md"},
                {item.name for item in path.iterdir()},
            )
            package = load_catalog(catalog)[0]
            self.assertEqual("CCHIA-API-999", package.control_id)


class CompilerEndToEndTests(unittest.TestCase):
    def test_compiler_selects_executes_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            shutil.copytree(SKILL_ROOT / "examples" / "demo-target", target)
            output = root / "output"
            result = compile_assessment(
                target=target,
                catalog_root=SKILL_ROOT / "checks",
                output=output,
                system_path=SKILL_ROOT / "examples" / "system.yaml",
            )
            assessment = result["assessment"]
            self.assertEqual("0.5.0", result["plan"]["engine"]["version"])
            self.assertEqual(64, len(result["plan"]["engine"]["sha256"]))
            self.assertEqual(64, len(result["plan"]["catalog"]["sha256"]))
            self.assertEqual(11, result["plan"]["catalog"]["control_count"])
            self.assertEqual(33, result["plan"]["catalog"]["fixture_count"])
            self.assertEqual(
                set(result["plan"]["selected_controls"]),
                set(result["plan"]["selected_control_versions"]),
            )
            self.assertTrue(
                all(version == "1.0.0" for version in result["plan"]["selected_control_versions"].values())
            )
            statuses = {item["control_id"]: item["evaluation"]["status"] for item in assessment["results"]}
            self.assertEqual(
                {
                    "CCHIA-AGT-005": "FAIL",
                    "CCHIA-AI-001": "PASS",
                    "CCHIA-GCP-IAM-002": "FAIL",
                    "CCHIA-IAM-001": "FAIL",
                    "CCHIA-K8S-001": "FAIL",
                },
                statuses,
            )
            self.assertTrue(assessment["target_integrity"]["unchanged"])
            self.assertTrue(all(item["control_version"] == "1.0.0" for item in assessment["results"]))
            self.assertEqual([], assessment["target_integrity"]["modified"])
            for name in ("plan.json", "context.json", "assessment.json", "report-cchia.md", "report-nist.md", "report-iso.md", "manifest.json"):
                self.assertTrue((output / name).is_file(), name)
            manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(manifest["artifacts"]), 11)
            evidence = json.loads((output / "evidence" / "CCHIA-IAM-001.json").read_text(encoding="utf-8"))
            serialized = json.dumps(evidence)
            self.assertNotIn("demo-secret-that-must-never-be-committed", serialized)

    def test_description_only_compilation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            description = root / "architecture.md"
            description.write_text(
                "AI agent with an MCP tool that can delete data from external email instructions.",
                encoding="utf-8",
            )
            result = compile_assessment(
                target=None,
                catalog_root=SKILL_ROOT / "checks",
                output=root / "output",
                system_path=description,
                plan_only=True,
            )
            selected = set(result["plan"]["selected_controls"])
            self.assertIn("CCHIA-AGT-005", selected)
            self.assertIn("CCHIA-AI-001", selected)
            self.assertEqual("read_only", result["plan"]["scope"]["execution_mode"])


if __name__ == "__main__":
    unittest.main()
