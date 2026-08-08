from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.catalog import load_catalog
from cchia_engine.cli import main
from cchia_engine.collectors import CollectorResult
from cchia_engine.fixtures import validate_catalog_fixtures, validate_package_fixtures
from cchia_engine.models import ContractError
from cchia_engine.scaffold import scaffold_check


CONTROL_ID = "CCHIA-API-901"


def _check_source(positive_status: str) -> str:
    return (
        "def evaluate(context):\n"
        "    case = context.get('fixture_case')\n"
        f"    status = '{positive_status}' if case == 'positive' else "
        "('PASS' if case == 'negative' else 'NOT_ASSESSED')\n"
        "    return {\n"
        "        'status': status,\n"
        "        'confidence': 'HIGH' if status != 'NOT_ASSESSED' else 'LOW',\n"
        "        'evidence_level': 'E3' if status != 'NOT_ASSESSED' else 'E0',\n"
        "        'summary': 'Resultado determinista del fixture.',\n"
        "        'evidence': [{'case': case}] if status != 'NOT_ASSESSED' else [],\n"
        "        'recommendation': 'Verificar nuevamente el control.',\n"
        "    }\n"
    )


def _fixture(case: str, expected_status: str, *, collectors: list[dict] | None = None) -> dict:
    context = {
        "fixture_case": case,
        "collection": {"complete": True, "mode": "read_only"},
    }
    if collectors is not None:
        context["collectors"] = collectors
    return {
        "schema_version": "1.0",
        "control_id": CONTROL_ID,
        "case": case,
        "expected_status": expected_status,
        "context": context,
    }


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _make_catalog(
    root: Path,
    *,
    positive_status: str = "FAIL",
    positive_expected: str | None = None,
    cases: tuple[str, ...] = ("positive", "negative", "no_evidence"),
) -> tuple[Path, Path]:
    catalog = root / "checks"
    package_path = scaffold_check(catalog, CONTROL_ID, "API", "Fixture contract test")
    (package_path / "check.py").write_text(_check_source(positive_status), encoding="utf-8")
    expected = {
        "positive": positive_expected or positive_status,
        "negative": "PASS",
        "no_evidence": "NOT_ASSESSED",
    }
    for case in cases:
        _write_json(package_path / "fixtures" / f"{case}.json", _fixture(case, expected[case]))
    return catalog, package_path


def _valid_collector() -> dict:
    return CollectorResult(
        collector_id="gcloud-iam",
        collector_version="1.0.0",
        status="AVAILABLE",
        collected_at="2026-08-07T22:00:00Z",
        provenance={
            "target": "C:/fixture",
            "provider": "gcp",
            "interface": {
                "kind": "command",
                "tool": "gcloud",
                "sdk": "Google Cloud CLI",
                "sdk_version": None,
                "executable_available": True,
                "resolved_executable": "C:/tools/gcloud.exe",
            },
            "commands": [
                {
                    "command_id": "project-description",
                    "policy_id": "gcloud.projects.describe.v1",
                    "argv": ["gcloud", "projects", "describe", "demo-project", "--format=json", "--quiet"],
                    "status": "AVAILABLE",
                    "exit_code": 0,
                    "duration_ms": 1,
                }
            ],
        },
        evidence=[
            {
                "command_id": "project-description",
                "status": "AVAILABLE",
                "content_type": "application/json",
                "data": {"projectId": "demo-project"},
            }
        ],
    ).to_dict()


class FixtureContractTests(unittest.TestCase):
    def test_complete_matrix_executes_expected_statuses_and_verifies_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            catalog, _ = _make_catalog(Path(temp))
            package = load_catalog(catalog)[0]
            with patch("cchia_engine.collectors.executor.subprocess.run") as collector_process:
                results = validate_package_fixtures(package)

        collector_process.assert_not_called()
        self.assertEqual(3, len(results))
        self.assertEqual(
            {"positive": "FAIL", "negative": "PASS", "no_evidence": "NOT_ASSESSED"},
            {item["case"]: item["actual_status"] for item in results},
        )
        self.assertTrue(all(len(item["evidence_sha256"]) == 64 for item in results))
        self.assertTrue(all(item["expected_status"] == item["actual_status"] for item in results))

    def test_positive_partial_is_valid_but_no_evidence_must_be_not_assessed(self):
        with tempfile.TemporaryDirectory() as temp:
            catalog, package_path = _make_catalog(Path(temp), positive_status="PARTIAL")
            results = validate_catalog_fixtures(load_catalog(catalog))
            self.assertEqual("PARTIAL", results[0]["actual_status"])

            invalid = _fixture("no_evidence", "PARTIAL")
            _write_json(package_path / "fixtures" / "no_evidence.json", invalid)
            with self.assertRaises(ContractError) as raised:
                validate_catalog_fixtures(load_catalog(catalog))

        self.assertIn("check-fixture.schema.json", str(raised.exception))

    def test_fixture_name_case_and_control_id_are_cross_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            catalog, package_path = _make_catalog(Path(temp))
            positive_path = package_path / "fixtures" / "positive.json"
            wrong_case = _fixture("negative", "PASS")
            _write_json(positive_path, wrong_case)
            with self.assertRaises(ContractError) as case_error:
                validate_package_fixtures(load_catalog(catalog)[0])
            self.assertIn("case debe ser positive", str(case_error.exception))

            wrong_id = _fixture("positive", "FAIL")
            wrong_id["control_id"] = "CCHIA-API-999"
            _write_json(positive_path, wrong_id)
            with self.assertRaises(ContractError) as id_error:
                validate_package_fixtures(load_catalog(catalog)[0])

        self.assertIn("no coincide", str(id_error.exception))

    def test_actual_status_mismatch_and_tampered_result_hash_fail_the_gate(self):
        with tempfile.TemporaryDirectory() as temp:
            catalog, _ = _make_catalog(
                Path(temp), positive_status="PARTIAL", positive_expected="FAIL"
            )
            package = load_catalog(catalog)[0]
            with self.assertRaises(ContractError) as status_error:
                validate_package_fixtures(package)
            self.assertIn("esperado FAIL", str(status_error.exception))

        with tempfile.TemporaryDirectory() as temp:
            catalog, _ = _make_catalog(Path(temp))
            package = load_catalog(catalog)[0]
            with patch("cchia_engine.fixtures.canonical_hash", return_value="0" * 64):
                with self.assertRaises(ContractError) as hash_error:
                    validate_package_fixtures(package)
            self.assertIn("evidence_sha256 inválido", str(hash_error.exception))

    def test_embedded_collector_contract_and_canonical_hash_are_validated_without_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            catalog, package_path = _make_catalog(Path(temp))
            positive_path = package_path / "fixtures" / "positive.json"
            collector = _valid_collector()
            _write_json(positive_path, _fixture("positive", "FAIL", collectors=[collector]))
            package = load_catalog(catalog)[0]
            with patch("cchia_engine.collectors.executor.subprocess.run") as collector_process:
                results = validate_package_fixtures(package)
            collector_process.assert_not_called()
            self.assertEqual(3, len(results))

            collector["evidence"][0]["data"]["projectId"] = "tampered-project"
            _write_json(positive_path, _fixture("positive", "FAIL", collectors=[collector]))
            with patch("cchia_engine.fixtures.run_check") as check:
                with self.assertRaises(ContractError) as tampered:
                    validate_package_fixtures(package)
            check.assert_not_called()

        self.assertIn("Hash de evidencia inválido", str(tampered.exception))

    def test_scaffold_remains_catalog_loadable_but_cli_validate_requires_all_fixtures(self):
        with tempfile.TemporaryDirectory() as temp:
            catalog, _ = _make_catalog(Path(temp), cases=())
            self.assertEqual(1, len(load_catalog(catalog)))
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main(["--catalog", str(catalog), "validate"])
            self.assertEqual(1, status)
            self.assertIn("falta fixture obligatorio", stderr.getvalue())

    def test_cli_validate_reports_check_and_fixture_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            catalog, _ = _make_catalog(Path(temp))
            stdout = StringIO()
            stderr = StringIO()
            with (
                patch("cchia_engine.collectors.executor.subprocess.run") as collector_process,
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                status = main(["--catalog", str(catalog), "validate"])

        self.assertEqual(0, status, stderr.getvalue())
        self.assertIn("1 CCHIA Checks y 3 fixtures válidos", stdout.getvalue())
        collector_process.assert_not_called()


if __name__ == "__main__":
    unittest.main()
