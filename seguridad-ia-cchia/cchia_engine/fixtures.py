"""Fixture-matrix quality gate for versioned CCHIA Check packages."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .collectors import verify_collector_evidence_hash
from .contracts import validate_contract
from .models import CheckPackage, ContractError
from .runner import run_check
from .utils import canonical_hash


FIXTURE_CASES: tuple[tuple[str, str], ...] = (
    ("positive", "positive.json"),
    ("negative", "negative.json"),
    ("no_evidence", "no_evidence.json"),
)
_CASE_STATUSES = {
    "positive": {"FAIL", "PARTIAL"},
    "negative": {"PASS"},
    "no_evidence": {"NOT_ASSESSED"},
}


def _load_fixture(package: CheckPackage, case: str, filename: str) -> tuple[Path, dict[str, Any]]:
    path = package.path / "fixtures" / filename
    if not path.is_file():
        raise ContractError(f"{package.control_id}: falta fixture obligatorio fixtures/{filename}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{path}: JSON de fixture inválido: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{path}: se esperaba un objeto JSON")
    validate_contract("check-fixture.schema.json", value)
    if value["control_id"] != package.control_id:
        raise ContractError(
            f"{path}: control_id {value['control_id']} no coincide con {package.control_id}"
        )
    if value["case"] != case or path.stem != case:
        raise ContractError(
            f"{path}: case debe ser {case} y coincidir con el nombre {case}.json"
        )
    expected_status = str(value["expected_status"])
    if expected_status not in _CASE_STATUSES[case]:
        allowed = ", ".join(sorted(_CASE_STATUSES[case]))
        raise ContractError(f"{path}: expected_status debe ser {allowed} para case={case}")
    if expected_status not in package.expected["allowed_statuses"]:
        raise ContractError(
            f"{path}: expected_status={expected_status} no está permitido por expected.json"
        )
    return path, value


def _verify_result_hash(path: Path, result: dict[str, Any]) -> str:
    evidence_hash = result.get("evidence_sha256")
    if not isinstance(evidence_hash, str):
        raise ContractError(f"{path}: run_check no emitió evidence_sha256")
    payload = dict(result)
    payload.pop("evidence_sha256", None)
    calculated = canonical_hash(payload)
    if evidence_hash != calculated:
        raise ContractError(
            f"{path}: evidence_sha256 inválido; esperado {calculated}, recibido {evidence_hash}"
        )
    return evidence_hash


def _validate_context_collectors(path: Path, context: dict[str, Any]) -> None:
    collectors = context.get("collectors", [])
    if not isinstance(collectors, list):
        raise ContractError(f"{path}: context.collectors debe ser una lista")
    for index, collector in enumerate(collectors):
        if not isinstance(collector, dict):
            raise ContractError(f"{path}: context.collectors[{index}] debe ser un objeto")
        validate_contract("collector-result.schema.json", collector)
        try:
            verify_collector_evidence_hash(collector)
        except ValueError as exc:
            raise ContractError(f"{path}: context.collectors[{index}]: {exc}") from exc


def validate_package_fixtures(package: CheckPackage) -> list[dict[str, Any]]:
    """Load, contract-check and execute the three canonical package fixtures."""

    validated: list[dict[str, Any]] = []
    for case, filename in FIXTURE_CASES:
        path, fixture = _load_fixture(package, case, filename)
        _validate_context_collectors(path, fixture["context"])
        # run_check executes only the pure package check. Fixture validation does
        # not discover or invoke cloud/Kubernetes collectors.
        result = run_check(package, fixture["context"])
        validate_contract("evidence.schema.json", result)
        evidence_hash = _verify_result_hash(path, result)
        actual_status = str(result["evaluation"]["status"])
        expected_status = str(fixture["expected_status"])
        if actual_status != expected_status:
            raise ContractError(
                f"{path}: esperado {expected_status}, run_check obtuvo {actual_status}"
            )
        validated.append(
            {
                "control_id": package.control_id,
                "case": case,
                "path": str(path),
                "expected_status": expected_status,
                "actual_status": actual_status,
                "evidence_sha256": evidence_hash,
            }
        )
    return validated


def validate_catalog_fixtures(packages: Iterable[CheckPackage]) -> list[dict[str, Any]]:
    """Require and execute a complete three-case matrix for every package."""

    validated: list[dict[str, Any]] = []
    for package in packages:
        validated.extend(validate_package_fixtures(package))
    return validated


__all__ = ["FIXTURE_CASES", "validate_catalog_fixtures", "validate_package_fixtures"]
