"""Carga, valida y selecciona paquetes CCHIA Check."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from typing import Any

import yaml

from .models import (
    CONFIDENCES,
    EVIDENCE_LEVELS,
    SEVERITIES,
    STATUSES,
    CheckPackage,
    CheckSafetyError,
    ContractError,
)
from .utils import sha256_file


REQUIRED_FILES = ("control.yaml", "check.py", "expected.json", "mapping.yaml", "README.md")
CONTROL_ID = re.compile(r"^CCHIA-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3}$")
CONTROL_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
REQUIRED_FINDING_FIELDS = (
    "asset_or_process", "risk", "business_impact", "technical_impact",
    "regulatory_compliance_impact", "root_cause", "priority", "owner",
    "verification", "residual_risk",
)
FORBIDDEN_NAMES = {
    "open", "exec", "eval", "compile", "__import__", "input", "breakpoint",
    "globals", "locals", "vars", "getattr", "setattr", "delattr", "memoryview",
}
FORBIDDEN_ATTRIBUTES = {
    "write", "writelines", "write_text", "write_bytes", "unlink", "remove", "rmdir",
    "removedirs", "rename", "renames", "replace", "mkdir", "makedirs", "touch", "chmod",
    "chown", "system", "popen", "spawn", "connect", "send", "sendall", "request", "urlopen",
}


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError(f"{path}: se esperaba un objeto YAML")
    return value


def validate_check_source(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        raise CheckSafetyError(f"{path}: sintaxis inválida: {exc}") from exc

    evaluate_functions = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "evaluate"
    ]
    if len(evaluate_functions) != 1:
        raise CheckSafetyError(f"{path}: debe definir exactamente una función evaluate(context)")
    if len(evaluate_functions[0].args.args) != 1:
        raise CheckSafetyError(f"{path}: evaluate debe recibir solo el argumento context")

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            raise CheckSafetyError(f"{path}:{node.lineno}: imports no permitidos en checks puros")
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            raise CheckSafetyError(f"{path}:{node.lineno}: estado global/no local no permitido")
        if isinstance(node, ast.Name) and (node.id in FORBIDDEN_NAMES or node.id.startswith("__")):
            raise CheckSafetyError(f"{path}:{node.lineno}: nombre no permitido: {node.id}")
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__") or node.attr in FORBIDDEN_ATTRIBUTES:
                raise CheckSafetyError(f"{path}:{node.lineno}: atributo no permitido: {node.attr}")


def _require(mapping: dict[str, Any], keys: tuple[str, ...], location: Path) -> None:
    missing = [key for key in keys if key not in mapping]
    if missing:
        raise ContractError(f"{location}: faltan campos: {', '.join(missing)}")


def load_check(path: Path) -> CheckPackage:
    for name in REQUIRED_FILES:
        if not (path / name).is_file():
            raise ContractError(f"{path}: falta {name}")

    control = _load_yaml(path / "control.yaml")
    expected = json.loads((path / "expected.json").read_text(encoding="utf-8"))
    mapping = _load_yaml(path / "mapping.yaml")
    if not isinstance(expected, dict):
        raise ContractError(f"{path / 'expected.json'}: se esperaba un objeto JSON")

    _require(
        control,
        ("schema_version", "version", "id", "title", "domain", "objective", "severity", "evidence", "applicability", "execution", "finding"),
        path / "control.yaml",
    )
    control_id = str(control["id"])
    if not CONTROL_ID.fullmatch(control_id):
        raise ContractError(f"{path}: id inválido: {control_id}")
    if path.name != control_id:
        raise ContractError(f"{path}: la carpeta debe llamarse {control_id}")
    if not CONTROL_VERSION.fullmatch(str(control["version"])):
        raise ContractError(f"{path}: version debe usar SemVer X.Y.Z")
    if str(control["domain"]).upper() != path.parent.name.upper():
        raise ContractError(f"{path}: domain debe coincidir con la carpeta padre")
    if str(control["severity"]).upper() not in SEVERITIES:
        raise ContractError(f"{path}: severity inválida")
    evidence = control["evidence"]
    if not isinstance(evidence, dict) or str(evidence.get("minimum_level", "")) not in EVIDENCE_LEVELS:
        raise ContractError(f"{path}: evidence.minimum_level debe ser E0..E5")
    execution = control["execution"]
    if not isinstance(execution, dict) or execution.get("mode") != "read_only":
        raise ContractError(f"{path}: execution.mode debe ser read_only")
    timeout = execution.get("timeout_seconds")
    if not isinstance(timeout, int) or not 1 <= timeout <= 60:
        raise ContractError(f"{path}: timeout_seconds debe estar entre 1 y 60")
    if not isinstance(control["finding"], dict):
        raise ContractError(f"{path}: finding debe ser un objeto")
    _require(control["finding"], REQUIRED_FINDING_FIELDS, path / "control.yaml")

    _require(expected, ("schema_version", "allowed_statuses", "required_fields"), path / "expected.json")
    unknown_statuses = set(expected["allowed_statuses"]) - STATUSES
    if unknown_statuses:
        raise ContractError(f"{path}: estados desconocidos: {sorted(unknown_statuses)}")
    _require(mapping, ("schema_version", "control_id", "frameworks", "sources"), path / "mapping.yaml")
    if mapping["control_id"] != control_id:
        raise ContractError(f"{path}: mapping.control_id no coincide")
    if not isinstance(mapping["frameworks"], dict) or not isinstance(mapping["sources"], list):
        raise ContractError(f"{path}: frameworks debe ser objeto y sources debe ser lista")
    for index, source in enumerate(mapping["sources"]):
        if not isinstance(source, dict):
            raise ContractError(f"{path}: sources[{index}] debe ser objeto")
        _require(source, ("title", "url", "verified"), path / "mapping.yaml")

    validate_check_source(path / "check.py")
    return CheckPackage(path, control, expected, mapping, sha256_file(path / "check.py"))


def load_catalog(root: Path) -> list[CheckPackage]:
    if not root.is_dir():
        raise ContractError(f"No existe el catálogo: {root}")
    packages = [load_check(path.parent) for path in sorted(root.rglob("control.yaml"))]
    if not packages:
        raise ContractError(f"No se encontraron controles en {root}")
    seen: set[str] = set()
    for package in packages:
        if package.control_id in seen:
            raise ContractError(f"Control duplicado: {package.control_id}")
        seen.add(package.control_id)
    return packages


def applicability(package: CheckPackage, signals: set[str]) -> tuple[bool, list[str]]:
    rule = package.control.get("applicability", {})
    if rule.get("always") is True:
        return True, ["control marcado como universal"]
    all_of = {str(item).lower() for item in rule.get("all_of", [])}
    any_of = {str(item).lower() for item in rule.get("any_of", [])}
    none_of = {str(item).lower() for item in rule.get("none_of", [])}
    missing = sorted(all_of - signals)
    matched_any = sorted(any_of & signals)
    blocked = sorted(none_of & signals)
    applies = not missing and not blocked and (not any_of or bool(matched_any))
    reasons: list[str] = []
    if all_of:
        reasons.append("all_of=" + ",".join(sorted(all_of & signals)))
    if matched_any:
        reasons.append("any_of=" + ",".join(matched_any))
    if missing:
        reasons.append("faltan=" + ",".join(missing))
    if blocked:
        reasons.append("excluido_por=" + ",".join(blocked))
    return applies, reasons
