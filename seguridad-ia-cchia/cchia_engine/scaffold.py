"""Genera un paquete de control completo; nunca un script aislado."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml


ID_PATTERN = re.compile(r"^CCHIA-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3}$")


def scaffold_check(catalog: Path, control_id: str, domain: str, title: str) -> Path:
    control_id = control_id.upper()
    domain = domain.upper()
    if not ID_PATTERN.fullmatch(control_id):
        raise ValueError("El ID debe seguir CCHIA-DOMINIO-001")
    destination = catalog / domain / control_id
    if destination.exists():
        raise FileExistsError(f"Ya existe {destination}")
    destination.mkdir(parents=True)
    control = {
        "schema_version": "1.0",
        "version": "1.0.0",
        "id": control_id,
        "title": title,
        "domain": domain,
        "objective": "Definir el resultado de seguridad verificable.",
        "severity": "MEDIUM",
        "evidence": {"minimum_level": "E3", "retention": "assessment"},
        "applicability": {"any_of": ["repository"]},
        "execution": {"mode": "read_only", "timeout_seconds": 10},
        "finding": {
            "asset_or_process": "Sistema evaluado",
            "risk": "Describir el escenario de riesgo.",
            "business_impact": "Describir el impacto de negocio.",
            "technical_impact": "Describir el impacto técnico.",
            "regulatory_compliance_impact": "No determinado.",
            "root_cause": "Control no implementado o no demostrado.",
            "priority": "90 days",
            "owner": "Security Owner",
            "verification": f"Volver a ejecutar {control_id}.",
            "residual_risk": "Reevaluar después de remediar.",
        },
    }
    (destination / "control.yaml").write_text(yaml.safe_dump(control, allow_unicode=True, sort_keys=False), encoding="utf-8")
    expected = {
        "schema_version": "1.0",
        "allowed_statuses": ["PASS", "FAIL", "PARTIAL", "NOT_ASSESSED"],
        "required_fields": ["status", "confidence", "evidence_level", "summary", "evidence", "recommendation"],
    }
    (destination / "expected.json").write_text(json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    mapping = {"schema_version": "1.0", "control_id": control_id, "frameworks": {"nist": [], "iso": [], "cchia": [{"id": control_id, "rationale": "Control nativo CCHIA."}]}, "sources": []}
    (destination / "mapping.yaml").write_text(yaml.safe_dump(mapping, allow_unicode=True, sort_keys=False), encoding="utf-8")
    (destination / "check.py").write_text(
        '"""Check puro: sin imports, red, subprocess ni acceso al filesystem."""\n\n'
        "def evaluate(context):\n"
        "    return {\n"
        "        \"status\": \"NOT_ASSESSED\",\n"
        "        \"confidence\": \"LOW\",\n"
        "        \"evidence_level\": \"E0\",\n"
        "        \"summary\": \"Implementar la lógica determinista del control.\",\n"
        "        \"evidence\": [],\n"
        "        \"recommendation\": \"Completar el check y sus pruebas.\",\n"
        "    }\n",
        encoding="utf-8",
    )
    (destination / "README.md").write_text(
        f"# {control_id} — {title}\n\nObjetivo, alcance, evidencia esperada, falsos positivos y procedimiento de verificación.\n",
        encoding="utf-8",
    )
    return destination
