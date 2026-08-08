"""Informes CCHIA, NIST e ISO derivados de la misma evidencia JSON."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


STATUS_SCORE = {"PASS": 100, "PARTIAL": 50, "FAIL": 0}
SEVERITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFORMATIONAL": 1}


def _score(results: list[dict[str, Any]]) -> dict[str, Any]:
    domains: dict[str, list[tuple[int, int]]] = defaultdict(list)
    for result in results:
        status = result["evaluation"]["status"]
        if status not in STATUS_SCORE:
            continue
        weight = SEVERITY_WEIGHT[result["severity"]]
        domains[result["domain"]].append((STATUS_SCORE[status], weight))
    domain_scores: dict[str, int | None] = {}
    combined: list[tuple[int, int]] = []
    for domain, values in sorted(domains.items()):
        total_weight = sum(weight for _, weight in values)
        domain_scores[domain] = round(sum(score * weight for score, weight in values) / total_weight)
        combined.extend(values)
    overall = None
    if combined:
        total_weight = sum(weight for _, weight in combined)
        overall = round(sum(score * weight for score, weight in combined) / total_weight)
    return {"overall": overall, "domains": domain_scores, "note": "Indicador interno; no es certificación."}


def _finding(result: dict[str, Any]) -> dict[str, Any] | None:
    evaluation = result["evaluation"]
    if evaluation["status"] == "PASS":
        return None
    template = result["finding_template"]
    return {
        "id": result["control_id"],
        "control_version": result["control_version"],
        "title": result["title"],
        "status": evaluation["status"],
        "severity": result["severity"],
        "confidence": evaluation["confidence"],
        "asset_or_process": template.get("asset_or_process", "Sistema evaluado"),
        "evidence": evaluation["evidence"],
        "observation": evaluation["summary"],
        "risk": template.get("risk", "Riesgo no especificado"),
        "business_impact": template.get("business_impact", "Requiere análisis contextual"),
        "technical_impact": template.get("technical_impact", "Requiere análisis contextual"),
        "regulatory_compliance_impact": template.get("regulatory_compliance_impact", "No determinado"),
        "framework_mapping": result["mapping"],
        "root_cause": template.get("root_cause", "No determinada"),
        "recommendation": evaluation["recommendation"],
        "priority": template.get("priority", "90 days"),
        "owner": template.get("owner", "Security Owner"),
        "verification": template.get("verification", "Volver a ejecutar el control"),
        "residual_risk": template.get("residual_risk", "Debe reevaluarse tras remediar"),
    }


def build_assessment(
    plan: dict[str, Any],
    results: list[dict[str, Any]],
    integrity: dict[str, Any],
    collector_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    counts = Counter(result["evaluation"]["status"] for result in results)
    findings = [finding for result in results if (finding := _finding(result)) is not None]
    collectors = collector_evidence or []
    limitations = [
        "La evaluación cubre solo los artefactos y la descripción suministrados.",
        "PASS significa que el patrón evaluado no se observó; no demuestra seguridad total ni conformidad.",
        "Los mappings son referencias justificadas, no una declaración de certificación ISO/NIST/CCHIA.",
        "Los controles técnicos no sustituyen revisión legal ni auditoría independiente cuando corresponda.",
    ]
    collection = plan["scope"].get("collection", {})
    if collection.get("complete") is False:
        reasons = ", ".join(collection.get("incomplete_reasons", [])) or "causa no especificada"
        limitations.append(
            f"La recolección está incompleta ({reasons}); los PASS afectados se degradaron a NOT_ASSESSED."
        )
    for collector in collectors:
        if collector.get("status") != "AVAILABLE":
            limitations.append(
                f"Collector {collector.get('collector_id', 'desconocido')} terminó "
                f"{collector.get('status', 'UNKNOWN')}; su estado runtime no quedó demostrado."
            )
        for item in collector.get("limitations", []):
            limitation = f"Collector {collector.get('collector_id', 'desconocido')}: {item}"
            if limitation not in limitations:
                limitations.append(limitation)
    return {
        "schema_version": "1.0",
        "assessment_id": plan["assessment_id"],
        "generated_at": plan["generated_at"],
        "scope": plan["scope"],
        "applicability": plan["applicability"],
        "summary": {"statuses": dict(sorted(counts.items())), "score": _score(results)},
        "results": results,
        "collector_evidence": collectors,
        "findings": findings,
        "target_integrity": integrity,
        "limitations": limitations,
    }


def _header(title: str, assessment: dict[str, Any]) -> list[str]:
    score = assessment["summary"]["score"]
    return [
        f"# {title}", "",
        f"- Assessment ID: `{assessment['assessment_id']}`",
        f"- Fecha de corte: `{assessment['generated_at']}`",
        f"- Target: `{assessment['scope']['target']}`",
        f"- Score interno: `{score['overall'] if score['overall'] is not None else 'N/A'}` / 100",
        "- Declaración: este resultado no es certificación ni prueba de seguridad total.", "",
    ]


def render_cchia(assessment: dict[str, Any]) -> str:
    lines = _header("CCHIA Security Assessment", assessment)
    statuses = assessment["summary"]["statuses"]
    lines += ["## 1. Executive Summary", "", "Resultados: " + ", ".join(f"{k}={v}" for k, v in statuses.items()) + ".", ""]
    collection = assessment["scope"].get("collection", {})
    coverage = "completa" if collection.get("complete") is True else "incompleta"
    lines += [
        "## 2. Scope", "",
        f"Se analizaron {assessment['scope']['file_count']} archivos en modo read-only; cobertura {coverage}.", "",
    ]
    if assessment.get("collector_evidence"):
        lines += ["### Runtime collectors", ""]
        for collector in assessment["collector_evidence"]:
            lines.append(
                f"- `{collector['collector_id']}`: {collector['status']} "
                f"(modo `{collector['mode']}`, evidencia `{collector['evidence_sha256']}`)"
            )
        lines.append("")
    lines += ["## 3. Applicability", ""]
    for item in assessment["applicability"]:
        lines.append(
            f"- `{item['control_id']}@{item['control_version']}`: {item['decision']} "
            f"({'; '.join(item['reasons']) or 'sin razón adicional'})"
        )
    lines += ["", "## 4. Domain Scores", "", "| Dominio | Score |", "|---|---:|"]
    for domain, score in assessment["summary"]["score"]["domains"].items():
        lines.append(f"| {domain} | {score} |")
    lines += ["", "## 5. Findings", ""]
    if not assessment["findings"]:
        lines.append("No se generaron findings; esto no elimina las limitaciones del alcance.")
    for finding in assessment["findings"]:
        lines += [
            f"### {finding['id']}@{finding['control_version']} — {finding['title']}", "",
            f"**Status:** {finding['status']} | **Severity:** {finding['severity']} | **Confidence:** {finding['confidence']}", "",
            f"**Observation:** {finding['observation']}", "",
            f"**Risk:** {finding['risk']}", "",
            f"**Business impact:** {finding['business_impact']}", "",
            f"**Technical impact:** {finding['technical_impact']}", "",
            f"**Recommendation:** {finding['recommendation']}", "",
            f"**Owner / priority:** {finding['owner']} / {finding['priority']}", "",
            f"**Verification:** {finding['verification']}", "",
        ]
        if finding["evidence"]:
            lines.append("**Evidence:**")
            lines.append("")
            for evidence in finding["evidence"]:
                lines.append("- `" + str(evidence).replace("`", "'") + "`")
            lines.append("")
    lines += [
        "## 6. Evidence and integrity", "",
        "Ventana de archivos de texto soportados y recolectados sin cambios fuera del directorio de salida: "
        f"`{assessment['target_integrity']['unchanged']}`.", "",
    ]
    lines += ["## 7. Limitations", ""] + [f"- {item}" for item in assessment["limitations"]] + [""]
    return "\n".join(lines)


def _render_framework(assessment: dict[str, Any], family: str, title: str) -> str:
    lines = _header(title, assessment)
    lines += ["## Control crosswalk", "", "| CCHIA Check | Status | Mapping | Rationale |", "|---|---|---|---|"]
    for result in assessment["results"]:
        mappings = result["mapping"].get(family, [])
        if not mappings:
            mapping_text = "No direct mapping identified"
            rationale = "No se fuerza equivalencia."
        else:
            mapping_text = ", ".join(str(item.get("id", item)) if isinstance(item, dict) else str(item) for item in mappings)
            rationale = "; ".join(str(item.get("rationale", "")) for item in mappings if isinstance(item, dict))
        lines.append(
            f"| {result['control_id']}@{result['control_version']} | "
            f"{result['evaluation']['status']} | {mapping_text} | {rationale} |"
        )
    lines += ["", "## Interpretation", "", "Este crosswalk muestra alineación conceptual o directa declarada por cada paquete. No demuestra conformidad con el framework.", ""]
    return "\n".join(lines)


def render_reports(assessment: dict[str, Any]) -> dict[str, str]:
    return {
        "report-cchia.md": render_cchia(assessment),
        "report-nist.md": _render_framework(assessment, "nist", "CCHIA to NIST Evidence Report"),
        "report-iso.md": _render_framework(assessment, "iso", "CCHIA to ISO/IEC Evidence Report"),
    }
