"""Tercer layer: selección, plan, ejecución, evidencia e informes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .catalog import applicability, load_catalog
from .collectors import collect_requested, verify_collector_evidence_hash
from .context import build_context, load_system, snapshot_target
from .contracts import validate_contract
from .models import ENGINE_VERSION
from .reporting import build_assessment, render_reports
from .runtime_context import enrich_context_with_collectors
from .runner import run_checks
from .utils import canonical_hash, sha256_file, utc_now, write_json


def _tree_fingerprint(root: Path, pattern: str = "*.py") -> str:
    payload = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in sorted(root.rglob(pattern))
        if path.is_file() and "__pycache__" not in path.parts
    }
    return canonical_hash(payload)


def _catalog_fingerprint(packages: list[Any]) -> str:
    payload: dict[str, dict[str, str]] = {}
    for package in packages:
        payload[package.control_id] = {
            path.relative_to(package.path).as_posix(): sha256_file(path)
            for path in sorted(package.path.rglob("*"))
            if path.is_file() and "__pycache__" not in path.parts
        }
    return canonical_hash(payload)


def _artifact_manifest(output: Path, assessment_id: str) -> dict[str, Any]:
    artifacts = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "manifest.json":
            artifacts.append({"path": path.relative_to(output).as_posix(), "sha256": sha256_file(path)})
    manifest = {"schema_version": "1.0", "assessment_id": assessment_id, "artifacts": artifacts}
    manifest["manifest_payload_sha256"] = canonical_hash(manifest)
    return manifest


def compile_assessment(
    *,
    target: Path | None,
    catalog_root: Path,
    output: Path,
    system_path: Path | None = None,
    forced_controls: list[str] | None = None,
    plan_only: bool = False,
    collector_names: list[str] | None = None,
    collector_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if target is None:
        if system_path is None:
            raise ValueError("Se requiere --target, --system o ambos")
        target = system_path
    target = target.resolve()
    if not target.exists():
        raise FileNotFoundError(f"No existe el target: {target}")
    output = output.resolve()
    catalog_root = catalog_root.resolve()
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(
            f"El directorio de salida no está vacío: {output}. Use una ruta nueva para no mezclar evidencia."
        )
    system = load_system(system_path.resolve() if system_path else None)
    excluded = [output] if output == target or output.is_relative_to(target) else []
    before = snapshot_target(target, excluded)
    context = build_context(target, system, excluded)
    requested_collectors = list(dict.fromkeys(collector_names or []))
    collector_results: list[dict[str, Any]] = []
    if requested_collectors:
        request: dict[str, Any] = {"collectors": requested_collectors}
        normalized_options = {
            key: value for key, value in (collector_options or {}).items() if value is not None
        }
        if normalized_options:
            request["options"] = normalized_options
        validate_contract("collector-request.schema.json", request)
        collector_results = collect_requested(
            requested_collectors,
            target=target,
            options=normalized_options,
        )
        for collector_result in collector_results:
            validate_contract("collector-result.schema.json", collector_result)
            verify_collector_evidence_hash(collector_result)
    # Los evaluadores consumen evidencia runtime redacted sin acoplarse al SDK.
    # La presencia del collector selecciona controles fail-closed; solo un
    # resultado AVAILABLE válido activa señales runtime/provider.
    if collector_results:
        context = enrich_context_with_collectors(context, collector_results)
    else:
        context["collectors"] = []
    packages = load_catalog(catalog_root)
    engine_fingerprint = _tree_fingerprint(Path(__file__).resolve().parent)
    catalog_fingerprint = _catalog_fingerprint(packages)
    signals = set(context["signals"])
    forced = set(forced_controls or [])
    unknown = forced - {package.control_id for package in packages}
    if unknown:
        raise ValueError("Controles solicitados inexistentes: " + ", ".join(sorted(unknown)))

    selected = []
    decisions = []
    for package in packages:
        applies, reasons = applicability(package, signals)
        if forced:
            applies = package.control_id in forced
            reasons = ["selección explícita"] if applies else ["no incluido en selección explícita"]
        decisions.append({
            "control_id": package.control_id,
            "control_version": package.control_version,
            "decision": "SELECTED" if applies else "NOT_APPLICABLE",
            "reasons": reasons,
        })
        if applies:
            selected.append(package)

    generated_at = utc_now()
    seed = {"target": str(target), "fingerprint": context["target"]["fingerprint"], "generated_at": generated_at}
    assessment_id = "CCHIA-" + canonical_hash(seed)[:12].upper()
    plan = {
        "schema_version": "1.0",
        "assessment_id": assessment_id,
        "generated_at": generated_at,
        "scope": {
            "target": str(target),
            "system_description": str(system_path.resolve()) if system_path else None,
            "target_fingerprint": context["target"]["fingerprint"],
            "file_count": context["collection"]["file_count"],
            "signals": context["signals"],
            "signal_evidence": context["signal_evidence"],
            "signal_details": context["signal_details"],
            "collection": context["collection"],
            "collectors": [
                {
                    "collector_id": item["collector_id"],
                    "collector_version": item["collector_version"],
                    "status": item["status"],
                    "collected_at": item["collected_at"],
                    "mode": item["mode"],
                    "evidence_sha256": item["evidence_sha256"],
                }
                for item in collector_results
            ],
            "execution_mode": "read_only",
        },
        "engine": {"version": ENGINE_VERSION, "sha256": engine_fingerprint},
        "catalog": {
            "root": str(catalog_root),
            "control_count": len(packages),
            "fixture_count": sum(
                1
                for package in packages
                for path in (package.path / "fixtures").glob("*.json")
                if path.is_file()
            ),
            "sha256": catalog_fingerprint,
        },
        "applicability": decisions,
        "selected_controls": [package.control_id for package in selected],
        "selected_control_versions": {
            package.control_id: package.control_version for package in selected
        },
    }
    validate_contract("plan.schema.json", plan)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "plan.json", plan)
    context_export = dict(context)
    context_export["files"] = [
        {key: value for key, value in item.items() if key != "content"} for item in context["files"]
    ]
    context_export["collectors"] = plan["scope"]["collectors"]
    write_json(output / "context.json", context_export)
    collector_dir = output / "collector-evidence"
    for collector_result in collector_results:
        write_json(collector_dir / f"{collector_result['collector_id']}.json", collector_result)
    if plan_only:
        write_json(output / "manifest.json", _artifact_manifest(output, assessment_id))
        return {"plan": plan, "output": str(output), "plan_only": True}

    results = run_checks(
        selected,
        context,
        {"engine_version": ENGINE_VERSION, "engine_sha256": engine_fingerprint, "catalog_sha256": catalog_fingerprint},
    )
    evidence_dir = output / "evidence"
    for result in results:
        validate_contract("evidence.schema.json", result)
        write_json(evidence_dir / f"{result['control_id']}.json", result)
    after = snapshot_target(target, excluded)
    integrity = {
        "mode": "pre_post_sha256",
        "scope": "collected_supported_text_window",
        "unchanged": before == after,
        "before_sha256": canonical_hash(before),
        "after_sha256": canonical_hash(after),
        "before_file_count": len(before),
        "after_file_count": len(after),
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "modified": sorted(path for path in set(before) & set(after) if before[path] != after[path]),
        "excluded_output": str(output) if excluded else None,
    }
    assessment = build_assessment(plan, results, integrity, collector_results)
    validate_contract("assessment.schema.json", assessment)
    write_json(output / "assessment.json", assessment)
    for name, content in render_reports(assessment).items():
        (output / name).write_text(content + "\n", encoding="utf-8")
    write_json(output / "manifest.json", _artifact_manifest(output, assessment_id))
    return {
        "plan": plan,
        "assessment": assessment,
        "output": str(output),
        "artifacts": sorted(path.name for path in output.iterdir()),
    }
