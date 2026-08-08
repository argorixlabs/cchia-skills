"""Ejecución determinista y con timeout de CCHIA Checks."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any

from .context import safeguard_pass_for_collection
from .models import CONFIDENCES, EVIDENCE_LEVELS, STATUSES, CheckPackage
from .sandbox import (
    SandboxLimits,
    initial_sandbox_report,
    minimal_worker_environment,
    run_worker_process,
)
from .utils import canonical_hash, utc_now, write_json


def _validate_evaluation(package: CheckPackage, value: dict[str, Any]) -> None:
    required = set(package.expected["required_fields"])
    missing = sorted(required - set(value))
    if missing:
        raise ValueError("faltan campos de resultado: " + ", ".join(missing))
    status = str(value.get("status", "")).upper()
    if status not in package.expected["allowed_statuses"] or status not in STATUSES:
        raise ValueError(f"status no permitido: {status}")
    if str(value.get("confidence", "")).upper() not in CONFIDENCES:
        raise ValueError("confidence debe ser HIGH, MEDIUM o LOW")
    if str(value.get("evidence_level", "")) not in EVIDENCE_LEVELS:
        raise ValueError("evidence_level debe ser E0..E5")
    if not isinstance(value.get("evidence"), list):
        raise ValueError("evidence debe ser una lista")


def run_check(package: CheckPackage, context: dict[str, Any], runtime: dict[str, Any] | None = None) -> dict[str, Any]:
    timeout = int(package.control["execution"]["timeout_seconds"])
    limits = SandboxLimits.from_execution(package.control["execution"], timeout)
    worker = Path(__file__).with_name("worker.py")
    started = utc_now()
    evaluation: dict[str, Any]
    error: str | None = None
    sandbox_report: dict[str, Any] | None = None
    with tempfile.TemporaryDirectory(prefix="cchia-check-") as temp_dir:
        temp_path = Path(temp_dir).resolve()
        context_path = temp_path / "context.json"
        write_json(context_path, context)
        environment, inherited_names = minimal_worker_environment(temp_path)
        sandbox_report = initial_sandbox_report(limits, inherited_names)
        try:
            completed = run_worker_process(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-X",
                    "utf8",
                    str(worker),
                    str((package.path / "check.py").resolve()),
                    str(context_path),
                ],
                cwd=temp_path,
                environment=environment,
                inherited_environment_names=inherited_names,
                timeout_seconds=timeout,
                limits=limits,
            )
            sandbox_report = completed.report
            sandbox_report["outcome"] = {
                "returncode": completed.returncode,
                "timed_out": completed.timed_out,
                "output_limit_exceeded": completed.output_limit_exceeded,
            }
            if completed.timed_out:
                raise TimeoutError(f"worker excedió {timeout}s y se intentó terminar su árbol")
            if completed.output_limit_exceeded:
                raise ValueError(
                    f"output del worker excedió {limits.max_output_bytes} bytes y fue rechazado"
                )
            payload = json.loads(completed.stdout.strip() or "{}")
            if completed.returncode != 0:
                raise RuntimeError(payload.get("error") or completed.stderr.strip() or "worker falló")
            _validate_evaluation(package, payload)
            evaluation = safeguard_pass_for_collection(payload, context)
            _validate_evaluation(package, evaluation)
        except Exception as exc:  # Boundary: un check roto no aborta el assessment completo.
            error = f"{type(exc).__name__}: {exc}"
            if sandbox_report is not None:
                sandbox_report.setdefault("fallbacks", []).append(
                    f"Ejecución no completada: {type(exc).__name__}: {exc}"
                )
                sandbox_report.setdefault(
                    "outcome",
                    {"returncode": None, "timed_out": False, "output_limit_exceeded": False},
                )
            evaluation = {
                "status": "ERROR",
                "confidence": "LOW",
                "evidence_level": "E0",
                "summary": "El check no pudo completar una evaluación válida.",
                "evidence": [],
                "recommendation": "Corregir el paquete o el contexto y volver a ejecutar.",
            }

    result = {
        "schema_version": "1.0",
        "control_id": package.control_id,
        "control_version": package.control_version,
        "domain": package.domain,
        "title": package.control["title"],
        "severity": str(package.control["severity"]).upper(),
        "started_at": started,
        "completed_at": utc_now(),
        "execution": {
            "mode": "read_only",
            "isolation": "layered-best-effort",
            "timeout_seconds": timeout,
            "check_sha256": package.source_hash,
            **(runtime or {}),
            "sandbox": sandbox_report,
        },
        "evaluation": evaluation,
        "mapping": package.mapping["frameworks"],
        "mapping_sources": package.mapping["sources"],
        "finding_template": package.control["finding"],
    }
    if error:
        result["execution"]["error"] = error
    result["evidence_sha256"] = canonical_hash(result)
    return result


def run_checks(
    packages: list[CheckPackage], context: dict[str, Any], runtime: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    return [run_check(package, context, runtime) for package in packages]
