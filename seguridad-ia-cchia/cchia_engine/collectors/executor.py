"""Safe subprocess boundary for opt-in command collectors."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from ..utils import canonical_hash, sha256_bytes, utc_now
from .base import CollectorResult, CommandSpec
from .policy import validate_command
from .redaction import redact, redact_text


MAX_COLLECTOR_STDOUT_BYTES = 4 * 1024 * 1024


def _decode_json_or_text(stdout: object) -> tuple[str, Any]:
    if isinstance(stdout, bytes):
        raw_text = stdout.decode("utf-8", errors="replace")
    elif stdout is None:
        raw_text = ""
    else:
        raw_text = str(stdout)
    if not raw_text.strip():
        return "application/json", None
    try:
        return "application/json", redact(json.loads(raw_text))
    except (json.JSONDecodeError, TypeError):
        return "text/plain", redact_text(raw_text)


def _target_label(target: Path | str | None) -> str | None:
    if target is None:
        return None
    return str(Path(target).resolve())


def execute_command_collector(
    *,
    collector_id: str,
    collector_version: str,
    provider: str,
    sdk_name: str,
    tool: str,
    specs: list[CommandSpec],
    target: Path | str | None,
    timeout_seconds: int,
    limitations: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Validate the complete plan before discovering or launching a process."""

    for spec in specs:
        validate_command(spec)

    collected_at = utc_now()
    discovered_executable = shutil.which(tool)
    resolved_executable = (
        str(Path(discovered_executable).resolve()) if discovered_executable is not None else None
    )
    executable_available = resolved_executable is not None
    command_records: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    if not executable_available:
        for spec in specs:
            command_records.append(
                {
                    "command_id": spec.command_id,
                    "policy_id": spec.policy_id,
                    "argv": list(spec.argv),
                    "status": "UNAVAILABLE",
                    "exit_code": None,
                    "duration_ms": 0,
                }
            )
        return CollectorResult(
            collector_id=collector_id,
            collector_version=collector_version,
            status="UNAVAILABLE",
            collected_at=collected_at,
            provenance={
                "target": _target_label(target),
                "provider": provider,
                "interface": {
                    "kind": "command",
                    "tool": tool,
                    "sdk": sdk_name,
                    "sdk_version": None,
                    "executable_available": False,
                    "resolved_executable": None,
                },
                "commands": command_records,
            },
            evidence=[],
            limitations=(*limitations, f"No se encontró {tool} en PATH; no se ejecutó ningún comando."),
        ).to_dict()

    any_error = False
    # No se reemplaza env: los clientes conservan su configuración de
    # credenciales. El cwd neutral evita config o ejecutables relativos al target.
    with tempfile.TemporaryDirectory(prefix="cchia-collector-") as neutral_cwd:
        for spec in specs:
            started_at = utc_now()
            started = time.monotonic()
            record: dict[str, Any] = {
                "command_id": spec.command_id,
                "policy_id": spec.policy_id,
                "argv": list(spec.argv),
                "status": "ERROR",
                "started_at": started_at,
                "exit_code": None,
            }
            try:
                # argv lógico ya fue validado; solo se sustituye argv[0] por la
                # ruta absoluta resuelta una vez, sin nueva búsqueda vía PATH.
                execution_argv = [resolved_executable, *spec.argv[1:]]
                completed = subprocess.run(
                    execution_argv,
                    capture_output=True,
                    text=True,
                    shell=False,
                    check=False,
                    timeout=timeout_seconds,
                    encoding="utf-8",
                    errors="replace",
                    cwd=neutral_cwd,
                    stdin=subprocess.DEVNULL,
                )
                stdout = completed.stdout or ""
                stderr = completed.stderr or ""
                stdout_bytes = stdout.encode("utf-8", errors="replace")
                if len(stdout_bytes) > MAX_COLLECTOR_STDOUT_BYTES:
                    any_error = True
                    record.update(
                        {
                            "status": "ERROR",
                            "exit_code": completed.returncode,
                            "error_type": "OUTPUT_LIMIT",
                            "stdout_sha256": sha256_bytes(stdout_bytes),
                            "stderr": redact_text(stderr),
                        }
                    )
                    evidence.append(
                        {
                            "command_id": spec.command_id,
                            "status": "ERROR",
                            "content_type": "application/json",
                            "data": {
                                "output_limit_exceeded": True,
                                "observed_bytes": len(stdout_bytes),
                                "limit_bytes": MAX_COLLECTOR_STDOUT_BYTES,
                            },
                            "error": "Salida collector excedió el límite permitido; evidencia descartada",
                        }
                    )
                    continue
                content_type, payload = _decode_json_or_text(stdout)
                command_status = "AVAILABLE" if completed.returncode == 0 else "ERROR"
                any_error = any_error or command_status == "ERROR"
                record.update(
                    {
                        "status": command_status,
                        "exit_code": completed.returncode,
                        "stdout_sha256": canonical_hash({"redacted": payload}),
                        "stderr": redact_text(stderr),
                    }
                )
                evidence.append(
                    {
                        "command_id": spec.command_id,
                        "status": command_status,
                        "content_type": content_type,
                        "data": payload,
                    }
                )
            except subprocess.TimeoutExpired as exc:
                any_error = True
                stdout = getattr(exc, "stdout", "") or ""
                stderr = getattr(exc, "stderr", "") or ""
                content_type, payload = _decode_json_or_text(stdout)
                record.update(
                    {
                        "status": "ERROR",
                        "error_type": "TIMEOUT",
                        "stderr": redact_text(stderr),
                    }
                )
                evidence.append(
                    {
                        "command_id": spec.command_id,
                        "status": "ERROR",
                        "content_type": content_type,
                        "data": payload,
                        "error": f"Timeout read-only después de {timeout_seconds} segundos",
                    }
                )
            except OSError as exc:
                any_error = True
                record.update(
                    {
                        "status": "ERROR",
                        "error_type": type(exc).__name__,
                        "stderr": redact_text(exc),
                    }
                )
                evidence.append(
                    {
                        "command_id": spec.command_id,
                        "status": "ERROR",
                        "content_type": "application/json",
                        "data": None,
                        "error": redact_text(exc),
                    }
                )
            finally:
                record["duration_ms"] = max(0, round((time.monotonic() - started) * 1000))
                command_records.append(redact(record))

    return CollectorResult(
        collector_id=collector_id,
        collector_version=collector_version,
        status="ERROR" if any_error else "AVAILABLE",
        collected_at=collected_at,
        provenance={
            "target": _target_label(target),
            "provider": provider,
            "interface": {
                "kind": "command",
                "tool": tool,
                "sdk": sdk_name,
                "sdk_version": None,
                "executable_available": True,
                "resolved_executable": redact_text(resolved_executable),
            },
            "commands": command_records,
        },
        evidence=redact(evidence),
        limitations=limitations,
    ).to_dict()
