"""Serializable contracts shared by read-only runtime collectors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..utils import canonical_hash


COLLECTOR_SCHEMA_VERSION = "1.0"
COLLECTOR_STATUSES = {"AVAILABLE", "UNAVAILABLE", "ERROR"}
COLLECTOR_MODE = "read_only"


class CollectorValidationError(ValueError):
    """A collector request falls outside the explicit read-only contract."""


def verify_collector_evidence_hash(result: dict[str, Any]) -> None:
    """Reject collector evidence whose canonical payload does not match its digest."""

    expected = canonical_hash(
        {
            "collector_id": result.get("collector_id"),
            "collector_version": result.get("collector_version"),
            "evidence": result.get("evidence"),
        }
    )
    if result.get("evidence_sha256") != expected:
        raise CollectorValidationError(
            f"Hash de evidencia inválido para collector {result.get('collector_id', 'desconocido')}"
        )


@dataclass(frozen=True)
class CommandSpec:
    """One immutable command admitted by a named allow-list rule."""

    command_id: str
    policy_id: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class CollectorResult:
    """Canonical, JSON-serializable result returned by every collector."""

    collector_id: str
    collector_version: str
    status: str
    collected_at: str
    provenance: dict[str, Any]
    evidence: list[dict[str, Any]]
    limitations: tuple[str, ...] = ()
    mode: str = COLLECTOR_MODE
    schema_version: str = COLLECTOR_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.status not in COLLECTOR_STATUSES:
            raise CollectorValidationError(f"Estado de collector inválido: {self.status}")
        if self.mode != COLLECTOR_MODE:
            raise CollectorValidationError("Los collectors CCHIA solo admiten mode=read_only")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": self.schema_version,
            "collector_id": self.collector_id,
            "collector_version": self.collector_version,
            "mode": self.mode,
            "status": self.status,
            "collected_at": self.collected_at,
            "provenance": self.provenance,
            "evidence": self.evidence,
            "redaction": {
                "applied": True,
                "strategy": "cchia-default-v1",
                "replacement": "[REDACTED]",
            },
            "limitations": list(self.limitations),
        }
        result["evidence_sha256"] = canonical_hash(
            {
                "collector_id": self.collector_id,
                "collector_version": self.collector_version,
                "evidence": self.evidence,
            }
        )
        return result
