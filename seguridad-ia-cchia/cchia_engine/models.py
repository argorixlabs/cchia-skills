"""Contratos internos, deliberadamente pequeños y serializables."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


ENGINE_VERSION = "0.5.0"
STATUSES = {
    "PASS",
    "FAIL",
    "PARTIAL",
    "NOT_ASSESSED",
    "NOT_APPLICABLE",
    "ERROR",
}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}
EVIDENCE_LEVELS = {"E0", "E1", "E2", "E3", "E4", "E5"}


@dataclass(frozen=True)
class CheckPackage:
    path: Path
    control: dict[str, Any]
    expected: dict[str, Any]
    mapping: dict[str, Any]
    source_hash: str

    @property
    def control_id(self) -> str:
        return str(self.control["id"])

    @property
    def domain(self) -> str:
        return str(self.control["domain"])

    @property
    def control_version(self) -> str:
        return str(self.control["version"])


class ContractError(ValueError):
    """El paquete de control no respeta el contrato CCHIA."""


class CheckSafetyError(ValueError):
    """El código del check viola el perfil de ejecución pura/read-only."""
