"""Opt-in AWS IAM inventory through a fixed read-only AWS CLI plan."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import CollectorValidationError, CommandSpec
from .executor import execute_command_collector
from .policy import validate_aws_profile


COLLECTOR_ID = "aws-iam"
COLLECTOR_VERSION = "1.0.0"


def _prefix(options: dict[str, Any]) -> tuple[str, ...]:
    profile = options.get("aws_profile")
    if profile is None:
        return ("aws",)
    return ("aws", "--profile", validate_aws_profile(profile))


def _timeout(options: dict[str, Any]) -> int:
    timeout = options.get("timeout_seconds", 30)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise CollectorValidationError("timeout_seconds debe ser un entero entre 1 y 300")
    return timeout


def collect_aws_iam(
    *, target: Path | str | None, options: dict[str, Any]
) -> dict[str, Any]:
    """Collect the caller, root-account summary and IAM authorization inventory."""

    if not isinstance(options, dict):
        raise CollectorValidationError("collector options debe ser un mapping de opciones tipadas")
    prefix = _prefix(options)
    specs = [
        CommandSpec(
            "caller-identity",
            "aws.sts.get-caller-identity.v1",
            (*prefix, "sts", "get-caller-identity", "--output", "json"),
        ),
        CommandSpec(
            "account-summary",
            "aws.iam.get-account-summary.v1",
            (*prefix, "iam", "get-account-summary", "--output", "json"),
        ),
        CommandSpec(
            "account-authorization-details",
            "aws.iam.get-account-authorization-details.v1",
            (
                *prefix,
                "iam",
                "get-account-authorization-details",
                "--filter",
                "User",
                "Role",
                "Group",
                "LocalManagedPolicy",
                "--output",
                "json",
            ),
        ),
    ]
    return execute_command_collector(
        collector_id=COLLECTOR_ID,
        collector_version=COLLECTOR_VERSION,
        provider="aws",
        sdk_name="AWS CLI",
        tool="aws",
        specs=specs,
        target=target,
        timeout_seconds=_timeout(options),
        limitations=(
            "Snapshot puntual de IAM; no prueba ausencia de drift, uso histórico ni acceso efectivo fuera de las políticas enumeradas.",
            "La identidad y el profile configurados en AWS CLI deben limitarse externamente a estas consultas de lectura.",
            "No evalúa SCP, resource policies, permission sets de IAM Identity Center ni permisos fuera de la cuenta consultada.",
        ),
    )


__all__ = [
    "COLLECTOR_ID",
    "COLLECTOR_VERSION",
    "collect_aws_iam",
    "validate_aws_profile",
]
