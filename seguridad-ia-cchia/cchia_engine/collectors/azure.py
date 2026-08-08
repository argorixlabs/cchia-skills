"""Opt-in Azure RBAC inventory through read-only Azure CLI commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import CollectorValidationError, CommandSpec
from .executor import execute_command_collector
from .policy import validate_azure_subscription


COLLECTOR_ID = "az-role-assignments"
COLLECTOR_VERSION = "1.0.0"
ACCOUNT_POLICY_ID = "az.account.show.v1"
ROLE_ASSIGNMENTS_POLICY_ID = "az.role.assignment.list.v1"


def collect_azure_role_assignments(
    *, target: Path | str | None, options: dict[str, Any]
) -> dict[str, Any]:
    subscription_value = options.get("azure_subscription")
    subscription = (
        validate_azure_subscription(subscription_value)
        if subscription_value is not None
        else None
    )
    timeout = options.get("timeout_seconds", 30)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise CollectorValidationError("timeout_seconds debe ser un entero entre 1 y 300")
    selector = ("--subscription", subscription) if subscription is not None else ()
    specs = [
        CommandSpec(
            "azure-account",
            ACCOUNT_POLICY_ID,
            ("az", "account", "show", *selector, "--output", "json"),
        ),
        CommandSpec(
            "role-assignments",
            ROLE_ASSIGNMENTS_POLICY_ID,
            (
                "az", "role", "assignment", "list", "--all", *selector,
                "--output", "json",
            ),
        ),
    ]
    return execute_command_collector(
        collector_id=COLLECTOR_ID,
        collector_version=COLLECTOR_VERSION,
        provider="azure",
        sdk_name="Azure CLI",
        tool="az",
        specs=specs,
        target=target,
        timeout_seconds=timeout,
        limitations=(
            "Snapshot puntual; no prueba ausencia de drift ni asignaciones históricas.",
            "az role assignment list --all no demuestra asignaciones heredadas desde management groups.",
            "La identidad Azure CLI debe estar limitada externamente a permisos de lectura.",
        ),
    )


__all__ = [
    "ACCOUNT_POLICY_ID",
    "COLLECTOR_ID",
    "COLLECTOR_VERSION",
    "ROLE_ASSIGNMENTS_POLICY_ID",
    "collect_azure_role_assignments",
]
