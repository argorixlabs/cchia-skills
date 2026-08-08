"""Opt-in Google Cloud IAM inventory through read-only gcloud commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import CollectorValidationError, CommandSpec
from .executor import execute_command_collector
from .policy import validate_gcp_project


COLLECTOR_ID = "gcloud-iam"
COLLECTOR_VERSION = "1.0.0"


def collect_gcloud_iam(
    *, target: Path | str | None, options: dict[str, Any]
) -> dict[str, Any]:
    project = validate_gcp_project(options.get("gcp_project"))
    timeout = options.get("timeout_seconds", 30)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise CollectorValidationError("timeout_seconds debe ser un entero entre 1 y 300")
    specs = [
        CommandSpec(
            "project-description",
            "gcloud.projects.describe.v1",
            ("gcloud", "projects", "describe", project, "--format=json", "--quiet"),
        ),
        CommandSpec(
            "project-iam-policy",
            "gcloud.projects.get-iam-policy.v1",
            ("gcloud", "projects", "get-iam-policy", project, "--format=json", "--quiet"),
        ),
        CommandSpec(
            "service-accounts",
            "gcloud.iam.service-accounts.list.v1",
            (
                "gcloud", "iam", "service-accounts", "list", "--project", project,
                "--format=json", "--quiet",
            ),
        ),
    ]
    return execute_command_collector(
        collector_id=COLLECTOR_ID,
        collector_version=COLLECTOR_VERSION,
        provider="gcp",
        sdk_name="Google Cloud CLI",
        tool="gcloud",
        specs=specs,
        target=target,
        timeout_seconds=timeout,
        limitations=(
            "Inventario puntual; no prueba ausencia de drift ni efectividad histórica de IAM.",
            "La identidad configurada en gcloud debe estar limitada externamente a permisos de lectura.",
        ),
    )
