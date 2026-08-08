"""Opt-in GitHub repository security inventory through fixed read-only gh commands."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import CollectorValidationError, CommandSpec
from .executor import execute_command_collector
from .policy import validate_github_repo


COLLECTOR_ID = "gh-repo-security"
COLLECTOR_VERSION = "1.0.0"
_API_HEADERS = (
    "-H",
    "Accept: application/vnd.github+json",
    "-H",
    "X-GitHub-Api-Version: 2022-11-28",
)

def _timeout(options: dict[str, Any]) -> int:
    timeout = options.get("timeout_seconds", 30)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise CollectorValidationError("timeout_seconds debe ser un entero entre 1 y 300")
    return timeout


def _api_spec(command_id: str, policy_id: str, endpoint: str) -> CommandSpec:
    return CommandSpec(command_id, policy_id, ("gh", "api", endpoint, *_API_HEADERS))


def collect_gh_repo_security(
    *, target: Path | str | None, options: dict[str, Any]
) -> dict[str, Any]:
    """Collect repository/ruleset/Actions metadata without output-dependent commands."""

    repository = validate_github_repo(options.get("github_repo"))
    specs = [
        CommandSpec(
            "repo-view",
            "gh.repo.view.v1",
            (
                "gh",
                "repo",
                "view",
                repository,
                "--json",
                "nameWithOwner,defaultBranchRef,visibility,isArchived",
            ),
        ),
        _api_spec("repo-metadata", "gh.api.repo.v1", f"repos/{repository}"),
        _api_spec("repo-rulesets", "gh.api.repo.rulesets.v1", f"repos/{repository}/rulesets"),
        _api_spec(
            "actions-workflow-permissions",
            "gh.api.repo.actions-workflow-permissions.v1",
            f"repos/{repository}/actions/permissions/workflow",
        ),
    ]
    return execute_command_collector(
        collector_id=COLLECTOR_ID,
        collector_version=COLLECTOR_VERSION,
        provider="github",
        sdk_name="GitHub CLI",
        tool="gh",
        specs=specs,
        target=target,
        timeout_seconds=_timeout(options),
        limitations=(
            "Snapshot puntual; no prueba historial, bypass efectivo ni ausencia de drift.",
            "La lista de rulesets puede paginar a 30 elementos y puede omitir detalle de rules; el evaluador rechaza cobertura insuficiente.",
            "El endpoint de workflow permissions requiere Administration:read aunque todos los comandos sean GET.",
            "La identidad configurada en gh debe usar permisos mínimos de lectura y puede mantener cache/configuración fuera del target.",
        ),
    )


__all__ = [
    "COLLECTOR_ID",
    "COLLECTOR_VERSION",
    "collect_gh_repo_security",
    "validate_github_repo",
]
