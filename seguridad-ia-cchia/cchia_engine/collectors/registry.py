"""Collector catalog and explicit opt-in dispatcher."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable

from .base import CollectorValidationError
from .aws import collect_aws_iam
from .azure import collect_azure_role_assignments
from .gcloud import collect_gcloud_iam
from .github import collect_gh_repo_security
from .kubectl import collect_kubectl_cluster, collect_kubectl_rbac, collect_kubectl_workloads


CollectorFunction = Callable[..., dict[str, Any]]
_SUPPORTED_OPTIONS = {
    "aws_profile",
    "azure_subscription",
    "gcp_project",
    "github_repo",
    "kube_context",
    "kube_namespace",
    "timeout_seconds",
}
_REGISTRY: dict[str, dict[str, Any]] = {
    "aws-iam": {
        "provider": "aws",
        "description": "Identidad, resumen de cuenta y autorización IAM con AWS CLI.",
        "function": collect_aws_iam,
    },
    "az-role-assignments": {
        "provider": "azure",
        "description": "Cuenta y asignaciones Azure RBAC visibles con Azure CLI.",
        "function": collect_azure_role_assignments,
    },
    "gcloud-iam": {
        "provider": "gcp",
        "description": "Describe proyecto, política IAM y lista service accounts con gcloud.",
        "function": collect_gcloud_iam,
    },
    "gh-repo-security": {
        "provider": "github",
        "description": "Metadatos, rulesets y permisos Actions de un repositorio con GitHub CLI.",
        "function": collect_gh_repo_security,
    },
    "kubectl-cluster": {
        "provider": "kubernetes",
        "description": "Versión de cluster y namespaces visibles con kubectl.",
        "function": collect_kubectl_cluster,
    },
    "kubectl-rbac": {
        "provider": "kubernetes",
        "description": "Roles y bindings de cluster/namespaces visibles con kubectl.",
        "function": collect_kubectl_rbac,
    },
    "kubectl-workloads": {
        "provider": "kubernetes",
        "description": "Inventario de workloads visible con kubectl, sin Secrets ni ConfigMaps.",
        "function": collect_kubectl_workloads,
    },
}


def available_collectors() -> list[dict[str, str]]:
    return [
        {
            "id": collector_id,
            "provider": str(metadata["provider"]),
            "mode": "read_only",
            "description": str(metadata["description"]),
        }
        for collector_id, metadata in sorted(_REGISTRY.items())
    ]


def collector_names() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def _normalize_options(options: Mapping[str, Any] | None) -> dict[str, Any]:
    if options is None:
        return {"timeout_seconds": 30}
    if not isinstance(options, Mapping):
        raise CollectorValidationError("collector options debe ser un mapping de opciones tipadas")
    unknown = set(options) - _SUPPORTED_OPTIONS
    if unknown:
        raise CollectorValidationError(
            "Opciones de collector no permitidas: " + ", ".join(sorted(str(item) for item in unknown))
        )
    normalized = {str(key): value for key, value in options.items() if value is not None}
    normalized.setdefault("timeout_seconds", 30)
    timeout = normalized["timeout_seconds"]
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise CollectorValidationError("timeout_seconds debe ser un entero entre 1 y 300")
    return normalized


def collect_requested(
    names: Sequence[str],
    *,
    target: Path | str | None = None,
    options: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run only explicitly requested collectors and return redacted JSON data.

    Passing an empty sequence is the no-op default and never discovers or invokes a
    cloud/Kubernetes executable.
    """

    if isinstance(names, (str, bytes)):
        raise CollectorValidationError("names debe ser una secuencia; no se aceptan comandos libres")
    requested = list(dict.fromkeys(names))
    if not requested:
        return []
    unknown = set(requested) - set(_REGISTRY)
    if unknown:
        raise CollectorValidationError(
            "Collectors desconocidos: " + ", ".join(sorted(str(item) for item in unknown))
        )
    normalized = _normalize_options(options)
    results = []
    for name in requested:
        function: CollectorFunction = _REGISTRY[name]["function"]
        results.append(function(target=target, options=normalized))
    return results
