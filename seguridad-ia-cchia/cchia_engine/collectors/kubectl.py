"""Opt-in Kubernetes cluster, RBAC and workload inventory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import CollectorValidationError, CommandSpec
from .executor import execute_command_collector
from .policy import validate_kube_selector


COLLECTOR_VERSION = "1.0.0"
_WORKLOAD_RESOURCES = "deployments,statefulsets,daemonsets,replicasets,cronjobs,jobs,pods"


def _prefix(options: dict[str, Any]) -> tuple[str, ...]:
    context = options.get("kube_context")
    if context is None:
        return ("kubectl",)
    return ("kubectl", "--context", validate_kube_selector(context, "kube_context"))


def _scope(options: dict[str, Any]) -> tuple[str, ...]:
    namespace = options.get("kube_namespace")
    if namespace is None:
        return ("--all-namespaces",)
    return ("--namespace", validate_kube_selector(namespace, "kube_namespace"))


def _timeout(options: dict[str, Any]) -> int:
    timeout = options.get("timeout_seconds", 30)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 300:
        raise CollectorValidationError("timeout_seconds debe ser un entero entre 1 y 300")
    return timeout


def _execute(
    collector_id: str,
    specs: list[CommandSpec],
    *,
    target: Path | str | None,
    options: dict[str, Any],
    limitations: tuple[str, ...],
) -> dict[str, Any]:
    return execute_command_collector(
        collector_id=collector_id,
        collector_version=COLLECTOR_VERSION,
        provider="kubernetes",
        sdk_name="Kubernetes kubectl client",
        tool="kubectl",
        specs=specs,
        target=target,
        timeout_seconds=_timeout(options),
        limitations=limitations,
    )


def collect_kubectl_cluster(
    *, target: Path | str | None, options: dict[str, Any]
) -> dict[str, Any]:
    prefix = _prefix(options)
    return _execute(
        "kubectl-cluster",
        [
            CommandSpec("cluster-version", "kubectl.cluster.version.v1", (*prefix, "version", "-o", "json")),
            CommandSpec(
                "namespaces", "kubectl.cluster.namespaces.v1", (*prefix, "get", "namespaces", "-o", "json")
            ),
        ],
        target=target,
        options=options,
        limitations=(
            "Snapshot puntual del endpoint seleccionado; no prueba controles fuera del API server.",
            "La identidad kubeconfig debe estar limitada externamente a verbos get/list.",
        ),
    )


def collect_kubectl_rbac(
    *, target: Path | str | None, options: dict[str, Any]
) -> dict[str, Any]:
    prefix = _prefix(options)
    scope = _scope(options)
    return _execute(
        "kubectl-rbac",
        [
            CommandSpec(
                "cluster-rbac",
                "kubectl.rbac.cluster.v1",
                (*prefix, "get", "clusterroles,clusterrolebindings", "-o", "json"),
            ),
            CommandSpec(
                "namespaced-rbac",
                "kubectl.rbac.namespaced.v1",
                (*prefix, "get", "roles,rolebindings", *scope, "-o", "json"),
            ),
        ],
        target=target,
        options=options,
        limitations=(
            "La enumeración RBAC no demuestra el acceso efectivo de identidades externas.",
            "La identidad kubeconfig debe estar limitada externamente a verbos get/list.",
        ),
    )


def collect_kubectl_workloads(
    *, target: Path | str | None, options: dict[str, Any]
) -> dict[str, Any]:
    prefix = _prefix(options)
    scope = _scope(options)
    return _execute(
        "kubectl-workloads",
        [
            CommandSpec(
                "workloads",
                "kubectl.workloads.v1",
                (*prefix, "get", _WORKLOAD_RESOURCES, *scope, "-o", "json"),
            )
        ],
        target=target,
        options=options,
        limitations=(
            "No recolecta objetos Secret ni ConfigMap.",
            "La identidad kubeconfig debe estar limitada externamente a verbos get/list.",
        ),
    )
