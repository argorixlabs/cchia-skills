"""Rigid allow-list for every subprocess a collector may launch."""

from __future__ import annotations

import re
from collections.abc import Sequence

from .base import CollectorValidationError, CommandSpec


_GCP_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_KUBE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,252}$")
_AWS_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")
_AZURE_SUBSCRIPTION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._() -]{0,127}$")
_GITHUB_REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$"
)
_GITHUB_API_HEADERS = (
    "-H",
    "Accept: application/vnd.github+json",
    "-H",
    "X-GitHub-Api-Version: 2022-11-28",
)


def validate_gcp_project(value: object) -> str:
    if not isinstance(value, str) or not _GCP_PROJECT.fullmatch(value):
        raise CollectorValidationError(
            "gcp_project inválido; use un ID de proyecto, nunca flags ni argumentos libres"
        )
    return value


def validate_kube_selector(value: object, option_name: str) -> str:
    if not isinstance(value, str) or not _KUBE_NAME.fullmatch(value) or ".." in value:
        raise CollectorValidationError(
            f"{option_name} inválido; use un nombre, nunca flags ni argumentos libres"
        )
    return value


def validate_aws_profile(value: object) -> str:
    if (
        not isinstance(value, str)
        or not _AWS_PROFILE.fullmatch(value)
        or ".." in value
    ):
        raise CollectorValidationError(
            "aws_profile inválido; use un nombre de perfil, nunca flags ni argumentos libres"
        )
    return value


def validate_azure_subscription(value: object) -> str:
    if (
        not isinstance(value, str)
        or not _AZURE_SUBSCRIPTION.fullmatch(value)
        or ".." in value
    ):
        raise CollectorValidationError(
            "azure_subscription inválida; use un ID o nombre, nunca flags ni argumentos libres"
        )
    return value


def validate_github_repo(value: object) -> str:
    if (
        not isinstance(value, str)
        or not _GITHUB_REPOSITORY.fullmatch(value)
        or ".." in value
    ):
        raise CollectorValidationError(
            "github_repo inválido; use owner/repo, nunca URL, flags ni argumentos libres"
        )
    _owner, repository = value.split("/", 1)
    if repository == "." or repository.startswith("-"):
        raise CollectorValidationError(
            "github_repo inválido; el repositorio no puede ser traversal ni interpretarse como flag"
        )
    return value


def _assert_exact(actual: Sequence[str], expected: Sequence[str], policy_id: str) -> None:
    if tuple(actual) != tuple(expected):
        raise CollectorValidationError(
            f"Comando rechazado por allow-list {policy_id}: {' '.join(actual)}"
        )


def validate_gcloud_command(argv: Sequence[str], policy_id: str) -> None:
    if not argv or argv[0] != "gcloud":
        raise CollectorValidationError("El collector gcloud solo puede invocar el ejecutable gcloud")
    if policy_id == "gcloud.projects.describe.v1" and len(argv) == 6:
        project = validate_gcp_project(argv[3])
        _assert_exact(argv, ("gcloud", "projects", "describe", project, "--format=json", "--quiet"), policy_id)
        return
    if policy_id == "gcloud.projects.get-iam-policy.v1" and len(argv) == 6:
        project = validate_gcp_project(argv[3])
        _assert_exact(
            argv,
            ("gcloud", "projects", "get-iam-policy", project, "--format=json", "--quiet"),
            policy_id,
        )
        return
    if policy_id == "gcloud.iam.service-accounts.list.v1" and len(argv) == 8:
        project = validate_gcp_project(argv[5])
        _assert_exact(
            argv,
            (
                "gcloud", "iam", "service-accounts", "list", "--project", project,
                "--format=json", "--quiet",
            ),
            policy_id,
        )
        return
    raise CollectorValidationError(f"Regla gcloud desconocida o forma inválida: {policy_id}")


def _split_aws_profile(argv: Sequence[str]) -> tuple[list[str], str | None]:
    if not argv or argv[0] != "aws":
        raise CollectorValidationError("El collector AWS solo puede invocar el ejecutable aws")
    rest = list(argv[1:])
    profile = None
    if rest[:1] == ["--profile"]:
        if len(rest) < 3:
            raise CollectorValidationError("Falta el valor seguro de --profile")
        profile = validate_aws_profile(rest[1])
        rest = rest[2:]
    return rest, profile


def _aws_prefix(profile: str | None) -> tuple[str, ...]:
    return ("aws", "--profile", profile) if profile else ("aws",)


def validate_aws_command(argv: Sequence[str], policy_id: str) -> None:
    rest, profile = _split_aws_profile(argv)
    prefix = _aws_prefix(profile)
    if policy_id == "aws.sts.get-caller-identity.v1":
        _assert_exact(argv, (*prefix, "sts", "get-caller-identity", "--output", "json"), policy_id)
        return
    if policy_id == "aws.iam.get-account-summary.v1":
        _assert_exact(argv, (*prefix, "iam", "get-account-summary", "--output", "json"), policy_id)
        return
    if policy_id == "aws.iam.get-account-authorization-details.v1":
        _assert_exact(
            argv,
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
            policy_id,
        )
        return
    raise CollectorValidationError(f"Regla AWS desconocida o forma inválida: {policy_id}")


def _azure_expected(
    base: tuple[str, ...], subscription: str | None
) -> tuple[str, ...]:
    subscription_args = ("--subscription", subscription) if subscription else ()
    return (*base, *subscription_args, "--output", "json")


def _azure_subscription(argv: Sequence[str], base: tuple[str, ...]) -> str | None:
    if tuple(argv[: len(base)]) != base:
        raise CollectorValidationError("Forma de comando Azure inválida")
    rest = tuple(argv[len(base):])
    if rest == ("--output", "json"):
        return None
    if len(rest) == 4 and rest[0] == "--subscription" and rest[2:] == ("--output", "json"):
        return validate_azure_subscription(rest[1])
    raise CollectorValidationError("Opciones Azure rechazadas por allow-list")


def validate_azure_command(argv: Sequence[str], policy_id: str) -> None:
    if not argv or argv[0] != "az":
        raise CollectorValidationError("El collector Azure solo puede invocar el ejecutable az")
    if policy_id == "az.account.show.v1":
        base = ("az", "account", "show")
        subscription = _azure_subscription(argv, base)
        _assert_exact(argv, _azure_expected(base, subscription), policy_id)
        return
    if policy_id == "az.role.assignment.list.v1":
        base = ("az", "role", "assignment", "list", "--all")
        subscription = _azure_subscription(argv, base)
        _assert_exact(argv, _azure_expected(base, subscription), policy_id)
        return
    raise CollectorValidationError(f"Regla Azure desconocida o forma inválida: {policy_id}")


def _github_endpoint_repo(endpoint: str) -> str:
    parts = endpoint.split("/")
    if len(parts) < 3 or parts[0] != "repos":
        raise CollectorValidationError("Endpoint GitHub rechazado por allow-list")
    return validate_github_repo(f"{parts[1]}/{parts[2]}")


def validate_github_command(argv: Sequence[str], policy_id: str) -> None:
    if not argv or argv[0] != "gh":
        raise CollectorValidationError("El collector GitHub solo puede invocar el ejecutable gh")
    if policy_id == "gh.repo.view.v1" and len(argv) == 6:
        repository = validate_github_repo(argv[3])
        _assert_exact(
            argv,
            (
                "gh",
                "repo",
                "view",
                repository,
                "--json",
                "nameWithOwner,defaultBranchRef,visibility,isArchived",
            ),
            policy_id,
        )
        return

    if len(argv) != 7 or argv[1] != "api":
        raise CollectorValidationError(f"Forma GitHub inválida para policy {policy_id}")
    endpoint = argv[2]
    repository = _github_endpoint_repo(endpoint)
    endpoint_by_policy = {
        "gh.api.repo.v1": f"repos/{repository}",
        "gh.api.repo.rulesets.v1": f"repos/{repository}/rulesets",
        "gh.api.repo.actions-workflow-permissions.v1": (
            f"repos/{repository}/actions/permissions/workflow"
        ),
    }
    expected_endpoint = endpoint_by_policy.get(policy_id)
    if expected_endpoint is None:
        raise CollectorValidationError(f"Regla GitHub desconocida: {policy_id}")
    _assert_exact(argv, ("gh", "api", expected_endpoint, *_GITHUB_API_HEADERS), policy_id)


def _split_kube_context(argv: Sequence[str]) -> tuple[list[str], str | None]:
    if not argv or argv[0] != "kubectl":
        raise CollectorValidationError("El collector Kubernetes solo puede invocar kubectl")
    rest = list(argv[1:])
    context = None
    if rest[:1] == ["--context"]:
        if len(rest) < 3:
            raise CollectorValidationError("Falta el valor seguro de --context")
        context = validate_kube_selector(rest[1], "kube_context")
        rest = rest[2:]
    return rest, context


def _kube_prefix(context: str | None) -> tuple[str, ...]:
    return ("kubectl", "--context", context) if context else ("kubectl",)


def _validate_namespaced_get(
    argv: Sequence[str], rest: Sequence[str], context: str | None, resource: str, policy_id: str
) -> None:
    base = (*_kube_prefix(context), "get", resource)
    if tuple(rest) == ("get", resource, "--all-namespaces", "-o", "json"):
        _assert_exact(argv, (*base, "--all-namespaces", "-o", "json"), policy_id)
        return
    if len(rest) == 6 and tuple(rest[:2]) == ("get", resource) and rest[2] == "--namespace":
        namespace = validate_kube_selector(rest[3], "kube_namespace")
        _assert_exact(argv, (*base, "--namespace", namespace, "-o", "json"), policy_id)
        return
    raise CollectorValidationError(f"Comando rechazado por allow-list {policy_id}")


def validate_kubectl_command(argv: Sequence[str], policy_id: str) -> None:
    rest, context = _split_kube_context(argv)
    prefix = _kube_prefix(context)
    if policy_id == "kubectl.cluster.version.v1":
        _assert_exact(argv, (*prefix, "version", "-o", "json"), policy_id)
        return
    if policy_id == "kubectl.cluster.namespaces.v1":
        _assert_exact(argv, (*prefix, "get", "namespaces", "-o", "json"), policy_id)
        return
    if policy_id == "kubectl.rbac.cluster.v1":
        _assert_exact(argv, (*prefix, "get", "clusterroles,clusterrolebindings", "-o", "json"), policy_id)
        return
    if policy_id == "kubectl.rbac.namespaced.v1":
        _validate_namespaced_get(argv, rest, context, "roles,rolebindings", policy_id)
        return
    if policy_id == "kubectl.workloads.v1":
        _validate_namespaced_get(
            argv,
            rest,
            context,
            "deployments,statefulsets,daemonsets,replicasets,cronjobs,jobs,pods",
            policy_id,
        )
        return
    raise CollectorValidationError(f"Regla kubectl desconocida: {policy_id}")


def validate_command(spec: CommandSpec) -> None:
    if not spec.argv:
        raise CollectorValidationError("Un comando de collector no puede estar vacío")
    if spec.argv[0] == "gcloud":
        validate_gcloud_command(spec.argv, spec.policy_id)
        return
    if spec.argv[0] == "kubectl":
        validate_kubectl_command(spec.argv, spec.policy_id)
        return
    if spec.argv[0] == "aws":
        validate_aws_command(spec.argv, spec.policy_id)
        return
    if spec.argv[0] == "az":
        validate_azure_command(spec.argv, spec.policy_id)
        return
    if spec.argv[0] == "gh":
        validate_github_command(spec.argv, spec.policy_id)
        return
    raise CollectorValidationError(f"Ejecutable no permitido: {spec.argv[0]}")
