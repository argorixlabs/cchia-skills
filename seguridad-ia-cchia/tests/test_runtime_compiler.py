from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
import sys

if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.collectors import CollectorResult, CollectorValidationError
from cchia_engine.compiler import compile_assessment


def _command(command_id: str, policy_id: str, *, available: bool = True) -> dict:
    return {
        "command_id": command_id,
        "policy_id": policy_id,
        "argv": ["read-only", command_id],
        "status": "AVAILABLE" if available else "UNAVAILABLE",
        "exit_code": 0 if available else None,
        "duration_ms": 1,
        "stdout_sha256": "b" * 64,
        "stderr": "",
    }


def _collector(
    collector_id: str,
    *,
    provider: str,
    tool: str,
    commands: list[dict],
    evidence: list[dict],
    status: str = "AVAILABLE",
) -> dict:
    return CollectorResult(
        collector_id=collector_id,
        collector_version="1.0.0",
        status=status,
        collected_at="2026-08-07T22:30:00Z",
        provenance={
            "target": str(SKILL_ROOT / "examples" / "demo-target"),
            "provider": provider,
            "interface": {
                "kind": "command",
                "tool": tool,
                "sdk": "integration-test read-only client",
                "sdk_version": None,
                "executable_available": status != "UNAVAILABLE",
                "resolved_executable": None if status == "UNAVAILABLE" else f"C:/mock/{tool}.exe",
            },
            "commands": commands,
        },
        evidence=evidence,
        limitations=("Fixture runtime determinista; no representa un proveedor real.",),
    ).to_dict()


def _gcloud(*, status: str = "AVAILABLE") -> dict:
    available = status == "AVAILABLE"
    command_specs = (
        ("project-description", "gcloud.projects.describe.v1"),
        ("project-iam-policy", "gcloud.projects.get-iam-policy.v1"),
        ("service-accounts", "gcloud.iam.service-accounts.list.v1"),
    )
    commands = [_command(command_id, policy, available=available) for command_id, policy in command_specs]
    evidence = []
    if available:
        evidence = [
            {"command_id": "project-description", "status": "AVAILABLE", "content_type": "application/json", "data": {"projectId": "demo-project"}},
            {"command_id": "project-iam-policy", "status": "AVAILABLE", "content_type": "application/json", "data": {"bindings": [{"role": "roles/compute.viewer", "members": ["group:platform@example.com"]}]}},
            {"command_id": "service-accounts", "status": "AVAILABLE", "content_type": "application/json", "data": []},
        ]
    return _collector(
        "gcloud-iam",
        provider="gcp",
        tool="gcloud",
        commands=commands,
        evidence=evidence,
        status=status,
    )


def _kubectl_rbac() -> dict:
    commands = [
        _command("cluster-rbac", "kubectl.rbac.cluster.v1"),
        _command("namespaced-rbac", "kubectl.rbac.namespaced.v1"),
    ]
    cluster_items = [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "read-pods"},
            "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "read-pods-binding"},
            "roleRef": {"kind": "ClusterRole", "name": "read-pods"},
            "subjects": [{"kind": "ServiceAccount", "name": "reader", "namespace": "prod"}],
        },
    ]
    namespaced_items = [
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "read-config", "namespace": "prod"},
            "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "read-config-binding", "namespace": "prod"},
            "roleRef": {"kind": "Role", "name": "read-config"},
            "subjects": [{"kind": "ServiceAccount", "name": "reader", "namespace": "prod"}],
        },
    ]
    evidence = [
        {"command_id": "cluster-rbac", "status": "AVAILABLE", "content_type": "application/json", "data": {"apiVersion": "v1", "kind": "List", "items": cluster_items}},
        {"command_id": "namespaced-rbac", "status": "AVAILABLE", "content_type": "application/json", "data": {"apiVersion": "v1", "kind": "List", "items": namespaced_items}},
    ]
    return _collector("kubectl-rbac", provider="kubernetes", tool="kubectl", commands=commands, evidence=evidence)


def _kubectl_workloads() -> dict:
    commands = [_command("workloads", "kubectl.workloads.v1")]
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "safe-api", "namespace": "prod"},
        "spec": {
            "containers": [{
                "name": "api",
                "securityContext": {"allowPrivilegeEscalation": False, "privileged": False},
                "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits": {"cpu": "500m", "memory": "512Mi"},
                },
            }]
        },
    }
    evidence = [{"command_id": "workloads", "status": "AVAILABLE", "content_type": "application/json", "data": {"apiVersion": "v1", "kind": "List", "items": [pod]}}]
    return _collector("kubectl-workloads", provider="kubernetes", tool="kubectl", commands=commands, evidence=evidence)


class RuntimeCompilerIntegrationTests(unittest.TestCase):
    def _compile(self, collectors: list[dict], names: list[str], *, options: dict | None = None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / "assessment"
        with patch("cchia_engine.compiler.collect_requested", return_value=collectors):
            result = compile_assessment(
                target=SKILL_ROOT / "examples" / "demo-target",
                catalog_root=SKILL_ROOT / "checks",
                output=output,
                collector_names=names,
                collector_options=options,
            )
        return result, output

    def test_available_gcloud_selects_and_executes_runtime_check(self):
        result, _ = self._compile(
            [_gcloud()], ["gcloud-iam"], options={"gcp_project": "demo-project"}
        )
        self.assertIn("runtime-gcp-iam", result["plan"]["scope"]["signals"])
        self.assertIn("CCHIA-GCP-IAM-003", result["plan"]["selected_controls"])
        evaluations = {
            item["control_id"]: item["evaluation"]["status"]
            for item in result["assessment"]["results"]
        }
        self.assertEqual("PASS", evaluations["CCHIA-GCP-IAM-003"])

    def test_unavailable_collector_selects_runtime_check_but_never_passes(self):
        result, _ = self._compile(
            [_gcloud(status="UNAVAILABLE")],
            ["gcloud-iam"],
            options={"gcp_project": "demo-project"},
        )
        signals = result["plan"]["scope"]["signals"]
        self.assertIn("collector-gcloud-iam-requested", signals)
        self.assertNotIn("runtime-gcp-iam", signals)
        evaluations = {
            item["control_id"]: item["evaluation"]["status"]
            for item in result["assessment"]["results"]
        }
        self.assertEqual("NOT_ASSESSED", evaluations["CCHIA-GCP-IAM-003"])
        self.assertNotIn("PASS", [
            item["evaluation"]["status"]
            for item in result["assessment"]["results"]
            if item["control_id"] == "CCHIA-GCP-IAM-003"
        ])

    def test_available_kubernetes_collectors_drive_both_runtime_checks(self):
        result, _ = self._compile(
            [_kubectl_rbac(), _kubectl_workloads()],
            ["kubectl-rbac", "kubectl-workloads"],
        )
        signals = result["plan"]["scope"]["signals"]
        self.assertIn("runtime-k8s-rbac", signals)
        self.assertIn("runtime-k8s-workloads", signals)
        evaluations = {
            item["control_id"]: item["evaluation"]["status"]
            for item in result["assessment"]["results"]
        }
        self.assertEqual("PASS", evaluations["CCHIA-K8S-RBAC-002"])
        self.assertEqual("PASS", evaluations["CCHIA-K8S-WL-003"])

    def test_tampered_collector_hash_is_rejected_before_artifact_write(self):
        tampered = copy.deepcopy(_gcloud())
        tampered["evidence_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "assessment"
            with patch("cchia_engine.compiler.collect_requested", return_value=[tampered]):
                with self.assertRaises(CollectorValidationError):
                    compile_assessment(
                        target=SKILL_ROOT / "examples" / "demo-target",
                        catalog_root=SKILL_ROOT / "checks",
                        output=output,
                        collector_names=["gcloud-iam"],
                        collector_options={"gcp_project": "demo-project"},
                    )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
