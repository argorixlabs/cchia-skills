from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.catalog import applicability, load_check
from cchia_engine.runner import run_check


RBAC_PACKAGE = load_check(
    SKILL_ROOT / "checks" / "KUBERNETES" / "CCHIA-K8S-RBAC-002"
)
WORKLOAD_PACKAGE = load_check(
    SKILL_ROOT / "checks" / "KUBERNETES" / "CCHIA-K8S-WL-003"
)


def _context(collectors: list[dict]) -> dict:
    return {
        "signals": [],
        "signal_evidence": {},
        "files": [],
        "system": {},
        "collectors": collectors,
        "collection": {"complete": True},
    }


def _collector(
    collector_id: str,
    command_payloads: dict[str, dict],
    *,
    status: str = "AVAILABLE",
) -> dict:
    command_status = "AVAILABLE" if status == "AVAILABLE" else status
    commands = []
    evidence = []
    for command_id, payload in command_payloads.items():
        policies = {
            "cluster-rbac": "kubectl.rbac.cluster.v1",
            "namespaced-rbac": "kubectl.rbac.namespaced.v1",
            "workloads": "kubectl.workloads.v1",
        }
        commands.append(
            {
                "command_id": command_id,
                "policy_id": policies[command_id],
                "argv": ["kubectl", "get", command_id, "-o", "json"],
                "status": command_status,
                "exit_code": 0 if status == "AVAILABLE" else None,
                "duration_ms": 1,
                "stdout_sha256": "b" * 64,
            }
        )
        if status != "UNAVAILABLE":
            evidence.append(
                {
                    "command_id": command_id,
                    "status": command_status,
                    "content_type": "application/json",
                    "data": payload,
                }
            )
    return {
        "schema_version": "1.0",
        "collector_id": collector_id,
        "collector_version": "1.0.0",
        "mode": "read_only",
        "status": status,
        "collected_at": "2026-08-07T22:00:00Z",
        "provenance": {
            "target": "fixture",
            "provider": "kubernetes",
            "interface": {
                "kind": "command",
                "tool": "kubectl",
                "sdk": "Kubernetes kubectl client",
                "sdk_version": None,
                "executable_available": status != "UNAVAILABLE",
                "resolved_executable": None if status == "UNAVAILABLE" else "C:/mock/kubectl.exe",
            },
            "commands": commands,
        },
        "evidence": evidence,
        "redaction": {
            "applied": True,
            "strategy": "cchia-default-v1",
            "replacement": "[REDACTED]",
        },
        "limitations": [],
        "evidence_sha256": "a" * 64,
    }


def _list(items: list[dict]) -> dict:
    return {"apiVersion": "v1", "kind": "List", "items": items}


def _role(kind: str, name: str, rules: list[dict], namespace: str | None = None) -> dict:
    metadata = {"name": name}
    if namespace is not None:
        metadata["namespace"] = namespace
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": kind,
        "metadata": metadata,
        "rules": rules,
    }


def _binding(
    kind: str,
    name: str,
    role_kind: str,
    role_name: str,
    subjects: list[dict],
    namespace: str | None = None,
) -> dict:
    metadata = {"name": name}
    if namespace is not None:
        metadata["namespace"] = namespace
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": kind,
        "metadata": metadata,
        "roleRef": {
            "apiGroup": "rbac.authorization.k8s.io",
            "kind": role_kind,
            "name": role_name,
        },
        "subjects": subjects,
    }


def _safe_rbac_payloads() -> dict[str, dict]:
    cluster = [
        _role("ClusterRole", "pod-reader", [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]),
        _binding(
            "ClusterRoleBinding",
            "reader-team",
            "ClusterRole",
            "pod-reader",
            [{"kind": "Group", "name": "platform-readers", "apiGroup": "rbac.authorization.k8s.io"}],
        ),
    ]
    namespaced = [
        _role("Role", "config-reader", [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}], "prod"),
        _binding(
            "RoleBinding",
            "config-reader-team",
            "Role",
            "config-reader",
            [{"kind": "ServiceAccount", "name": "api", "namespace": "prod"}],
            "prod",
        ),
    ]
    return {"cluster-rbac": _list(cluster), "namespaced-rbac": _list(namespaced)}


def _safe_deployment() -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "api", "namespace": "prod"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "api",
                            "securityContext": {
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                            },
                            "resources": {
                                "requests": {"cpu": "100m", "memory": "128Mi"},
                                "limits": {"cpu": "500m", "memory": "256Mi"},
                            },
                        }
                    ]
                }
            }
        },
    }


class RuntimeKubernetesApplicabilityTests(unittest.TestCase):
    def test_controls_select_on_runtime_or_requested_collector_signal(self):
        cases = (
            (RBAC_PACKAGE, "runtime-k8s-rbac", "collector-kubectl-rbac-requested"),
            (WORKLOAD_PACKAGE, "runtime-k8s-workloads", "collector-kubectl-workloads-requested"),
        )
        for package, runtime_signal, requested_signal in cases:
            with self.subTest(control=package.control_id):
                self.assertTrue(applicability(package, {runtime_signal})[0])
                self.assertTrue(applicability(package, {requested_signal})[0])
                self.assertFalse(applicability(package, set())[0])
                self.assertEqual("1.0.0", package.control["version"])


class RuntimeKubernetesContractTests(unittest.TestCase):
    def _valid_cases(self):
        return (
            (
                RBAC_PACKAGE,
                _collector("kubectl-rbac", _safe_rbac_payloads()),
            ),
            (
                WORKLOAD_PACKAGE,
                _collector("kubectl-workloads", {"workloads": _list([_safe_deployment()])}),
            ),
        )

    def test_unknown_contract_hash_interface_or_policy_is_not_assessed(self):
        for package, _base in self._valid_cases():
            fixtures = []
            unknown_version = self._valid_collector(package)
            unknown_version["collector_version"] = "2.0.0"
            fixtures.append(unknown_version)
            bad_hash = self._valid_collector(package)
            bad_hash["evidence_sha256"] = "not-a-hash"
            fixtures.append(bad_hash)
            unresolved = self._valid_collector(package)
            unresolved["provenance"]["interface"]["resolved_executable"] = None
            fixtures.append(unresolved)
            wrong_policy = self._valid_collector(package)
            wrong_policy["provenance"]["commands"][0]["policy_id"] = "kubectl.unknown.v1"
            fixtures.append(wrong_policy)
            for collector in fixtures:
                with self.subTest(control=package.control_id, fixture=fixtures.index(collector)):
                    evaluation = run_check(package, _context([collector]))["evaluation"]
                    self.assertEqual("NOT_ASSESSED", evaluation["status"])

    def _valid_collector(self, package):
        if package.control_id == "CCHIA-K8S-RBAC-002":
            return _collector("kubectl-rbac", _safe_rbac_payloads())
        return _collector("kubectl-workloads", {"workloads": _list([_safe_deployment()])})

    def test_malformed_untrusted_command_metadata_is_not_reflected(self):
        for package, collector in self._valid_cases():
            collector["provenance"]["commands"][0]["command_id"] = ["sensitive-marker"]
            evaluation = run_check(package, _context([collector]))["evaluation"]
            self.assertEqual("NOT_ASSESSED", evaluation["status"])
            self.assertNotIn("sensitive-marker", json.dumps(evaluation))

    def test_redacted_critical_fields_are_not_assessed(self):
        rbac = _collector("kubectl-rbac", _safe_rbac_payloads())
        rbac["evidence"][0]["data"]["items"][1]["subjects"][0]["name"] = "[REDACTED]"
        workload = _collector("kubectl-workloads", {"workloads": _list([_safe_deployment()])})
        container = workload["evidence"][0]["data"]["items"][0]["spec"]["template"]["spec"]["containers"][0]
        container["resources"]["limits"]["memory"] = "[REDACTED]"

        self.assertEqual(
            "NOT_ASSESSED",
            run_check(RBAC_PACKAGE, _context([rbac]))["evaluation"]["status"],
        )
        self.assertEqual(
            "NOT_ASSESSED",
            run_check(WORKLOAD_PACKAGE, _context([workload]))["evaluation"]["status"],
        )


class RuntimeRBACCheckTests(unittest.TestCase):
    def test_safe_complete_inventory_passes(self):
        collector = _collector("kubectl-rbac", _safe_rbac_payloads())
        result = run_check(RBAC_PACKAGE, _context([collector]))
        self.assertEqual("PASS", result["evaluation"]["status"])
        self.assertEqual("E4", result["evaluation"]["evidence_level"])
        self.assertEqual(2, result["evaluation"]["evidence"][0]["roles_scanned"])
        self.assertEqual(2, result["evaluation"]["evidence"][0]["bindings_scanned"])

    def test_public_cluster_admin_and_custom_wildcard_bindings_fail(self):
        payloads = _safe_rbac_payloads()
        payloads["cluster-rbac"]["items"].extend(
            [
                _role(
                    "ClusterRole",
                    "dangerous-operator",
                    [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
                ),
                _binding(
                    "ClusterRoleBinding",
                    "anonymous-admin",
                    "ClusterRole",
                    "cluster-admin",
                    [{"kind": "Group", "name": "system:unauthenticated", "apiGroup": "rbac.authorization.k8s.io"}],
                ),
                _binding(
                    "ClusterRoleBinding",
                    "operator-team",
                    "ClusterRole",
                    "dangerous-operator",
                    [{"kind": "Group", "name": "operators", "apiGroup": "rbac.authorization.k8s.io"}],
                ),
            ]
        )
        collector = _collector("kubectl-rbac", payloads)
        result = run_check(RBAC_PACKAGE, _context([collector]))
        self.assertEqual("FAIL", result["evaluation"]["status"])
        patterns = {item["pattern"] for item in result["evaluation"]["evidence"]}
        self.assertEqual(
            {"cluster-admin-binding", "public-or-anonymous-subject", "broad-role-binding"},
            patterns,
        )
        broad = [item for item in result["evaluation"]["evidence"] if item["pattern"] == "broad-role-binding"]
        self.assertIn("wildcard-verbs-and-resources", broad[0]["broad_reasons"])

    def test_unavailable_error_missing_and_incomplete_evidence_never_pass(self):
        safe = _safe_rbac_payloads()
        fixtures = [
            [],
            [_collector("kubectl-rbac", safe, status="UNAVAILABLE")],
            [_collector("kubectl-rbac", safe, status="ERROR")],
        ]
        incomplete = _collector("kubectl-rbac", safe)
        incomplete["evidence"] = [
            row for row in incomplete["evidence"] if row["command_id"] != "namespaced-rbac"
        ]
        fixtures.append([incomplete])
        malformed = _collector("kubectl-rbac", safe)
        malformed["evidence"][0]["data"] = {"kind": "List", "items": "not-a-list"}
        fixtures.append([malformed])
        for collectors in fixtures:
            with self.subTest(collectors=collectors):
                result = run_check(RBAC_PACKAGE, _context(collectors))
                self.assertEqual("NOT_ASSESSED", result["evaluation"]["status"])
                self.assertNotEqual("PASS", result["evaluation"]["status"])


class RuntimeWorkloadCheckTests(unittest.TestCase):
    def test_safe_complete_inventory_passes(self):
        collector = _collector("kubectl-workloads", {"workloads": _list([_safe_deployment()])})
        result = run_check(WORKLOAD_PACKAGE, _context([collector]))
        self.assertEqual("PASS", result["evaluation"]["status"])
        self.assertEqual("E4", result["evaluation"]["evidence_level"])
        self.assertEqual(1, result["evaluation"]["evidence"][0]["workloads_scanned"])

    def test_privilege_host_access_and_resource_gaps_fail(self):
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "danger", "namespace": "prod"},
            "spec": {
                "hostNetwork": True,
                "hostPID": True,
                "hostIPC": True,
                "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
                "containers": [
                    {
                        "name": "danger",
                        "securityContext": {
                            "privileged": True,
                            "allowPrivilegeEscalation": True,
                        },
                        "resources": {},
                    }
                ],
            },
        }
        collector = _collector("kubectl-workloads", {"workloads": _list([pod])})
        result = run_check(WORKLOAD_PACKAGE, _context([collector]))
        self.assertEqual("FAIL", result["evaluation"]["status"])
        patterns = {item["pattern"] for item in result["evaluation"]["evidence"]}
        self.assertEqual(
            {
                "host-network",
                "host-pid",
                "host-ipc",
                "host-path-volume",
                "privileged-container",
                "privilege-escalation-not-disabled",
                "container-resources-incomplete",
            },
            patterns,
        )
        resource = [item for item in result["evaluation"]["evidence"] if item["pattern"] == "container-resources-incomplete"]
        self.assertEqual(
            ["request.cpu", "limit.cpu", "request.memory", "limit.memory"],
            resource[0]["missing"],
        )

    def test_pod_level_resources_and_limit_derived_requests_are_recognized(self):
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "pod-budget", "namespace": "prod"},
            "spec": {
                "resources": {
                    "limits": {"cpu": "1", "memory": "512Mi"}
                },
                "containers": [
                    {
                        "name": "api",
                        "securityContext": {"allowPrivilegeEscalation": False},
                    }
                ],
            },
        }
        collector = _collector("kubectl-workloads", {"workloads": _list([pod])})
        result = run_check(WORKLOAD_PACKAGE, _context([collector]))
        self.assertEqual("PASS", result["evaluation"]["status"])

    def test_unavailable_error_missing_and_incomplete_evidence_never_pass(self):
        payloads = {"workloads": _list([_safe_deployment()])}
        fixtures = [
            [],
            [_collector("kubectl-workloads", payloads, status="UNAVAILABLE")],
            [_collector("kubectl-workloads", payloads, status="ERROR")],
        ]
        incomplete = _collector("kubectl-workloads", payloads)
        incomplete["evidence"][0]["data"] = {
            "apiVersion": "v1",
            "kind": "List",
            "items": [{"kind": "Deployment", "metadata": {"name": "broken", "namespace": "prod"}}],
        }
        fixtures.append([incomplete])
        text_payload = _collector("kubectl-workloads", payloads)
        text_payload["evidence"][0]["content_type"] = "text/plain"
        fixtures.append([text_payload])
        for collectors in fixtures:
            with self.subTest(collectors=collectors):
                result = run_check(WORKLOAD_PACKAGE, _context(collectors))
                self.assertEqual("NOT_ASSESSED", result["evaluation"]["status"])
                self.assertNotEqual("PASS", result["evaluation"]["status"])

    def test_check_evidence_does_not_copy_unrelated_collector_payload_values(self):
        deployment = _safe_deployment()
        deployment["spec"]["template"]["spec"]["containers"][0]["env"] = [
            {"name": "TOKEN", "value": "must-not-leak-from-runtime-payload"}
        ]
        collector = _collector("kubectl-workloads", {"workloads": _list([deployment])})
        result = run_check(WORKLOAD_PACKAGE, _context([collector]))
        self.assertEqual("PASS", result["evaluation"]["status"])
        self.assertNotIn("must-not-leak-from-runtime-payload", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
