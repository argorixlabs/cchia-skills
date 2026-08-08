from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.collectors import (
    CollectorValidationError,
    available_collectors,
    collect_requested,
    validate_gcloud_command,
    validate_kubectl_command,
)
from cchia_engine.cli import main


MOCK_TOOL_ROOT = (Path(tempfile.gettempdir()) / "cchia-test-tools").resolve()
GCLOUD_EXECUTABLE = str(MOCK_TOOL_ROOT / "gcloud.exe")
KUBECTL_EXECUTABLE = str(MOCK_TOOL_ROOT / "kubectl.exe")


class CollectorOptInTests(unittest.TestCase):
    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which")
    def test_empty_request_never_discovers_or_runs_tools(self, which, run):
        self.assertEqual([], collect_requested([], target=SKILL_ROOT))
        which.assert_not_called()
        run.assert_not_called()

    def test_catalog_exposes_only_read_only_collectors(self):
        catalog = available_collectors()
        self.assertEqual(7, len(catalog))
        self.assertEqual(
            {
                "aws-iam",
                "az-role-assignments",
                "gcloud-iam",
                "gh-repo-security",
                "kubectl-cluster",
                "kubectl-rbac",
                "kubectl-workloads",
            },
            {item["id"] for item in catalog},
        )
        self.assertTrue(all(item["mode"] == "read_only" for item in catalog))

    def test_cli_lists_collectors_without_executing_them(self):
        stdout = StringIO()
        with patch("cchia_engine.collectors.executor.subprocess.run") as run, redirect_stdout(stdout):
            self.assertEqual(0, main(["collectors", "--json"]))
        payload = json.loads(stdout.getvalue())
        self.assertEqual(7, len(payload))
        self.assertTrue(all(item["mode"] == "read_only" for item in payload))
        run.assert_not_called()

    @patch("cchia_engine.cli.compile_assessment")
    def test_cli_passes_typed_collector_request_only_when_explicit(self, compile_assessment):
        compile_assessment.return_value = {"output": "out", "plan_only": True}
        stdout = StringIO()
        with redirect_stdout(stdout):
            status = main(
                [
                    "compile",
                    "--target", str(SKILL_ROOT),
                    "--output", "out",
                    "--plan-only",
                    "--collector", "gcloud-iam",
                    "--gcp-project", "demo-project",
                    "--collector-timeout", "20",
                ]
            )
        self.assertEqual(0, status)
        kwargs = compile_assessment.call_args.kwargs
        self.assertEqual(["gcloud-iam"], kwargs["collector_names"])
        self.assertEqual("demo-project", kwargs["collector_options"]["gcp_project"])
        self.assertEqual(20, kwargs["collector_options"]["timeout_seconds"])

    @patch("cchia_engine.cli.compile_assessment")
    def test_cli_wires_aws_azure_and_github_typed_options(self, compile_assessment):
        compile_assessment.return_value = {"output": "out", "plan_only": True}
        with redirect_stdout(StringIO()):
            status = main(
                [
                    "compile",
                    "--target", str(SKILL_ROOT),
                    "--output", "out",
                    "--plan-only",
                    "--collector", "aws-iam",
                    "--collector", "az-role-assignments",
                    "--collector", "gh-repo-security",
                    "--aws-profile", "audit-prod",
                    "--azure-subscription", "audit-subscription",
                    "--github-repo", "acme/platform",
                ]
            )
        self.assertEqual(0, status)
        kwargs = compile_assessment.call_args.kwargs
        self.assertEqual(
            ["aws-iam", "az-role-assignments", "gh-repo-security"],
            kwargs["collector_names"],
        )
        self.assertEqual("audit-prod", kwargs["collector_options"]["aws_profile"])
        self.assertEqual("audit-subscription", kwargs["collector_options"]["azure_subscription"])
        self.assertEqual("acme/platform", kwargs["collector_options"]["github_repo"])


class GcloudCollectorTests(unittest.TestCase):
    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=GCLOUD_EXECUTABLE)
    def test_gcloud_iam_uses_absolute_executable_neutral_cwd_and_redacts(self, which, run):
        outputs = [
            {"projectId": "demo-project", "accessToken": "gcp-token-must-disappear"},
            {"bindings": [{"role": "roles/viewer", "members": ["user:a@example.com"]}]},
            [{"email": "runtime@demo-project.iam.gserviceaccount.com", "password": "must-disappear"}],
        ]
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=json.dumps(output), stderr="") for output in outputs
        ]

        [result] = collect_requested(
            ["gcloud-iam"],
            target=SKILL_ROOT,
            options={"gcp_project": "demo-project", "timeout_seconds": 15},
        )

        self.assertEqual("read_only", result["mode"])
        self.assertEqual("AVAILABLE", result["status"])
        self.assertEqual("command", result["provenance"]["interface"]["kind"])
        self.assertEqual("Google Cloud CLI", result["provenance"]["interface"]["sdk"])
        self.assertEqual(GCLOUD_EXECUTABLE, result["provenance"]["interface"]["resolved_executable"])
        self.assertEqual(64, len(result["evidence_sha256"]))
        serialized = json.dumps(result)
        self.assertNotIn("gcp-token-must-disappear", serialized)
        self.assertNotIn("must-disappear", serialized)
        self.assertIn("[REDACTED]", serialized)
        which.assert_called_once_with("gcloud")
        self.assertEqual(3, run.call_count)
        neutral_directories = set()
        for call in run.call_args_list:
            argv = call.args[0]
            self.assertEqual(GCLOUD_EXECUTABLE, argv[0])
            self.assertTrue(Path(argv[0]).is_absolute())
            self.assertFalse(call.kwargs["shell"])
            self.assertIs(subprocess.DEVNULL, call.kwargs["stdin"])
            self.assertEqual(15, call.kwargs["timeout"])
            self.assertNotIn("env", call.kwargs, "El entorno configurado debe heredarse")
            neutral_cwd = Path(call.kwargs["cwd"])
            self.assertTrue(neutral_cwd.is_absolute())
            self.assertTrue(neutral_cwd.name.startswith("cchia-collector-"))
            self.assertNotEqual(SKILL_ROOT.resolve(), neutral_cwd)
            neutral_directories.add(neutral_cwd)
            self.assertNotIn("delete", argv)
            self.assertNotIn("set-iam-policy", argv)
        self.assertEqual(1, len(neutral_directories))
        self.assertTrue(all(not path.exists() for path in neutral_directories))

    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=None)
    def test_missing_gcloud_returns_unavailable_without_process(self, _which, run):
        [result] = collect_requested(
            ["gcloud-iam"], options={"gcp_project": "demo-project"}
        )
        self.assertEqual("UNAVAILABLE", result["status"])
        self.assertFalse(result["provenance"]["interface"]["executable_available"])
        self.assertIsNone(result["provenance"]["interface"]["resolved_executable"])
        self.assertEqual([], result["evidence"])
        run.assert_not_called()


class KubernetesCollectorTests(unittest.TestCase):
    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=KUBECTL_EXECUTABLE)
    def test_kubectl_collectors_use_absolute_binary_neutral_cwd_and_redact(self, which, run):
        workload = {
            "items": [
                {
                    "kind": "Pod",
                    "spec": {
                        "containers": [
                            {
                                "name": "api",
                                "env": [
                                    {"name": "DB_PASSWORD", "value": "k8s-secret-must-disappear"},
                                    {"name": "LOG_LEVEL", "value": "info"},
                                ],
                            }
                        ]
                    },
                }
            ]
        }

        def process(argv, **_kwargs):
            payload = workload if "deployments,statefulsets,daemonsets,replicasets,cronjobs,jobs,pods" in argv else {"items": []}
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(payload), stderr="")

        run.side_effect = process
        results = collect_requested(
            ["kubectl-cluster", "kubectl-rbac", "kubectl-workloads"],
            options={"kube_context": "audit@cluster", "kube_namespace": "prod"},
        )

        self.assertEqual(3, len(results))
        self.assertTrue(all(item["status"] == "AVAILABLE" for item in results))
        self.assertEqual(5, run.call_count)
        serialized = json.dumps(results)
        self.assertNotIn("k8s-secret-must-disappear", serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertIn("info", serialized)
        self.assertEqual(3, which.call_count)
        self.assertTrue(all(item["provenance"]["interface"]["resolved_executable"] == KUBECTL_EXECUTABLE for item in results))
        neutral_directories = set()
        for call in run.call_args_list:
            argv = call.args[0]
            self.assertEqual([KUBECTL_EXECUTABLE, "--context", "audit@cluster"], argv[:3])
            self.assertTrue(Path(argv[0]).is_absolute())
            self.assertFalse(call.kwargs["shell"])
            self.assertIs(subprocess.DEVNULL, call.kwargs["stdin"])
            self.assertNotIn("env", call.kwargs, "El entorno configurado debe heredarse")
            neutral_cwd = Path(call.kwargs["cwd"])
            self.assertTrue(neutral_cwd.is_absolute())
            self.assertTrue(neutral_cwd.name.startswith("cchia-collector-"))
            neutral_directories.add(neutral_cwd)
            self.assertNotIn("apply", argv)
            self.assertNotIn("delete", argv)
            self.assertNotIn("patch", argv)
            self.assertNotIn("secrets", argv)
        self.assertEqual(3, len(neutral_directories))
        self.assertTrue(all(not path.exists() for path in neutral_directories))

    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=KUBECTL_EXECUTABLE)
    def test_command_error_is_redacted_and_reported(self, _which, run):
        run.return_value = subprocess.CompletedProcess(
            [], 1, stdout="", stderr="Authorization: Bearer runtime-token-must-disappear"
        )
        [result] = collect_requested(["kubectl-workloads"])
        self.assertEqual("ERROR", result["status"])
        serialized = json.dumps(result)
        self.assertNotIn("runtime-token-must-disappear", serialized)
        self.assertIn("[REDACTED]", serialized)


class CollectorSafetyPolicyTests(unittest.TestCase):
    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=GCLOUD_EXECUTABLE)
    def test_oversized_json_output_is_discarded_and_never_passes(self, _which, run):
        marker = "CCHIA_OVERSIZED_SECRET_MUST_NOT_PERSIST"
        oversized = json.dumps({"items": [marker + ("x" * (4 * 1024 * 1024))]})
        run.return_value = subprocess.CompletedProcess([], 0, stdout=oversized, stderr="")

        [result] = collect_requested(
            ["gcloud-iam"], options={"gcp_project": "demo-project"}
        )

        self.assertEqual("ERROR", result["status"])
        self.assertTrue(all(item["status"] == "ERROR" for item in result["evidence"]))
        self.assertTrue(all(item["data"]["output_limit_exceeded"] for item in result["evidence"]))
        self.assertTrue(all(
            item.get("error_type") == "OUTPUT_LIMIT"
            for item in result["provenance"]["commands"]
        ))
        self.assertNotIn(marker, json.dumps(result))

    @patch("cchia_engine.collectors.executor.subprocess.run")
    def test_free_form_or_mutating_options_are_rejected_before_process(self, run):
        with self.assertRaises(CollectorValidationError):
            collect_requested(
                ["gcloud-iam"],
                options={"gcp_project": "demo-project", "args": ["projects", "delete", "demo-project"]},
            )
        with self.assertRaises(CollectorValidationError):
            collect_requested(
                ["kubectl-workloads"], options={"kube_context": "prod --as=cluster-admin"}
            )
        run.assert_not_called()

    def test_allow_list_rejects_mutating_argv(self):
        with self.assertRaises(CollectorValidationError):
            validate_gcloud_command(
                ["gcloud", "projects", "delete", "demo-project", "--quiet"],
                "gcloud.projects.describe.v1",
            )
        with self.assertRaises(CollectorValidationError):
            validate_kubectl_command(
                ["kubectl", "delete", "pod", "api"], "kubectl.workloads.v1"
            )
        with self.assertRaises(CollectorValidationError):
            validate_kubectl_command(
                ["kubectl", "get", "secrets", "--all-namespaces", "-o", "json"],
                "kubectl.workloads.v1",
            )

    def test_result_and_request_schemas_declare_required_safety_contract(self):
        result_schema = json.loads(
            (SKILL_ROOT / "schemas" / "collector-result.schema.json").read_text(encoding="utf-8")
        )
        request_schema = json.loads(
            (SKILL_ROOT / "schemas" / "collector-request.schema.json").read_text(encoding="utf-8")
        )
        self.assertIn("mode", result_schema["required"])
        self.assertIn("provenance", result_schema["required"])
        self.assertIn("redaction", result_schema["required"])
        self.assertEqual("read_only", result_schema["properties"]["mode"]["const"])
        interface = result_schema["properties"]["provenance"]["properties"]["interface"]
        self.assertIn("resolved_executable", interface["required"])
        self.assertFalse(request_schema["additionalProperties"])
        self.assertFalse(request_schema["properties"]["options"]["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
