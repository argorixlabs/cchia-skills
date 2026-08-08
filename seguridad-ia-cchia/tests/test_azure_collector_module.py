from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.collectors.azure import collect_azure_role_assignments
from cchia_engine.collectors.base import CollectorValidationError, CommandSpec
from cchia_engine.collectors.policy import (
    validate_azure_command,
    validate_azure_subscription,
)


MOCK_AZ = str((Path(tempfile.gettempdir()) / "cchia-azure-test-tools" / "az.exe").resolve())


class AzureCollectorModuleTests(unittest.TestCase):
    @patch("cchia_engine.collectors.azure.execute_command_collector")
    def test_exact_command_plan_without_subscription(self, execute):
        execute.return_value = {"status": "AVAILABLE"}

        result = collect_azure_role_assignments(
            target=SKILL_ROOT, options={"timeout_seconds": 17}
        )

        self.assertEqual({"status": "AVAILABLE"}, result)
        kwargs = execute.call_args.kwargs
        self.assertEqual("az-role-assignments", kwargs["collector_id"])
        self.assertEqual("1.0.0", kwargs["collector_version"])
        self.assertEqual("azure", kwargs["provider"])
        self.assertEqual("Azure CLI", kwargs["sdk_name"])
        self.assertEqual("az", kwargs["tool"])
        self.assertEqual(17, kwargs["timeout_seconds"])
        self.assertEqual(
            [
                CommandSpec(
                    "azure-account",
                    "az.account.show.v1",
                    ("az", "account", "show", "--output", "json"),
                ),
                CommandSpec(
                    "role-assignments",
                    "az.role.assignment.list.v1",
                    (
                        "az", "role", "assignment", "list", "--all",
                        "--output", "json",
                    ),
                ),
            ],
            kwargs["specs"],
        )

    @patch("cchia_engine.collectors.azure.execute_command_collector")
    def test_subscription_is_inserted_only_in_rigid_position(self, execute):
        execute.return_value = {"status": "AVAILABLE"}

        collect_azure_role_assignments(
            target=None,
            options={"azure_subscription": "fixture-audit", "timeout_seconds": 30},
        )

        specs = execute.call_args.kwargs["specs"]
        self.assertEqual(
            (
                "az", "account", "show", "--subscription", "fixture-audit",
                "--output", "json",
            ),
            specs[0].argv,
        )
        self.assertEqual(
            (
                "az", "role", "assignment", "list", "--all", "--subscription",
                "fixture-audit", "--output", "json",
            ),
            specs[1].argv,
        )
        for spec in specs:
            validate_azure_command(spec.argv, spec.policy_id)

    @patch("cchia_engine.collectors.azure.execute_command_collector")
    def test_invalid_subscription_or_timeout_is_rejected_before_execution(self, execute):
        for value in ("--subscription", "../prod", "prod/ops", "prod;delete", "", "prod\nadmin"):
            with self.subTest(subscription=value):
                with self.assertRaises(CollectorValidationError):
                    collect_azure_role_assignments(
                        target=None, options={"azure_subscription": value}
                    )
        for timeout in (True, 0, 301, "30"):
            with self.subTest(timeout=timeout):
                with self.assertRaises(CollectorValidationError):
                    collect_azure_role_assignments(
                        target=None, options={"timeout_seconds": timeout}
                    )
        execute.assert_not_called()

    def test_policy_rejects_mutating_or_free_form_argv(self):
        with self.assertRaises(CollectorValidationError):
            validate_azure_command(
                ["az", "role", "assignment", "delete", "--assignee", "fixture"],
                "az.role.assignment.list.v1",
            )
        with self.assertRaises(CollectorValidationError):
            validate_azure_command(
                ["az", "account", "show", "--output", "yaml"],
                "az.account.show.v1",
            )

    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=MOCK_AZ)
    def test_mocked_execution_uses_shared_safe_boundary_and_redacts(self, which, run):
        outputs = [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "tenantId": "22222222-2222-2222-2222-222222222222",
                "accessToken": "azure-token-must-disappear",
            },
            [
                {
                    "roleDefinitionName": "Reader",
                    "principalName": "fixture-reader@example.invalid",
                    "password": "azure-password-must-disappear",
                }
            ],
        ]
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=json.dumps(output), stderr="")
            for output in outputs
        ]

        result = collect_azure_role_assignments(
            target=SKILL_ROOT,
            options={"azure_subscription": "fixture-audit", "timeout_seconds": 12},
        )

        self.assertEqual("AVAILABLE", result["status"])
        self.assertEqual("read_only", result["mode"])
        self.assertEqual("azure", result["provenance"]["provider"])
        self.assertEqual(MOCK_AZ, result["provenance"]["interface"]["resolved_executable"])
        serialized = json.dumps(result)
        self.assertNotIn("azure-token-must-disappear", serialized)
        self.assertNotIn("azure-password-must-disappear", serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertEqual(2, run.call_count)
        which.assert_called_once_with("az")
        neutral_directories = set()
        for call in run.call_args_list:
            argv = call.args[0]
            self.assertEqual(MOCK_AZ, argv[0])
            self.assertIn("--subscription", argv)
            self.assertIn("fixture-audit", argv)
            self.assertFalse(call.kwargs["shell"])
            self.assertIs(subprocess.DEVNULL, call.kwargs["stdin"])
            self.assertEqual(12, call.kwargs["timeout"])
            self.assertNotIn("env", call.kwargs)
            neutral_cwd = Path(call.kwargs["cwd"])
            self.assertTrue(neutral_cwd.is_absolute())
            self.assertTrue(neutral_cwd.name.startswith("cchia-collector-"))
            neutral_directories.add(neutral_cwd)
            self.assertNotIn("delete", argv)
        self.assertEqual(1, len(neutral_directories))
        self.assertTrue(all(not path.exists() for path in neutral_directories))

    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=None)
    def test_missing_azure_cli_returns_unavailable_without_process(self, _which, run):
        result = collect_azure_role_assignments(target=None, options={})

        self.assertEqual("UNAVAILABLE", result["status"])
        self.assertFalse(result["provenance"]["interface"]["executable_available"])
        self.assertIsNone(result["provenance"]["interface"]["resolved_executable"])
        self.assertEqual([], result["evidence"])
        run.assert_not_called()

    def test_subscription_validator_has_one_central_authority(self):
        self.assertEqual("fixture-audit", validate_azure_subscription("fixture-audit"))
        with self.assertRaises(CollectorValidationError):
            validate_azure_subscription("prod/ops")


if __name__ == "__main__":
    unittest.main()
