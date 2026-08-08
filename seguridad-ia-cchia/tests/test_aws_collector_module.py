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

from cchia_engine.collectors.aws import collect_aws_iam, validate_aws_profile
from cchia_engine.collectors.base import CollectorValidationError, CommandSpec
from cchia_engine.collectors.policy import validate_aws_command


MOCK_AWS = str((Path(tempfile.gettempdir()) / "cchia-aws-test-tools" / "aws.exe").resolve())

EXPECTED = [
    (
        "caller-identity",
        "aws.sts.get-caller-identity.v1",
        ("sts", "get-caller-identity", "--output", "json"),
    ),
    (
        "account-summary",
        "aws.iam.get-account-summary.v1",
        ("iam", "get-account-summary", "--output", "json"),
    ),
    (
        "account-authorization-details",
        "aws.iam.get-account-authorization-details.v1",
        (
            "iam", "get-account-authorization-details", "--filter", "User", "Role", "Group",
            "LocalManagedPolicy", "--output", "json",
        ),
    ),
]


class AwsCollectorModuleTests(unittest.TestCase):
    @patch("cchia_engine.collectors.aws.execute_command_collector")
    def test_exact_command_plan_without_profile(self, execute):
        execute.return_value = {"status": "AVAILABLE"}
        result = collect_aws_iam(target=SKILL_ROOT, options={"timeout_seconds": 17})

        self.assertEqual({"status": "AVAILABLE"}, result)
        kwargs = execute.call_args.kwargs
        self.assertEqual("aws-iam", kwargs["collector_id"])
        self.assertEqual("1.0.0", kwargs["collector_version"])
        self.assertEqual("aws", kwargs["provider"])
        self.assertEqual("AWS CLI", kwargs["sdk_name"])
        self.assertEqual("aws", kwargs["tool"])
        self.assertEqual(17, kwargs["timeout_seconds"])
        specs = kwargs["specs"]
        self.assertEqual(3, len(specs))
        for spec, (command_id, policy_id, tail) in zip(specs, EXPECTED):
            self.assertEqual(CommandSpec(command_id, policy_id, ("aws", *tail)), spec)

    @patch("cchia_engine.collectors.aws.execute_command_collector")
    def test_profile_is_inserted_only_as_rigid_prefix(self, execute):
        execute.return_value = {"status": "AVAILABLE"}
        collect_aws_iam(target=None, options={"aws_profile": "audit-prod", "timeout_seconds": 30})

        for spec, (_command_id, _policy_id, tail) in zip(
            execute.call_args.kwargs["specs"], EXPECTED
        ):
            self.assertEqual(("aws", "--profile", "audit-prod", *tail), spec.argv)
            validate_aws_command(spec.argv, spec.policy_id)

    @patch("cchia_engine.collectors.aws.execute_command_collector")
    def test_invalid_profile_or_timeout_is_rejected_before_execution(self, execute):
        for value in ("--profile", "prod admin", "../prod", "prod/ops", "prod+audit", ""):
            with self.subTest(profile=value):
                with self.assertRaises(CollectorValidationError):
                    collect_aws_iam(target=None, options={"aws_profile": value})
        for timeout in (True, 0, 301, "30"):
            with self.subTest(timeout=timeout):
                with self.assertRaises(CollectorValidationError):
                    collect_aws_iam(target=None, options={"timeout_seconds": timeout})
        execute.assert_not_called()

    def test_policy_rejects_mutating_or_free_form_argv(self):
        with self.assertRaises(CollectorValidationError):
            validate_aws_command(
                ["aws", "iam", "delete-user", "--user-name", "fixture"],
                "aws.iam.get-account-summary.v1",
            )
        with self.assertRaises(CollectorValidationError):
            validate_aws_command(
                ["aws", "--profile", "audit", "iam", "get-account-summary", "--output", "yaml"],
                "aws.iam.get-account-summary.v1",
            )

    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=MOCK_AWS)
    def test_mocked_execution_uses_absolute_binary_neutral_cwd_and_redacts(self, which, run):
        outputs = [
            {
                "UserId": "AROAFIXTURE:session",
                "Account": "123456789012",
                "Arn": "arn:aws:sts::123456789012:assumed-role/fixture/session",
                "Token": "aws-token-must-disappear",
            },
            {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}},
            {
                "IsTruncated": False,
                "UserDetailList": [],
                "RoleDetailList": [],
                "GroupDetailList": [],
                "Policies": [],
            },
        ]
        run.side_effect = [
            subprocess.CompletedProcess([], 0, stdout=json.dumps(output), stderr="")
            for output in outputs
        ]

        result = collect_aws_iam(
            target=SKILL_ROOT,
            options={"aws_profile": "audit-prod", "timeout_seconds": 12},
        )

        self.assertEqual("AVAILABLE", result["status"])
        self.assertEqual("read_only", result["mode"])
        self.assertEqual("aws", result["provenance"]["provider"])
        self.assertEqual(MOCK_AWS, result["provenance"]["interface"]["resolved_executable"])
        self.assertNotIn("aws-token-must-disappear", json.dumps(result))
        self.assertIn("[REDACTED]", json.dumps(result))
        self.assertEqual(3, run.call_count)
        which.assert_called_once_with("aws")
        neutral_directories = set()
        for call in run.call_args_list:
            argv = call.args[0]
            self.assertEqual([MOCK_AWS, "--profile", "audit-prod"], argv[:3])
            self.assertFalse(call.kwargs["shell"])
            self.assertIs(subprocess.DEVNULL, call.kwargs["stdin"])
            self.assertEqual(12, call.kwargs["timeout"])
            self.assertNotIn("env", call.kwargs)
            neutral_cwd = Path(call.kwargs["cwd"])
            self.assertTrue(neutral_cwd.is_absolute())
            self.assertTrue(neutral_cwd.name.startswith("cchia-collector-"))
            neutral_directories.add(neutral_cwd)
            self.assertNotIn("delete-user", argv)
        self.assertEqual(1, len(neutral_directories))
        self.assertTrue(all(not path.exists() for path in neutral_directories))

    @patch("cchia_engine.collectors.executor.subprocess.run")
    @patch("cchia_engine.collectors.executor.shutil.which", return_value=None)
    def test_missing_aws_cli_returns_unavailable_without_process(self, _which, run):
        result = collect_aws_iam(target=None, options={})
        self.assertEqual("UNAVAILABLE", result["status"])
        self.assertFalse(result["provenance"]["interface"]["executable_available"])
        self.assertEqual([], result["evidence"])
        run.assert_not_called()

    def test_single_profile_validator_authority_is_reexported(self):
        self.assertEqual("audit-prod", validate_aws_profile("audit-prod"))
        with self.assertRaises(CollectorValidationError):
            validate_aws_profile("prod+audit")


if __name__ == "__main__":
    unittest.main()
