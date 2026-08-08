from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.collectors import (
    CollectorValidationError,
    validate_aws_command,
    validate_azure_command,
    validate_github_command,
)


class ProviderAllowListTests(unittest.TestCase):
    def test_aws_accepts_only_exact_read_only_inventory_commands(self):
        validate_aws_command(
            ["aws", "--profile", "audit-prod", "sts", "get-caller-identity", "--output", "json"],
            "aws.sts.get-caller-identity.v1",
        )
        validate_aws_command(
            [
                "aws", "iam", "get-account-authorization-details", "--filter",
                "User", "Role", "Group", "LocalManagedPolicy", "--output", "json",
            ],
            "aws.iam.get-account-authorization-details.v1",
        )
        with self.assertRaises(CollectorValidationError):
            validate_aws_command(
                ["aws", "iam", "attach-role-policy", "--role-name", "admin"],
                "aws.iam.get-account-summary.v1",
            )
        with self.assertRaises(CollectorValidationError):
            validate_aws_command(
                ["aws", "--profile", "prod --no-sign-request", "sts", "get-caller-identity", "--output", "json"],
                "aws.sts.get-caller-identity.v1",
            )

    def test_azure_accepts_only_account_and_role_assignment_reads(self):
        validate_azure_command(
            ["az", "account", "show", "--subscription", "00000000-0000-0000-0000-000000000000", "--output", "json"],
            "az.account.show.v1",
        )
        validate_azure_command(
            ["az", "role", "assignment", "list", "--all", "--output", "json"],
            "az.role.assignment.list.v1",
        )
        with self.assertRaises(CollectorValidationError):
            validate_azure_command(
                ["az", "role", "assignment", "create", "--role", "Owner"],
                "az.role.assignment.list.v1",
            )
        with self.assertRaises(CollectorValidationError):
            validate_azure_command(
                ["az", "account", "show", "--subscription", "--all", "--output", "json"],
                "az.account.show.v1",
            )

    def test_github_accepts_only_fixed_get_surfaces_and_headers(self):
        headers = [
            "-H", "Accept: application/vnd.github+json",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
        ]
        validate_github_command(
            ["gh", "api", "repos/acme/platform/rulesets", *headers],
            "gh.api.repo.rulesets.v1",
        )
        validate_github_command(
            [
                "gh", "repo", "view", "acme/platform", "--json",
                "nameWithOwner,defaultBranchRef,visibility,isArchived",
            ],
            "gh.repo.view.v1",
        )
        with self.assertRaises(CollectorValidationError):
            validate_github_command(
                ["gh", "api", "repos/acme/platform/rulesets", "--method", "POST"],
                "gh.api.repo.rulesets.v1",
            )
        with self.assertRaises(CollectorValidationError):
            validate_github_command(
                ["gh", "api", "repos/acme/platform/hooks", *headers],
                "gh.api.repo.rulesets.v1",
            )
        with self.assertRaises(CollectorValidationError):
            validate_github_command(
                [
                    "gh", "repo", "view", "acme/.", "--json",
                    "nameWithOwner,defaultBranchRef,visibility,isArchived",
                ],
                "gh.repo.view.v1",
            )

    def test_schemas_enumerate_all_provider_collectors_and_typed_options(self):
        request = json.loads((SKILL_ROOT / "schemas" / "collector-request.schema.json").read_text(encoding="utf-8"))
        result = json.loads((SKILL_ROOT / "schemas" / "collector-result.schema.json").read_text(encoding="utf-8"))
        expected = {
            "aws-iam", "az-role-assignments", "gcloud-iam", "gh-repo-security",
            "kubectl-cluster", "kubectl-rbac", "kubectl-workloads",
        }
        self.assertEqual(expected, set(request["properties"]["collectors"]["items"]["enum"]))
        self.assertEqual(expected, set(result["properties"]["collector_id"]["enum"]))
        self.assertTrue({"aws_profile", "azure_subscription", "github_repo"}.issubset(
            request["properties"]["options"]["properties"]
        ))


if __name__ == "__main__":
    unittest.main()
