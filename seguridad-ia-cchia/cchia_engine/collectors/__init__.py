"""Opt-in authenticated read-only collectors for the CCHIA compiler."""

from .base import (
    COLLECTOR_STATUSES,
    CollectorResult,
    CollectorValidationError,
    verify_collector_evidence_hash,
)
from .policy import (
    validate_aws_command,
    validate_azure_command,
    validate_gcloud_command,
    validate_github_command,
    validate_kubectl_command,
)
from .redaction import REDACTED, redact, redact_text
from .registry import available_collectors, collect_requested, collector_names

__all__ = [
    "COLLECTOR_STATUSES",
    "CollectorResult",
    "CollectorValidationError",
    "REDACTED",
    "available_collectors",
    "collect_requested",
    "collector_names",
    "redact",
    "redact_text",
    "validate_aws_command",
    "validate_azure_command",
    "validate_gcloud_command",
    "validate_github_command",
    "validate_kubectl_command",
    "verify_collector_evidence_hash",
]
