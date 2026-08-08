from __future__ import annotations

import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.collectors import CollectorResult
from cchia_engine.runtime_context import enrich_context_with_collectors


def _context() -> dict:
    return {"signals": ["repository"], "signal_evidence": {}, "signal_details": {}}


def _collector(collector_id: str, provider: str, tool: str, status: str) -> dict:
    available = status == "AVAILABLE"
    evidence = (
        [{"command_id": "inventory", "status": "AVAILABLE", "content_type": "application/json", "data": {}}]
        if available else []
    )
    return CollectorResult(
        collector_id=collector_id,
        collector_version="1.0.0",
        status=status,
        collected_at="2026-08-08T01:00:00Z",
        provenance={
            "target": None,
            "provider": provider,
            "interface": {
                "kind": "command",
                "tool": tool,
                "sdk": "test client",
                "sdk_version": None,
                "executable_available": available,
                "resolved_executable": f"C:/mock/{tool}.exe" if available else None,
            },
            "commands": [],
        },
        evidence=evidence,
    ).to_dict()


class ProviderRuntimeContextTests(unittest.TestCase):
    def test_available_provider_collectors_activate_requested_and_runtime_signals(self):
        cases = (
            ("aws-iam", "aws", "aws", {"aws", "cloud", "runtime-aws-iam"}),
            (
                "az-role-assignments", "azure", "az",
                {"azure", "cloud", "runtime-azure-role-assignments"},
            ),
            (
                "gh-repo-security", "github", "gh",
                {"github", "repository", "runtime-github-repo-security"},
            ),
        )
        for collector_id, provider, tool, runtime_signals in cases:
            with self.subTest(collector_id=collector_id):
                enriched = enrich_context_with_collectors(
                    _context(), [_collector(collector_id, provider, tool, "AVAILABLE")]
                )
                self.assertIn(f"collector-{collector_id}-requested", enriched["signals"])
                self.assertTrue(runtime_signals.issubset(set(enriched["signals"])))
                for signal in runtime_signals:
                    self.assertEqual("HIGH", enriched["signal_details"][signal]["confidence_label"])

    def test_unavailable_provider_collectors_never_activate_runtime_or_provider(self):
        cases = (
            ("aws-iam", "aws", "aws", {"aws", "cloud", "runtime-aws-iam"}),
            (
                "az-role-assignments", "azure", "az",
                {"azure", "cloud", "runtime-azure-role-assignments"},
            ),
            (
                "gh-repo-security", "github", "gh",
                {"github", "runtime-github-repo-security"},
            ),
        )
        for collector_id, provider, tool, forbidden in cases:
            with self.subTest(collector_id=collector_id):
                enriched = enrich_context_with_collectors(
                    _context(), [_collector(collector_id, provider, tool, "UNAVAILABLE")]
                )
                self.assertIn(f"collector-{collector_id}-requested", enriched["signals"])
                self.assertTrue(forbidden.isdisjoint(set(enriched["signals"])))


if __name__ == "__main__":
    unittest.main()
