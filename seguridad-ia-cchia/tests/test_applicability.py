from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = SKILL_ROOT.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.context import (
    build_context,
    collection_allows_pass,
    infer_signal_details,
    infer_signals,
    load_system,
    safeguard_pass_for_collection,
)


class ApplicabilityV2Tests(unittest.TestCase):
    def test_product_spec_provider_roadmap_does_not_activate_cloud_providers(self):
        system = load_system(PROJECT_ROOT / "docs" / "product-spec.md")

        signals, _ = infer_signals([], system)
        details = infer_signal_details([], system)

        self.assertNotIn("aws", signals)
        self.assertNotIn("azure", signals)
        self.assertNotIn("gcp", signals)
        self.assertNotIn("cloud", signals)
        for provider in ("aws", "azure", "gcp"):
            self.assertIn(provider, details)
            self.assertFalse(details[provider]["active"])
            self.assertEqual("LOW", details[provider]["confidence_label"])
            self.assertTrue(details[provider]["evidence"])
            self.assertTrue(all(not item["supports_activation"] for item in details[provider]["evidence"]))

    def test_explicit_usage_and_structured_provider_activate_with_provenance(self):
        narrative = {"description": "The production service is deployed on GCP."}
        structured = {"components": [{"name": "api", "cloud_provider": "Azure"}]}

        narrative_details = infer_signal_details([], narrative)
        structured_details = infer_signal_details([], structured)

        self.assertTrue(narrative_details["gcp"]["active"])
        self.assertGreaterEqual(narrative_details["gcp"]["confidence"], 0.8)
        self.assertEqual("usage-context", narrative_details["gcp"]["evidence"][0]["provenance"]["method"])
        self.assertTrue(structured_details["azure"]["active"])
        self.assertEqual("provider-field", structured_details["azure"]["evidence"][0]["provenance"]["method"])
        self.assertTrue(structured_details["cloud"]["active"])

    def test_explicit_signals_remain_backward_compatible(self):
        signals, evidence = infer_signals([], {"signals": ["GCP", "CUSTOM-SURFACE"]})

        self.assertEqual(["custom-surface", "gcp"], signals)
        self.assertEqual(["system.signals"], evidence["gcp"])
        self.assertEqual(["system.signals"], evidence["custom-surface"])


class CollectionCoverageTests(unittest.TestCase):
    def test_max_files_marks_collection_incomplete_and_preserves_repository_applicability(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            (target / "a.py").write_text("print('a')\n", encoding="utf-8")
            (target / "b.py").write_text("print('b')\n", encoding="utf-8")

            context = build_context(target, {}, max_files=1, max_file_bytes=1_000)

        collection = context["collection"]
        self.assertFalse(collection["complete"])
        self.assertTrue(collection["truncated"])
        self.assertFalse(collection["pass_eligible"])
        self.assertEqual(1, collection["file_count"])
        self.assertEqual(1, collection["skipped_file_limit"])
        self.assertIn("max_files", collection["incomplete_reasons"])
        self.assertIn("repository", context["signals"])

    def test_max_file_bytes_marks_collection_incomplete_even_when_no_file_is_read(self):
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp)
            (target / "large.py").write_text("x" * 50, encoding="utf-8")

            context = build_context(target, {}, max_files=10, max_file_bytes=10)

        collection = context["collection"]
        self.assertFalse(collection["complete"])
        self.assertTrue(collection["truncated"])
        self.assertEqual(0, collection["file_count"])
        self.assertEqual(1, collection["skipped_too_large"])
        self.assertIn("max_file_bytes", collection["incomplete_reasons"])
        self.assertIn("repository", context["signals"])

    def test_pass_is_not_preserved_when_collection_is_incomplete(self):
        evaluation = {
            "status": "PASS",
            "confidence": "HIGH",
            "evidence_level": "E3",
            "summary": "No se observaron hallazgos.",
            "evidence": [],
            "recommendation": "Mantener el control.",
        }
        context = {"collection": {"complete": False, "incomplete_reasons": ["max_files"]}}

        protected = safeguard_pass_for_collection(evaluation, context)

        self.assertEqual("PASS", evaluation["status"])
        self.assertEqual("NOT_ASSESSED", protected["status"])
        self.assertEqual("LOW", protected["confidence"])
        self.assertEqual("E0", protected["evidence_level"])
        self.assertFalse(collection_allows_pass(context))
        self.assertIn("Cobertura de recolección incompleta", protected["summary"])

    def test_complete_collection_preserves_pass(self):
        evaluation = {"status": "PASS"}
        context = {"collection": {"complete": True}}

        self.assertIs(evaluation, safeguard_pass_for_collection(evaluation, context))
        self.assertTrue(collection_allows_pass(context))


if __name__ == "__main__":
    unittest.main()
