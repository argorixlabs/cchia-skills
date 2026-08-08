from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.runtime_context import enrich_context_with_collectors


def _result(collector_id: str, status: str = "AVAILABLE", digest: str = "a" * 64) -> dict:
    return {
        "collector_id": collector_id,
        "status": status,
        "evidence_sha256": digest,
        "provenance": {
            "provider": "gcp" if collector_id == "gcloud-iam" else "kubernetes",
            "interface": {"kind": "command"},
        },
        "evidence": [{"command_id": "inventory"}] if status == "AVAILABLE" else [],
    }


def _base_context() -> dict:
    repository_evidence = {
        "source": "target contiene archivos",
        "kind": "collected_artifact",
        "confidence": 1.0,
        "supports_activation": True,
        "provenance": {"origin": "target", "method": "collection"},
    }
    return {
        "schema_version": "1.1",
        "signals": ["repository"],
        "signal_evidence": {"repository": ["target contiene archivos"]},
        "signal_details": {
            "repository": {
                "active": True,
                "confidence": 1.0,
                "confidence_label": "HIGH",
                "evidence": [repository_evidence],
            }
        },
        "files": [{"path": "app.py", "content": "print('ok')"}],
        "system": {"name": "demo", "components": [{"name": "api"}]},
        "collection": {"mode": "read_only", "complete": True},
        "target": {"path": "C:/demo", "fingerprint": "0" * 64},
    }


class RuntimeCollectorContextTests(unittest.TestCase):
    def test_structural_copy_shares_large_read_only_sections_and_isolates_edited_containers(self):
        context = _base_context()
        collectors = [_result("gcloud-iam")]

        enriched = enrich_context_with_collectors(context, collectors)

        self.assertIsNot(enriched, context)
        for shared_key in ("files", "system", "collection", "target"):
            self.assertIs(
                context[shared_key],
                enriched[shared_key],
                f"{shared_key} debe compartirse sin duplicar contenido",
            )
        self.assertIsNot(context["signals"], enriched["signals"])
        self.assertIsNot(context["signal_evidence"], enriched["signal_evidence"])
        self.assertIsNot(context["signal_details"], enriched["signal_details"])
        self.assertIsNot(collectors, enriched["collectors"])
        self.assertIsNot(collectors[0], enriched["collectors"][0])

        enriched["signals"].append("test-only")
        enriched["signal_evidence"]["repository"].append("test source")
        enriched["signal_details"]["repository"]["evidence"].append({"source": "test"})
        enriched["collectors"][0]["provenance"]["provider"] = "changed"

        self.assertNotIn("test-only", context["signals"])
        self.assertNotIn("test source", context["signal_evidence"]["repository"])
        self.assertNotIn({"source": "test"}, context["signal_details"]["repository"]["evidence"])
        self.assertEqual("gcp", collectors[0]["provenance"]["provider"])

    def test_available_gcloud_adds_request_provider_and_runtime_signals(self):
        context = _base_context()
        collectors = [_result("gcloud-iam")]
        context_before = copy.deepcopy(context)
        collectors_before = copy.deepcopy(collectors)

        enriched = enrich_context_with_collectors(context, collectors)

        self.assertEqual(context_before, context)
        self.assertEqual(collectors_before, collectors)
        self.assertIsNot(enriched, context)
        self.assertEqual(context_before["signal_details"]["repository"], enriched["signal_details"]["repository"])
        expected = {
            "repository",
            "collector-gcloud-iam-requested",
            "gcp",
            "cloud",
            "runtime-gcp-iam",
        }
        self.assertEqual(expected, set(enriched["signals"]))

        requested = enriched["signal_details"]["collector-gcloud-iam-requested"]
        self.assertTrue(requested["active"])
        self.assertEqual(1.0, requested["confidence"])
        self.assertEqual("collector_request", requested["evidence"][0]["kind"])
        self.assertEqual("AVAILABLE", requested["evidence"][0]["provenance"]["status"])

        for signal in ("gcp", "cloud", "runtime-gcp-iam"):
            detail = enriched["signal_details"][signal]
            self.assertTrue(detail["active"])
            self.assertEqual(0.95, detail["confidence"])
            self.assertEqual("HIGH", detail["confidence_label"])
            item = detail["evidence"][0]
            self.assertTrue(item["supports_activation"])
            self.assertEqual("runtime_collector_evidence", item["kind"])
            self.assertEqual("gcloud-iam", item["provenance"]["collector_id"])
            self.assertEqual("AVAILABLE", item["provenance"]["status"])
            self.assertEqual("a" * 64, item["provenance"]["evidence_sha256"])

        self.assertEqual(collectors, enriched["collectors"])
        self.assertIsNot(collectors[0], enriched["collectors"][0])

    def test_available_kubectl_collectors_deduplicate_kubernetes_and_keep_each_source(self):
        collectors = [
            _result("kubectl-cluster", digest="b" * 64),
            _result("kubectl-rbac", digest="c" * 64),
            _result("kubectl-workloads", digest="d" * 64),
        ]

        enriched = enrich_context_with_collectors(_base_context(), collectors)

        self.assertEqual(1, enriched["signals"].count("kubernetes"))
        self.assertTrue(
            {
                "collector-kubectl-cluster-requested",
                "collector-kubectl-rbac-requested",
                "collector-kubectl-workloads-requested",
                "runtime-kubernetes",
                "runtime-k8s-rbac",
                "runtime-k8s-workloads",
            }.issubset(enriched["signals"])
        )
        kubernetes_evidence = enriched["signal_details"]["kubernetes"]["evidence"]
        self.assertEqual(3, len(kubernetes_evidence))
        self.assertEqual(
            {"kubectl-cluster", "kubectl-rbac", "kubectl-workloads"},
            {item["provenance"]["collector_id"] for item in kubernetes_evidence},
        )
        self.assertEqual(3, len(enriched["signal_evidence"]["kubernetes"]))

    def test_unavailable_and_error_activate_only_requested_signals_with_visible_provenance(self):
        collectors = [
            _result("gcloud-iam", "UNAVAILABLE", "e" * 64),
            _result("kubectl-rbac", "ERROR", "f" * 64),
        ]

        enriched = enrich_context_with_collectors(_base_context(), collectors)

        self.assertIn("collector-gcloud-iam-requested", enriched["signals"])
        self.assertIn("collector-kubectl-rbac-requested", enriched["signals"])
        for forbidden in ("gcp", "cloud", "runtime-gcp-iam", "kubernetes", "runtime-k8s-rbac"):
            self.assertNotIn(forbidden, enriched["signals"])
            self.assertNotIn(forbidden, enriched["signal_details"])
        self.assertEqual(collectors, enriched["collectors"])
        self.assertEqual(
            "UNAVAILABLE",
            enriched["signal_details"]["collector-gcloud-iam-requested"]["evidence"][0]["provenance"]["status"],
        )
        self.assertEqual(
            "ERROR",
            enriched["signal_details"]["collector-kubectl-rbac-requested"]["evidence"][0]["provenance"]["status"],
        )

    def test_existing_documentary_signal_is_upgraded_without_losing_its_evidence(self):
        context = _base_context()
        mention = {
            "source": "system.description",
            "kind": "documentary_mention",
            "confidence": 0.2,
            "supports_activation": False,
            "provenance": {"origin": "system", "method": "mention-only"},
        }
        context["signal_details"]["gcp"] = {
            "active": False,
            "confidence": 0.2,
            "confidence_label": "LOW",
            "evidence": [mention],
        }

        enriched = enrich_context_with_collectors(context, [_result("gcloud-iam")])

        detail = enriched["signal_details"]["gcp"]
        self.assertTrue(detail["active"])
        self.assertEqual(0.95, detail["confidence"])
        self.assertEqual("HIGH", detail["confidence_label"])
        self.assertEqual(2, len(detail["evidence"]))
        self.assertEqual(mention, detail["evidence"][0])
        self.assertFalse(context["signal_details"]["gcp"]["active"])

    def test_available_without_valid_evidence_hash_adds_request_but_not_runtime(self):
        enriched = enrich_context_with_collectors(
            _base_context(), [_result("kubectl-workloads", "AVAILABLE", "not-a-sha256")]
        )

        self.assertIn("collector-kubectl-workloads-requested", enriched["signals"])
        self.assertNotIn("kubernetes", enriched["signals"])
        self.assertNotIn("runtime-k8s-workloads", enriched["signals"])

    def test_repeated_enrichment_does_not_duplicate_signal_evidence(self):
        collector = _result("kubectl-cluster")
        once = enrich_context_with_collectors(_base_context(), [collector])
        twice = enrich_context_with_collectors(once, [collector])

        self.assertEqual(1, twice["signals"].count("kubernetes"))
        self.assertEqual(1, len(twice["signal_details"]["kubernetes"]["evidence"]))
        self.assertEqual(1, len(twice["signal_evidence"]["kubernetes"]))
        self.assertEqual(
            1,
            len(twice["signal_details"]["collector-kubectl-cluster-requested"]["evidence"]),
        )


if __name__ == "__main__":
    unittest.main()
