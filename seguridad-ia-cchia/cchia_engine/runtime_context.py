"""Pure enrichment of selector-v2 context from collector results.

Collector presence and runtime availability are deliberately different facts:
a requested collector can select a control that later returns NOT_ASSESSED,
while only AVAILABLE evidence may activate runtime/provider assertions.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from copy import deepcopy
from typing import Any


RUNTIME_CONFIDENCE = 0.95
REQUEST_CONFIDENCE = 1.0
_SHA256 = re.compile(r"^[a-f0-9]{64}$")

_RUNTIME_SIGNALS: dict[str, tuple[str, ...]] = {
    "aws-iam": ("aws", "cloud", "runtime-aws-iam"),
    "az-role-assignments": ("azure", "cloud", "runtime-azure-role-assignments"),
    "gcloud-iam": ("gcp", "cloud", "runtime-gcp-iam"),
    "gh-repo-security": ("github", "repository", "runtime-github-repo-security"),
    "kubectl-cluster": ("kubernetes", "runtime-kubernetes"),
    "kubectl-rbac": ("kubernetes", "runtime-k8s-rbac"),
    "kubectl-workloads": ("kubernetes", "runtime-k8s-workloads"),
}
_REQUEST_SIGNALS = {
    collector_id: f"collector-{collector_id}-requested"
    for collector_id in _RUNTIME_SIGNALS
}


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.85:
        return "HIGH"
    if confidence >= 0.65:
        return "MEDIUM"
    return "LOW"


def _numeric_confidence(value: object) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0.0, min(1.0, float(value)))
    return 0.0


def _source_provenance(result: Mapping[str, Any], *, method: str) -> dict[str, Any]:
    return {
        "origin": "collector",
        "collector_id": str(result.get("collector_id", "")),
        "status": str(result.get("status", "")),
        "evidence_sha256": result.get("evidence_sha256"),
        "method": method,
    }


def _add_signal(
    context: dict[str, Any],
    signal: str,
    *,
    source: str,
    kind: str,
    confidence: float,
    provenance: dict[str, Any],
) -> None:
    signals = context.setdefault("signals", [])
    if not isinstance(signals, list):
        signals = list(signals) if isinstance(signals, (tuple, set)) else []
        context["signals"] = signals
    if signal not in signals:
        signals.append(signal)

    signal_evidence = context.setdefault("signal_evidence", {})
    if not isinstance(signal_evidence, dict):
        signal_evidence = {}
        context["signal_evidence"] = signal_evidence
    sources = signal_evidence.setdefault(signal, [])
    if not isinstance(sources, list):
        sources = [str(sources)]
        signal_evidence[signal] = sources
    if source not in sources:
        sources.append(source)

    signal_details = context.setdefault("signal_details", {})
    if not isinstance(signal_details, dict):
        signal_details = {}
        context["signal_details"] = signal_details
    current = signal_details.get(signal)
    detail = current if isinstance(current, dict) else {}
    evidence = detail.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    item = {
        "source": source,
        "kind": kind,
        "confidence": confidence,
        "supports_activation": True,
        "provenance": provenance,
    }
    if item not in evidence:
        evidence.append(item)
    merged_confidence = max(_numeric_confidence(detail.get("confidence")), confidence)
    detail.update(
        {
            "active": True,
            "confidence": round(merged_confidence, 2),
            "confidence_label": _confidence_label(merged_confidence),
            "evidence": evidence,
        }
    )
    signal_details[signal] = detail


def enrich_context_with_collectors(
    context: Mapping[str, Any],
    collector_results: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Return an enriched deep copy without mutating either input.

    Every known collector result activates a ``collector-*-requested`` signal.
    Provider/runtime signals additionally require ``status=AVAILABLE`` and a
    valid evidence SHA-256. Full collector provenance stays under ``collectors``
    regardless of status so ERROR/UNAVAILABLE remain auditable.
    """

    # El snapshot puede contener gigabytes bajo ``files[*].content``. Solo los
    # contenedores que este helper edita necesitan aislamiento; el resto se
    # comparte deliberadamente como vista read-only.
    enriched = dict(context)
    enriched["signals"] = deepcopy(context.get("signals", []))
    enriched["signal_evidence"] = deepcopy(context.get("signal_evidence", {}))
    enriched["signal_details"] = deepcopy(context.get("signal_details", {}))
    results = deepcopy(list(collector_results))
    enriched["collectors"] = results

    for result in results:
        if not isinstance(result, Mapping):
            continue
        collector_id = str(result.get("collector_id", ""))
        requested_signal = _REQUEST_SIGNALS.get(collector_id)
        if requested_signal is None:
            continue
        status = str(result.get("status", ""))
        evidence_sha256 = result.get("evidence_sha256")

        request_source = f"collector:{collector_id}:requested:{status or 'UNKNOWN'}"
        _add_signal(
            enriched,
            requested_signal,
            source=request_source,
            kind="collector_request",
            confidence=REQUEST_CONFIDENCE,
            provenance=_source_provenance(result, method="collector-request-result"),
        )

        if (
            status != "AVAILABLE"
            or not isinstance(evidence_sha256, str)
            or _SHA256.fullmatch(evidence_sha256) is None
        ):
            continue

        runtime_source = f"collector:{collector_id}:AVAILABLE:sha256:{evidence_sha256}"
        for signal in _RUNTIME_SIGNALS[collector_id]:
            _add_signal(
                enriched,
                signal,
                source=runtime_source,
                kind="runtime_collector_evidence",
                confidence=RUNTIME_CONFIDENCE,
                provenance=_source_provenance(result, method="authenticated-read-only-runtime"),
            )

    return enriched


__all__ = ["enrich_context_with_collectors"]
