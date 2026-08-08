"""Intake read-only, trazable y conservador de repositorios y sistemas."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

import yaml

from .utils import canonical_hash, sha256_bytes, sha256_file, utc_now


TEXT_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".rb", ".php",
    ".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".env", ".md", ".txt", ".sh", ".ps1", ".dockerfile", ".xml",
}
SPECIAL_NAMES = {"dockerfile", "makefile", "jenkinsfile", ".env", ".mcp.json", "mcp.json"}
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "coverage", "__pycache__"}
MAX_FILE_BYTES = 1_000_000
MAX_FILES = 2_000
SIGNAL_ACTIVE_THRESHOLD = 0.65
MAX_SIGNAL_EVIDENCE = 10
MAX_COLLECTION_SAMPLES = 20

_PROVIDER_TERMS = {
    "gcp": ("gcp", "google cloud", "google provider"),
    "aws": ("aws", "amazon web services"),
    "azure": ("azure", "microsoft cloud"),
}
_PROVIDER_FIELDS = {
    "provider", "cloud_provider", "cloud", "platform", "deployment_platform", "hosting_provider",
}
_DOCUMENTARY_CUES = (
    "roadmap", "future", "futuro", "futura", "planned", "planificado", "eventually", "eventualmente",
    "candidate", "candidato", "support for", "soporte para", "collectors for", "collectors para",
    "agregar", "añadir", "add support", "next step", "siguiente paso", "pendiente", "faltan",
)
_USAGE_CUES = (
    "uses", "use ", "using", "utiliza", "usa ", "operates on", "runs on", "run on", "deployed on",
    "deployed to", "hosted on", "desplegado en", "desplegada en", "alojado en", "alojada en",
    "powered by", "basado en", "basada en",
)
_SOURCE_CODE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rs", ".rb", ".php", ".json", ".toml",
}


def load_system(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        value = json.loads(raw)
    elif path.suffix.lower() in {".yaml", ".yml"}:
        value = yaml.safe_load(raw)
    else:
        value = {"description": raw, "source_format": path.suffix.lower().lstrip(".") or "text"}
    if not isinstance(value, dict):
        raise ValueError("La descripción del sistema debe ser un objeto YAML/JSON")
    return value


def _is_excluded(path: Path, excluded: Iterable[Path]) -> bool:
    resolved = path.resolve()
    for root in excluded:
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


def _is_supported_text(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES or path.name.lower() in SPECIAL_NAMES


def _append_sample(samples: dict[str, list[str]], reason: str, path: Path, target: Path) -> None:
    bucket = samples.setdefault(reason, [])
    if len(bucket) >= MAX_COLLECTION_SAMPLES:
        return
    try:
        value = path.name if target.is_file() else path.relative_to(target).as_posix()
    except ValueError:
        value = str(path)
    bucket.append(value)


def _collect_paths(
    target: Path,
    excluded: Iterable[Path],
    *,
    max_files: int,
    max_file_bytes: int,
) -> tuple[list[Path], dict[str, Any]]:
    """Selecciona archivos y conserva evidencia explícita de toda pérdida de cobertura."""
    if max_files < 1:
        raise ValueError("max_files debe ser al menos 1")
    if max_file_bytes < 1:
        raise ValueError("max_file_bytes debe ser al menos 1")

    selected: list[Path] = []
    counts = {
        "candidate_files": 0,
        "skipped_file_limit": 0,
        "skipped_too_large": 0,
        "skipped_io": 0,
    }
    samples: dict[str, list[str]] = {}

    def consider(path: Path) -> None:
        if _is_excluded(path, excluded) or not _is_supported_text(path):
            return
        counts["candidate_files"] += 1
        try:
            size = path.stat().st_size
        except OSError:
            counts["skipped_io"] += 1
            _append_sample(samples, "io_error", path, target)
            return
        if size > max_file_bytes:
            counts["skipped_too_large"] += 1
            _append_sample(samples, "max_file_bytes", path, target)
            return
        if len(selected) >= max_files:
            counts["skipped_file_limit"] += 1
            _append_sample(samples, "max_files", path, target)
            return
        selected.append(path)

    if target.is_file():
        consider(target)
    else:
        walk_errors: list[OSError] = []
        for root, dirs, names in os.walk(target, onerror=walk_errors.append):
            root_path = Path(root)
            dirs[:] = sorted(
                d for d in dirs
                if d.lower() not in IGNORED_DIRS and not _is_excluded(root_path / d, excluded)
            )
            for name in sorted(names):
                consider(root_path / name)
        if walk_errors:
            counts["skipped_io"] += len(walk_errors)
            for error in walk_errors[:MAX_COLLECTION_SAMPLES]:
                filename = Path(error.filename) if error.filename else target
                _append_sample(samples, "io_error", filename, target)

    return selected, {**counts, "samples": samples}


def _iter_files(target: Path, excluded: Iterable[Path]) -> Iterable[Path]:
    """Compatibilidad interna: itera la misma ventana acotada usada por el intake."""
    paths, _ = _collect_paths(
        target,
        excluded,
        max_files=MAX_FILES,
        max_file_bytes=MAX_FILE_BYTES,
    )
    yield from paths


def snapshot_target(target: Path, excluded: Iterable[Path] = ()) -> dict[str, str]:
    snapshot: dict[str, str] = {}
    for path in _iter_files(target, excluded):
        try:
            relative = path.name if target.is_file() else path.relative_to(target).as_posix()
            snapshot[relative] = sha256_file(path)
        except OSError:
            continue
    return snapshot


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(str(key) + " " + _flatten(item) for key, item in value.items())
    if isinstance(value, list):
        return " ".join(_flatten(item) for item in value)
    return str(value)


def _contains(text: str, words: Iterable[str]) -> bool:
    return any(re.search(r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])", text) for word in words)


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.85:
        return "HIGH"
    if confidence >= SIGNAL_ACTIVE_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def _iter_scalar_fields(value: Any, prefix: str = "system") -> Iterable[tuple[str, str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            field = f"{prefix}.{key}"
            yield from _iter_scalar_fields(item, field)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _iter_scalar_fields(item, f"{prefix}[{index}]")
    elif value is not None:
        leaf = prefix.rsplit(".", 1)[-1].split("[", 1)[0].lower()
        yield prefix, leaf, str(value)


def _documentary_context(text: str) -> bool:
    lowered = text.lower()
    return any(cue in lowered for cue in _DOCUMENTARY_CUES)


def _declares_provider(text: str, terms: Iterable[str]) -> bool:
    lowered = text.lower()
    if not _contains(lowered, terms) or _documentary_context(lowered):
        return False
    for cue in _USAGE_CUES:
        cue_index = lowered.find(cue)
        if cue_index < 0:
            continue
        for term in terms:
            term_index = lowered.find(term)
            if term_index >= 0 and abs(term_index - cue_index) <= 120:
                return True
    return bool(re.search(r"\b(?:cloud|provider|plataforma|infraestructura)\s*(?:is|es|:|=)\s*", lowered))


def infer_signal_details(files: list[dict[str, Any]], system: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Infiere señales activas y menciones débiles con confidence y provenance.

    Las menciones documentales se conservan como evidencia LOW pero no activan
    aplicabilidad. Una señal solo queda activa con evidencia explícita o
    estructural de al menos ``SIGNAL_ACTIVE_THRESHOLD``.
    """
    raw_details: dict[str, dict[str, Any]] = {}

    def add(
        signal: str,
        source: str,
        *,
        kind: str,
        confidence: float,
        provenance: dict[str, Any],
        supports_activation: bool = True,
    ) -> None:
        normalized = signal.strip().lower()
        if not normalized:
            return
        entry = raw_details.setdefault(normalized, {"evidence": [], "max_activating_confidence": 0.0})
        evidence = {
            "source": source,
            "kind": kind,
            "confidence": round(max(0.0, min(1.0, confidence)), 2),
            "supports_activation": supports_activation,
            "provenance": provenance,
        }
        if supports_activation:
            entry["max_activating_confidence"] = max(entry["max_activating_confidence"], evidence["confidence"])
        if evidence in entry["evidence"]:
            return
        if len(entry["evidence"]) < MAX_SIGNAL_EVIDENCE:
            entry["evidence"].append(evidence)
            return
        # Una larga lista de menciones débiles nunca debe ocultar la declaración
        # estructural que realmente activó la señal.
        weakest_index = min(
            range(len(entry["evidence"])),
            key=lambda index: (
                entry["evidence"][index]["supports_activation"],
                entry["evidence"][index]["confidence"],
            ),
        )
        weakest = entry["evidence"][weakest_index]
        if supports_activation and (
            not weakest["supports_activation"] or evidence["confidence"] > weakest["confidence"]
        ):
            entry["evidence"][weakest_index] = evidence

    if files:
        add(
            "repository",
            "target contiene archivos de texto analizables",
            kind="collected_artifact",
            confidence=1.0,
            provenance={"origin": "target", "method": "supported-text-collection"},
        )

    explicit = system.get("signals", [])
    if isinstance(explicit, list):
        for index, signal in enumerate(explicit):
            add(
                str(signal),
                "system.signals",
                kind="explicit_declaration",
                confidence=1.0,
                provenance={"origin": "system", "field": f"signals[{index}]", "method": "operator-declared"},
            )

    # Campos estructurados tienen semántica más fuerte que una mención narrativa.
    for field_path, leaf, raw_value in _iter_scalar_fields(system):
        if field_path in {"system.description", "system.source_format"} or field_path.startswith("system.signals["):
            continue
        value = raw_value.lower()
        if leaf in _PROVIDER_FIELDS:
            for provider, terms in _PROVIDER_TERMS.items():
                if _contains(value, terms):
                    add(
                        provider,
                        field_path,
                        kind="structured_declaration",
                        confidence=0.95,
                        provenance={"origin": "system", "field": field_path[7:], "method": "provider-field"},
                    )
                    add(
                        "cloud",
                        f"{field_path} declara {provider.upper()}",
                        kind="derived_signal",
                        confidence=0.95,
                        provenance={"origin": "system", "field": field_path[7:], "derived_from": provider},
                    )

    agents = system.get("agents")
    if isinstance(agents, list) and agents:
        add("agent", "system.agents", kind="structured_declaration", confidence=0.95,
            provenance={"origin": "system", "field": "agents", "method": "non-empty-list"})
        add("ai", "system.agents implica sistema de IA", kind="derived_signal", confidence=0.9,
            provenance={"origin": "system", "field": "agents", "derived_from": "agent"})
    if any(system.get(field) for field in ("model", "models", "llm")):
        add("ai", "system declara modelo/LLM", kind="structured_declaration", confidence=0.95,
            provenance={"origin": "system", "field": "model|models|llm", "method": "non-empty-field"})

    structured_text = _flatten({key: value for key, value in system.items() if key != "description"}).lower()
    if _contains(structured_text, ("personal data", "datos personales", "pii", "health", "salud", "biometric", "biométrico")):
        add("sensitive-data", "campos estructurados del sistema", kind="structured_declaration", confidence=0.9,
            provenance={"origin": "system", "method": "structured-sensitive-data-term"})
    tools = system.get("tools")
    if isinstance(tools, list) and tools:
        tools_text = _flatten(tools).lower()
        if _contains(tools_text, ("delete", "eliminar", "payment", "pago", "transfer", "deploy", "iam change", "execute code", "write")):
            add("high-impact-tools", "system.tools", kind="structured_declaration", confidence=0.9,
                provenance={"origin": "system", "field": "tools", "method": "high-impact-effect"})
    oversight = _flatten(system.get("human_oversight", "")).lower()
    if _contains(oversight, ("required", "enabled", "human approval", "aprobación humana", "aprobacion humana", "four-eyes", "dual control")):
        add("human-approval", "system.human_oversight", kind="structured_declaration", confidence=0.9,
            provenance={"origin": "system", "field": "human_oversight", "method": "approval-term"})

    description = str(system.get("description", ""))
    description_lower = description.lower()
    description_lines = [
        (line_number, line.strip().lower())
        for line_number, line in enumerate(description.splitlines(), start=1)
        if line.strip()
    ]

    for provider, terms in _PROVIDER_TERMS.items():
        matching_lines = [line for _, line in description_lines if _contains(line, terms)]
        for line_number, line in description_lines:
            if not _contains(line, terms):
                continue
            declared = _declares_provider(line, terms)
            add(
                provider,
                "system.description",
                kind="usage_declaration" if declared else "documentary_mention",
                confidence=0.82 if declared else 0.2,
                supports_activation=declared,
                provenance={
                    "origin": "system",
                    "field": "description",
                    "line": line_number,
                    "method": "usage-context" if declared else "mention-only",
                },
            )
            if declared:
                add("cloud", f"descripción declara uso de {provider.upper()}", kind="derived_signal", confidence=0.82,
                    provenance={"origin": "system", "field": "description", "derived_from": provider})
        # Evita que una descripción sin saltos pierda la capacidad de declarar uso.
        if not matching_lines and _contains(description_lower, terms):
            declared = _declares_provider(description_lower, terms)
            add(provider, "system.description", kind="usage_declaration" if declared else "documentary_mention",
                confidence=0.82 if declared else 0.2, supports_activation=declared,
                provenance={"origin": "system", "field": "description", "method": "usage-context" if declared else "mention-only"})

    documentary_description = _documentary_context(description_lower)
    agent_declaration = bool(re.search(r"\b(?:ai\s+agent|agentic\s+(?:system|application)|agente\s+de\s+ia|agente\s+ia)\b", description_lower))
    if agent_declaration and not documentary_description:
        add("agent", "system.description", kind="usage_declaration", confidence=0.85,
            provenance={"origin": "system", "field": "description", "method": "agent-declaration"})
        add("ai", "agente declarado en system.description", kind="derived_signal", confidence=0.85,
            provenance={"origin": "system", "field": "description", "derived_from": "agent"})
    elif _contains(description_lower, ("agent", "agente", "agentic", "autonomous", "autónomo", "autonomo")):
        add("agent", "system.description", kind="documentary_mention", confidence=0.25, supports_activation=False,
            provenance={"origin": "system", "field": "description", "method": "mention-only"})

    ai_declared = bool(re.search(r"\b(?:uses?|using|utiliza|usa|powered by|basad[oa] en)\b[^.\n]{0,100}\b(?:ai|llm|genai|rag|inteligencia artificial)\b", description_lower))
    if ai_declared and not documentary_description:
        add("ai", "system.description", kind="usage_declaration", confidence=0.8,
            provenance={"origin": "system", "field": "description", "method": "ai-usage-context"})
    elif _contains(description_lower, ("artificial intelligence", "inteligencia artificial", "llm", "model", "modelo", "rag", "genai")):
        add("ai", "system.description", kind="documentary_mention", confidence=0.25, supports_activation=False,
            provenance={"origin": "system", "field": "description", "method": "mention-only"})

    mcp_declared = (
        _contains(description_lower, ("mcp", "model context protocol", "tool server"))
        and (agent_declaration or bool(re.search(r"\b(?:uses?|using|utiliza|usa|through|mediante|con)\b[^.\n]{0,100}\bmcp\b", description_lower)))
        and not documentary_description
    )
    if mcp_declared:
        add("mcp", "system.description", kind="usage_declaration", confidence=0.82,
            provenance={"origin": "system", "field": "description", "method": "mcp-usage-context"})
        add("agent", "MCP declarado implica superficie agéntica/herramientas", kind="derived_signal", confidence=0.75,
            provenance={"origin": "system", "field": "description", "derived_from": "mcp"})
    elif _contains(description_lower, ("mcp", "model context protocol", "tool server")):
        add("mcp", "system.description", kind="documentary_mention", confidence=0.25, supports_activation=False,
            provenance={"origin": "system", "field": "description", "method": "mention-only"})

    if re.search(r"\b(?:can|may|puede|permite|capaz de)\b[^.\n]{0,80}\b(?:delete|eliminar|payment|pago|transfer|deploy|execute|ejecutar|write|escribir)\b", description_lower):
        add("high-impact-tools", "system.description", kind="capability_declaration", confidence=0.8,
            provenance={"origin": "system", "field": "description", "method": "capability-pattern"})
    if re.search(r"\b(?:reads?|receives?|ingests?|lee|recibe|ingiere)\b[^.\n]{0,80}\b(?:external|extern[oa]|email|correo|web|document)\b", description_lower):
        add("external-input", "system.description", kind="dataflow_declaration", confidence=0.8,
            provenance={"origin": "system", "field": "description", "method": "external-input-pattern"})
    if re.search(r"\b(?:processes?|stores?|contains?|procesa|almacena|contiene)\b[^.\n]{0,80}\b(?:personal data|datos personales|pii|health|salud|biometric|biométrico)\b", description_lower):
        add("sensitive-data", "system.description", kind="data_declaration", confidence=0.8,
            provenance={"origin": "system", "field": "description", "method": "sensitive-data-pattern"})
    if re.search(r"\b(?:requires?|requiere|with|con)\b[^.\n]{0,80}\b(?:human approval|aprobación humana|aprobacion humana|four-eyes|dual control)\b", description_lower):
        add("human-approval", "system.description", kind="control_declaration", confidence=0.8,
            provenance={"origin": "system", "field": "description", "method": "approval-pattern"})

    for file in files:
        path = str(file["path"])
        path_lower = path.lower()
        content = str(file["content"]).lower()
        suffix = Path(path_lower).suffix
        provenance = {"origin": "target", "path": path}
        if path_lower.endswith((".tf", ".tfvars")):
            add("terraform", path, kind="artifact_type", confidence=1.0,
                provenance={**provenance, "method": "terraform-extension"})
            provider_matches = {
                "gcp": 'provider "google"' in content or bool(re.search(r"\bgoogle_[a-z0-9_]+", content)),
                "aws": 'provider "aws"' in content or bool(re.search(r"\baws_[a-z0-9_]+", content)),
                "azure": 'provider "azurerm"' in content or bool(re.search(r"\bazurerm_[a-z0-9_]+", content)),
            }
            for provider, matched in provider_matches.items():
                if matched:
                    add(provider, path, kind="configuration_signature", confidence=0.98,
                        provenance={**provenance, "method": "terraform-provider-signature"})
                    add("cloud", path, kind="derived_signal", confidence=0.98,
                        provenance={**provenance, "derived_from": provider})
        if path_lower.endswith((".yaml", ".yml")) and "apiversion:" in content and "kind:" in content:
            add("kubernetes", path, kind="configuration_signature", confidence=0.98,
                provenance={**provenance, "method": "kubernetes-object-signature"})
        if "mcpservers" in content or path_lower.endswith((".mcp.json", "mcp.json")):
            add("mcp", path, kind="configuration_signature", confidence=0.98,
                provenance={**provenance, "method": "mcp-config-signature"})
            add("agent", path, kind="derived_signal", confidence=0.85,
                provenance={**provenance, "derived_from": "mcp"})
            add("ai", path, kind="derived_signal", confidence=0.85,
                provenance={**provenance, "derived_from": "mcp"})
        if suffix in _SOURCE_CODE_SUFFIXES and any(
            token in content for token in ("openai", "anthropic", "langchain", "crewai", "autogen", "llamaindex")
        ):
            add("ai", path, kind="code_or_dependency_signature", confidence=0.88,
                provenance={**provenance, "method": "ai-sdk-signature"})

    details: dict[str, dict[str, Any]] = {}
    for signal, detail in sorted(raw_details.items()):
        activating_confidence = detail["max_activating_confidence"]
        confidence = activating_confidence or max((item["confidence"] for item in detail["evidence"]), default=0.0)
        active = activating_confidence >= SIGNAL_ACTIVE_THRESHOLD
        details[signal] = {
            "active": active,
            "confidence": round(confidence, 2),
            "confidence_label": _confidence_label(confidence),
            "evidence": detail["evidence"],
        }
    return details


def infer_signals(files: list[dict[str, Any]], system: dict[str, Any]) -> tuple[list[str], dict[str, list[str]]]:
    """API compatible: lista de señales activas y fuentes legibles."""
    details = infer_signal_details(files, system)
    signals = sorted(signal for signal, detail in details.items() if detail["active"])
    evidence = {
        signal: list(dict.fromkeys(item["source"] for item in details[signal]["evidence"] if item["supports_activation"]))
        for signal in signals
    }
    return signals, evidence


def collection_allows_pass(context: dict[str, Any]) -> bool:
    """Retorna False si la ventana recolectada no sustenta una conclusión PASS."""
    return context.get("collection", {}).get("complete") is True


def safeguard_pass_for_collection(evaluation: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Degrada PASS a NOT_ASSESSED cuando archivos relevantes pudieron quedar fuera.

    Este helper es puro para que runner/policy lo aplique después de validar la
    salida del check. No muta la evaluación recibida.
    """
    if str(evaluation.get("status", "")).upper() != "PASS" or collection_allows_pass(context):
        return evaluation
    result = dict(evaluation)
    result["status"] = "NOT_ASSESSED"
    result["confidence"] = "LOW"
    result["evidence_level"] = "E0"
    previous = str(result.get("summary", "")).strip()
    limitation = "Cobertura de recolección incompleta; el PASS original no es demostrable."
    result["summary"] = f"{limitation} {previous}".strip()
    limitations = list(result.get("limitations", [])) if isinstance(result.get("limitations", []), list) else []
    if limitation not in limitations:
        limitations.append(limitation)
    result["limitations"] = limitations
    return result


def build_context(
    target: Path,
    system: dict[str, Any],
    excluded: Iterable[Path] = (),
    *,
    max_files: int = MAX_FILES,
    max_file_bytes: int = MAX_FILE_BYTES,
) -> dict[str, Any]:
    target = target.resolve()
    files: list[dict[str, Any]] = []
    paths, collection_stats = _collect_paths(
        target,
        excluded,
        max_files=max_files,
        max_file_bytes=max_file_bytes,
    )
    skipped_decode = 0
    decode_samples: list[str] = []
    for path in paths:
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            skipped_decode += 1
            if len(decode_samples) < MAX_COLLECTION_SAMPLES:
                relative = path.name if target.is_file() else path.relative_to(target).as_posix()
                decode_samples.append(relative)
            continue
        relative = path.name if target.is_file() else path.relative_to(target).as_posix()
        files.append({
            "path": relative,
            "sha256": sha256_bytes(raw),
            "size": len(raw),
            "content": text,
        })

    if decode_samples:
        collection_stats["samples"]["decode_error"] = decode_samples
    incomplete_reasons: list[str] = []
    if collection_stats["skipped_file_limit"]:
        incomplete_reasons.append("max_files")
    if collection_stats["skipped_too_large"]:
        incomplete_reasons.append("max_file_bytes")
    if collection_stats["skipped_io"]:
        incomplete_reasons.append("io_error")
    if skipped_decode:
        incomplete_reasons.append("decode_error")
    collection_complete = not incomplete_reasons

    signal_details = infer_signal_details(files, system)
    if collection_stats["candidate_files"] and "repository" not in signal_details:
        # Aunque todos los archivos hayan quedado fuera por límites/decodificación,
        # el target sigue siendo un repositorio aplicable. Esto selecciona los
        # checks pertinentes para que terminen en NOT_ASSESSED, no en una falsa
        # exclusión por ausencia de señal.
        signal_details["repository"] = {
            "active": True,
            "confidence": 0.95,
            "confidence_label": "HIGH",
            "evidence": [{
                "source": "target contiene archivos candidatos no recolectados completamente",
                "kind": "collection_metadata",
                "confidence": 0.95,
                "supports_activation": True,
                "provenance": {"origin": "target", "method": "supported-file-candidate"},
            }],
        }
    signals = sorted(signal for signal, detail in signal_details.items() if detail["active"])
    signal_evidence = {
        signal: list(dict.fromkeys(
            item["source"] for item in signal_details[signal]["evidence"] if item["supports_activation"]
        ))
        for signal in signals
    }
    snapshot = {item["path"]: item["sha256"] for item in files}
    return {
        "schema_version": "1.1",
        "collected_at": utc_now(),
        "target": {"path": str(target), "fingerprint": canonical_hash(snapshot)},
        "system": system,
        "signals": signals,
        "signal_evidence": signal_evidence,
        "signal_details": signal_details,
        "files": files,
        "collection": {
            "mode": "read_only",
            "file_count": len(files),
            "candidate_files": collection_stats["candidate_files"],
            "complete": collection_complete,
            "truncated": bool(collection_stats["skipped_file_limit"] or collection_stats["skipped_too_large"]),
            "pass_eligible": collection_complete,
            "incomplete_reasons": incomplete_reasons,
            "skipped_decode": skipped_decode,
            "skipped_file_limit": collection_stats["skipped_file_limit"],
            "skipped_too_large": collection_stats["skipped_too_large"],
            "skipped_io": collection_stats["skipped_io"],
            "samples": collection_stats["samples"],
            "limits": {"max_files": max_files, "max_file_bytes": max_file_bytes},
        },
    }
