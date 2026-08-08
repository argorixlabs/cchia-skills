"""Evalúa señales declaradas sin confiar en que un system prompt sea aprobación."""

def evaluate(context):
    signals = set(context.get("signals", []))
    sources = context.get("signal_evidence", {})
    high_impact = "high-impact-tools" in signals
    approval = "human-approval" in signals
    evidence = [{"signal": key, "sources": sources.get(key, [])} for key in ("agent", "mcp", "high-impact-tools", "human-approval", "external-input") if key in signals]
    if not high_impact:
        return {
            "status": "NOT_ASSESSED",
            "confidence": "MEDIUM",
            "evidence_level": "E1",
            "summary": "Existe superficie agéntica, pero no se documentó un inventario suficiente de acciones de alto impacto.",
            "evidence": evidence,
            "recommendation": "Inventariar tools, permisos, reversibilidad, límites y acciones que requieren aprobación independiente.",
        }
    if not approval:
        return {
            "status": "FAIL",
            "confidence": "HIGH",
            "evidence_level": "E2",
            "summary": "Se declararon acciones de alto impacto, pero no una aprobación humana/policy gate independiente.",
            "evidence": evidence,
            "recommendation": "Interponer un gateway determinista fuera del LLM con deny-by-default, aprobación, límites, identidad y auditoría.",
        }
    return {
        "status": "PASS",
        "confidence": "MEDIUM",
        "evidence_level": "E2",
        "summary": "La descripción declara aprobación para acciones de alto impacto; falta demostrarla con pruebas runtime.",
        "evidence": evidence,
        "recommendation": "Probar bypass, timeout, replay, mutación de payload y caída del aprobador; conservar evidencia de que la acción nunca llegó al destino.",
    }
