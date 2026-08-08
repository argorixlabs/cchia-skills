"""Valida completitud documental sin convertir declaraciones en evidencia operativa."""

def _has_key(value, alternatives):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in alternatives and item not in (None, "", [], {}):
                return True
            if _has_key(item, alternatives):
                return True
    elif isinstance(value, list):
        for item in value:
            if _has_key(item, alternatives):
                return True
    return False


def evaluate(context):
    system = context.get("system", {})
    if not system:
        return {
            "status": "NOT_ASSESSED",
            "confidence": "HIGH",
            "evidence_level": "E0",
            "summary": "Se detectó superficie de IA, pero no se entregó una descripción estructurada del sistema.",
            "evidence": [],
            "recommendation": "Completar system.yaml con owner, modelo/proveedor, datos, supervisión, monitoreo y retiro.",
        }
    groups = (
        ("owner", ("owner", "propietario", "responsable")),
        ("model_or_provider", ("model", "modelo", "provider", "proveedor")),
        ("data", ("data", "datos", "data_categories", "categorias_datos")),
        ("human_oversight", ("human_oversight", "supervision_humana", "approval")),
        ("monitoring", ("monitoring", "monitoreo", "observability", "observabilidad")),
        ("decommissioning", ("decommissioning", "retiro", "retirement", "kill_switch")),
    )
    missing = []
    present = []
    for label, alternatives in groups:
        if _has_key(system, alternatives):
            present.append(label)
        else:
            missing.append(label)
    if missing:
        return {
            "status": "PARTIAL",
            "confidence": "HIGH",
            "evidence_level": "E2",
            "summary": "El inventario del sistema de IA está incompleto; una declaración documentada aún no prueba operación efectiva.",
            "evidence": [{"present": present, "missing": missing}],
            "recommendation": "Completar los campos faltantes y adjuntar evidencia operativa en una evaluación posterior.",
        }
    return {
        "status": "PASS",
        "confidence": "MEDIUM",
        "evidence_level": "E2",
        "summary": "La descripción contiene el inventario mínimo requerido; su implementación operativa aún debe probarse.",
        "evidence": [{"documented_fields": present}],
        "recommendation": "Vincular cada declaración a configuración, logs, pruebas y responsables verificables.",
    }
