"""Heurística conservadora que nunca conserva el valor del posible secreto."""

def evaluate(context):
    evidence = []
    scanned = 0
    for file in context.get("files", []):
        path = file.get("path", "")
        lower_path = path.lower()
        if lower_path.startswith("checks/") or "/checks/" in lower_path:
            continue
        scanned += 1
        for number, line in enumerate(file.get("content", "").splitlines(), 1):
            stripped = line.strip()
            lower = stripped.lower()
            if not stripped or stripped.startswith(("#", "//", "*")):
                continue
            pattern = ""
            if "-----begin private key-----" in lower:
                pattern = "private-key-material"
            elif "aws_access_key_id" in lower and ("=" in lower or ":" in lower):
                pattern = "aws-access-key-assignment"
            elif any(token in lower for token in ("client_secret", "api_key", "apikey", "password")) and ("=" in lower or ":" in lower):
                if not any(token in lower for token in ("example", "placeholder", "changeme", "${", "process.env", "os.getenv", "secret_ref")):
                    pattern = "inline-secret-assignment"
            if pattern:
                evidence.append({"path": path, "line": number, "pattern": pattern, "value_redacted": True})
                if len(evidence) >= 50:
                    break
        if len(evidence) >= 50:
            break
    if scanned == 0:
        return {
            "status": "NOT_ASSESSED",
            "confidence": "LOW",
            "evidence_level": "E0",
            "summary": "No hubo archivos de repositorio analizables fuera del catálogo de checks.",
            "evidence": [],
            "recommendation": "Entregar el repositorio o una exportación de configuración dentro del alcance.",
        }
    if evidence:
        return {
            "status": "FAIL",
            "confidence": "MEDIUM",
            "evidence_level": "E4",
            "summary": "Se observaron patrones compatibles con secretos inline; los valores fueron deliberadamente redactados.",
            "evidence": evidence,
            "recommendation": "Validar cada coincidencia, revocar/rotar las credenciales reales, eliminar el material del historial y usar un secret manager.",
        }
    return {
        "status": "PASS",
        "confidence": "MEDIUM",
        "evidence_level": "E3",
        "summary": "No se observaron los patrones de secretos cubiertos por este check en los archivos analizados.",
        "evidence": [{"files_scanned": scanned, "patterns": 3}],
        "recommendation": "Mantener secret scanning preventivo y rotación; complementar con un scanner especializado.",
    }
