"""Inspección textual de Terraform; no invoca gcloud ni terraform."""

def evaluate(context):
    evidence = []
    terraform_files = 0
    risky = (
        ("roles/owner", "primitive-owner-role"),
        ("roles/editor", "primitive-editor-role"),
        ("allusers", "public-principal"),
        ("allauthenticatedusers", "authenticated-public-principal"),
    )
    for file in context.get("files", []):
        path = file.get("path", "")
        if not path.lower().endswith((".tf", ".tfvars")):
            continue
        terraform_files += 1
        for number, line in enumerate(file.get("content", "").splitlines(), 1):
            lower = line.lower()
            for token, pattern in risky:
                if token in lower and not lower.strip().startswith(("#", "//")):
                    evidence.append({"path": path, "line": number, "pattern": pattern})
    if terraform_files == 0:
        return {
            "status": "NOT_ASSESSED", "confidence": "HIGH", "evidence_level": "E0",
            "summary": "No se encontraron archivos Terraform analizables.", "evidence": [],
            "recommendation": "Entregar el código Terraform que administra IAM de GCP.",
        }
    if evidence:
        return {
            "status": "FAIL", "confidence": "HIGH", "evidence_level": "E4",
            "summary": "Se observaron roles básicos de alto alcance o principals públicos en Terraform.",
            "evidence": evidence,
            "recommendation": "Sustituir por roles predefinidos/custom mínimos y principals explícitos; revisar IAM efectivo e herencia.",
        }
    return {
        "status": "PASS", "confidence": "MEDIUM", "evidence_level": "E3",
        "summary": "No se observaron los cuatro patrones riesgosos en el Terraform analizado.",
        "evidence": [{"terraform_files_scanned": terraform_files}],
        "recommendation": "Validar además IAM efectivo, políticas de organización y drift fuera de Terraform.",
    }
