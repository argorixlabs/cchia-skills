"""Check estático deliberadamente acotado a configuraciones explícitas de alto riesgo."""

def evaluate(context):
    evidence = []
    workloads = 0
    patterns = (
        ("privileged: true", "privileged-container"),
        ("allowprivilegeescalation: true", "privilege-escalation"),
        ("hostnetwork: true", "host-network"),
        ("hostpid: true", "host-pid"),
        ("hostipc: true", "host-ipc"),
        ("hostpath:", "host-path-volume"),
        ("runasuser: 0", "root-user"),
    )
    for file in context.get("files", []):
        path = file.get("path", "")
        if not path.lower().endswith((".yaml", ".yml")):
            continue
        content = file.get("content", "")
        lower_content = content.lower()
        if "apiversion:" not in lower_content or "kind:" not in lower_content:
            continue
        if any(kind in lower_content for kind in ("kind: pod", "kind: deployment", "kind: daemonset", "kind: statefulset", "kind: job", "kind: cronjob")):
            workloads += 1
            for number, line in enumerate(content.splitlines(), 1):
                normalized = " ".join(line.lower().strip().split())
                for token, pattern in patterns:
                    if token in normalized and not normalized.startswith("#"):
                        evidence.append({"path": path, "line": number, "pattern": pattern})
    if workloads == 0:
        return {
            "status": "NOT_ASSESSED", "confidence": "MEDIUM", "evidence_level": "E0",
            "summary": "Se detectó señal Kubernetes, pero no manifiestos de workloads soportados.", "evidence": [],
            "recommendation": "Entregar manifests renderizados o exportación read-only de workloads.",
        }
    if evidence:
        return {
            "status": "FAIL", "confidence": "HIGH", "evidence_level": "E4",
            "summary": "Se observaron configuraciones explícitas que aumentan privilegios o acceso al host.",
            "evidence": evidence,
            "recommendation": "Eliminar la configuración riesgosa o gobernar una excepción mínima; imponer Pod Security/admission policy.",
        }
    return {
        "status": "PASS", "confidence": "MEDIUM", "evidence_level": "E3",
        "summary": "No se observaron los patrones explícitos de alto riesgo en los workloads analizados.",
        "evidence": [{"workload_manifests_scanned": workloads}],
        "recommendation": "Complementar con manifests renderizados, admission policies y evidencia runtime del clúster.",
    }
