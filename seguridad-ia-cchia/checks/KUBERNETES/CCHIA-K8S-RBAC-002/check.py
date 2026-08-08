"""Evalúa el snapshot redacted de kubectl-rbac sin invocar APIs ni filesystem."""

REQUIRED_COMMANDS = {
    "cluster-rbac": "kubectl.rbac.cluster.v1",
    "namespaced-rbac": "kubectl.rbac.namespaced.v1",
}
PUBLIC_USERS = ("system:anonymous", "*")
PUBLIC_GROUPS = ("system:unauthenticated", "system:authenticated", "*")
SENSITIVE_VERBS = (
    "*", "create", "update", "patch", "delete", "deletecollection",
    "impersonate", "bind", "escalate",
)


def _not_assessed(reason, evidence):
    return {
        "status": "NOT_ASSESSED",
        "confidence": "LOW",
        "evidence_level": "E0",
        "summary": "La evidencia runtime de RBAC no permite una conclusión: " + reason,
        "evidence": evidence,
        "recommendation": "Ejecutar kubectl-rbac con identidad get/list suficiente y conservar ambos payloads JSON completos.",
    }


def _collector_payloads(context):
    matches = []
    for item in context.get("collectors", []):
        if isinstance(item, dict) and item.get("collector_id") == "kubectl-rbac":
            matches.append(item)
    if len(matches) != 1:
        return None, "se requiere exactamente un resultado kubectl-rbac"
    collector = matches[0]
    if collector.get("schema_version") != "1.0" or collector.get("collector_version") != "1.0.0":
        return None, "la versión del collector no coincide con el contrato evaluado"
    if collector.get("mode") != "read_only":
        return None, "el collector no acredita mode=read_only"
    if collector.get("status") != "AVAILABLE":
        return None, "kubectl-rbac no terminó AVAILABLE"
    redaction = collector.get("redaction", {})
    if (
        not isinstance(redaction, dict)
        or redaction.get("applied") is not True
        or redaction.get("strategy") != "cchia-default-v1"
        or redaction.get("replacement") != "[REDACTED]"
    ):
        return None, "el payload no acredita redacción aplicada"

    evidence_hash = collector.get("evidence_sha256")
    if (
        not isinstance(evidence_hash, str)
        or len(evidence_hash) != 64
        or not all(character in "0123456789abcdef" for character in evidence_hash)
    ):
        return None, "el collector no contiene un hash canónico válido"

    provenance = collector.get("provenance", {})
    if not isinstance(provenance, dict) or provenance.get("provider") != "kubernetes":
        return None, "la provenance no identifica Kubernetes"
    interface = provenance.get("interface")
    if (
        not isinstance(interface, dict)
        or interface.get("kind") != "command"
        or interface.get("tool") != "kubectl"
        or interface.get("executable_available") is not True
        or not isinstance(interface.get("resolved_executable"), str)
        or not interface.get("resolved_executable").strip()
    ):
        return None, "la provenance no demuestra un cliente kubectl disponible"
    commands = provenance.get("commands", []) if isinstance(provenance, dict) else []
    evidence_rows = collector.get("evidence", [])
    if not isinstance(commands, list) or not isinstance(evidence_rows, list):
        return None, "commands/evidence no tienen estructura de lista"

    payloads = {}
    for command in commands:
        if not isinstance(command, dict):
            return None, "provenance contiene un registro de comando inválido"
        if not isinstance(command.get("command_id"), str) or not isinstance(command.get("policy_id"), str):
            return None, "provenance contiene metadata de comando inválida"
        if command.get("status") != "AVAILABLE":
            return None, "al menos un comando del collector no terminó AVAILABLE"
    for row in evidence_rows:
        if not isinstance(row, dict) or not isinstance(row.get("command_id"), str):
            return None, "collector contiene metadata de evidencia inválida"
        if row.get("status") != "AVAILABLE":
            return None, "al menos un payload del collector no terminó AVAILABLE"
    for command_id, policy_id in REQUIRED_COMMANDS.items():
        command_matches = []
        for command in commands:
            if isinstance(command, dict) and command.get("command_id") == command_id:
                command_matches.append(command)
        if len(command_matches) != 1:
            return None, "falta provenance único para " + command_id
        command = command_matches[0]
        stdout_hash = command.get("stdout_sha256")
        valid_stdout_hash = (
            isinstance(stdout_hash, str)
            and len(stdout_hash) == 64
            and all(character in "0123456789abcdef" for character in stdout_hash)
        )
        if (
            command.get("policy_id") != policy_id
            or command.get("status") != "AVAILABLE"
            or command.get("exit_code") != 0
            or not valid_stdout_hash
        ):
            return None, "el comando requerido no terminó AVAILABLE: " + command_id

        evidence_matches = []
        for row in evidence_rows:
            if isinstance(row, dict) and row.get("command_id") == command_id:
                evidence_matches.append(row)
        if len(evidence_matches) != 1:
            return None, "falta evidencia única para " + command_id
        row = evidence_matches[0]
        if row.get("status") != "AVAILABLE" or row.get("content_type") != "application/json":
            return None, "la evidencia no es JSON AVAILABLE para " + command_id
        data = row.get("data")
        if not isinstance(data, dict):
            return None, "el payload no es un objeto para " + command_id
        if data.get("kind") != "List" or not isinstance(data.get("apiVersion"), str):
            return None, "el payload no acredita una lista Kubernetes para " + command_id
        if not isinstance(data.get("items"), list):
            return None, "items no es una lista para " + command_id
        payloads[command_id] = data.get("items", [])
    return payloads, ""


def _role_reasons(rules):
    reasons = []
    for rule in rules:
        verbs = [str(value).lower() for value in rule.get("verbs", [])]
        resources = [str(value).lower() for value in rule.get("resources", [])]
        api_groups = [str(value).lower() for value in rule.get("apiGroups", [])]
        urls = [str(value).lower() for value in rule.get("nonResourceURLs", [])]
        sensitive = any(value in SENSITIVE_VERBS for value in verbs)
        if "*" in verbs and "*" in resources:
            reasons.append("wildcard-verbs-and-resources")
        elif "*" in resources and sensitive:
            reasons.append("wildcard-resources-with-sensitive-verbs")
        elif "*" in api_groups and "*" in resources and sensitive:
            reasons.append("wildcard-api-groups-and-resources")
        if "*" in urls and ("*" in verbs or "get" in verbs):
            reasons.append("wildcard-non-resource-urls")
        if any(value in ("impersonate", "bind", "escalate") for value in verbs):
            reasons.append("authorization-escalation-verbs")
    return sorted(set(reasons))


def _validate_items(payloads):
    expected = {
        "cluster-rbac": ("ClusterRole", "ClusterRoleBinding"),
        "namespaced-rbac": ("Role", "RoleBinding"),
    }
    inventory = []
    observed_cluster_kinds = set()
    for command_id in REQUIRED_COMMANDS:
        for item in payloads.get(command_id, []):
            if not isinstance(item, dict):
                return None, "un item de " + command_id + " no es objeto"
            kind = item.get("kind")
            metadata = item.get("metadata")
            api_version = item.get("apiVersion")
            if (
                kind not in expected[command_id]
                or not isinstance(metadata, dict)
                or not isinstance(api_version, str)
                or not api_version.startswith("rbac.authorization.k8s.io/")
            ):
                return None, "kind/metadata inesperado en " + command_id
            name = metadata.get("name")
            if not isinstance(name, str) or not name or "[redacted]" in name.lower():
                return None, "item sin metadata.name en " + command_id
            namespace = metadata.get("namespace", "")
            if kind in ("Role", "RoleBinding") and (not isinstance(namespace, str) or not namespace):
                return None, "objeto namespaced sin metadata.namespace"
            if kind in ("ClusterRole", "Role"):
                rules = item.get("rules", [])
                if not isinstance(rules, list) or any(not isinstance(rule, dict) for rule in rules):
                    return None, "rules inválidas en " + kind + "/" + name
                for rule in rules:
                    for field in ("verbs", "resources", "apiGroups", "nonResourceURLs"):
                        if field in rule and not isinstance(rule.get(field), list):
                            return None, "campo de rule inválido en un rol"
                        values = rule.get(field, [])
                        if any(not isinstance(value, str) or "[redacted]" in value.lower() for value in values):
                            return None, "campo crítico de rule incompleto o redactado"
            else:
                role_ref = item.get("roleRef")
                subjects = item.get("subjects", [])
                if not isinstance(role_ref, dict) or not isinstance(role_ref.get("kind"), str) or not isinstance(role_ref.get("name"), str):
                    return None, "binding sin roleRef estructural"
                if "[redacted]" in role_ref.get("name", "").lower():
                    return None, "binding con roleRef redactado"
                if not isinstance(subjects, list) or any(not isinstance(subject, dict) for subject in subjects):
                    return None, "binding con subjects inválidos"
                for subject in subjects:
                    if not isinstance(subject.get("kind"), str) or not isinstance(subject.get("name"), str):
                        return None, "binding con subject incompleto"
                    if "[redacted]" in subject.get("name", "").lower():
                        return None, "binding con subject crítico redactado"
            inventory.append({"command_id": command_id, "item": item})
            if command_id == "cluster-rbac":
                observed_cluster_kinds.add(kind)
    if "ClusterRole" not in observed_cluster_kinds or "ClusterRoleBinding" not in observed_cluster_kinds:
        return None, "cluster-rbac no contiene ambos tipos ClusterRole y ClusterRoleBinding"
    return inventory, ""


def evaluate(context):
    payloads, problem = _collector_payloads(context)
    if payloads is None:
        return _not_assessed(problem, [])
    inventory, problem = _validate_items(payloads)
    if inventory is None:
        return _not_assessed(problem, [{"collector_id": "kubectl-rbac", "payload_structurally_complete": False}])

    broad_roles = {}
    bindings = []
    role_count = 0
    for row in inventory:
        item = row["item"]
        kind = item.get("kind")
        metadata = item.get("metadata", {})
        name = metadata.get("name", "")
        namespace = metadata.get("namespace", "")
        if kind in ("ClusterRole", "Role"):
            role_count += 1
            reasons = _role_reasons(item.get("rules", []))
            if reasons:
                key = kind + ":" + namespace + ":" + name
                broad_roles[key] = reasons
        else:
            bindings.append(row)

    findings = []
    for row in bindings:
        item = row["item"]
        metadata = item.get("metadata", {})
        binding_kind = item.get("kind", "")
        binding_name = metadata.get("name", "")
        namespace = metadata.get("namespace", "")
        role_ref = item.get("roleRef", {})
        role_kind = role_ref.get("kind", "")
        role_name = role_ref.get("name", "")
        base = {
            "collector_id": "kubectl-rbac",
            "command_id": row["command_id"],
            "binding_kind": binding_kind,
            "binding": binding_name,
            "namespace": namespace or None,
            "role_ref": role_kind + "/" + role_name,
        }
        if role_kind == "ClusterRole" and role_name == "cluster-admin":
            finding = dict(base)
            finding["pattern"] = "cluster-admin-binding"
            findings.append(finding)
        role_namespace = "" if role_kind == "ClusterRole" else namespace
        role_key = role_kind + ":" + role_namespace + ":" + role_name
        if role_key in broad_roles:
            finding = dict(base)
            finding["pattern"] = "broad-role-binding"
            finding["broad_reasons"] = broad_roles[role_key]
            findings.append(finding)
        for subject in item.get("subjects", []):
            subject_kind = str(subject.get("kind", ""))
            subject_name = str(subject.get("name", ""))
            if (subject_kind == "User" and subject_name.lower() in PUBLIC_USERS) or (
                subject_kind == "Group" and subject_name.lower() in PUBLIC_GROUPS
            ):
                finding = dict(base)
                finding["pattern"] = "public-or-anonymous-subject"
                finding["subject"] = subject_kind + "/" + subject_name
                findings.append(finding)
        if len(findings) >= 200:
            break

    if findings:
        return {
            "status": "FAIL",
            "confidence": "HIGH",
            "evidence_level": "E4",
            "summary": "El snapshot runtime contiene bindings a cluster-admin, roles con permisos amplios o subjects públicos/anónimos.",
            "evidence": findings,
            "recommendation": "Eliminar grants públicos, sustituir cluster-admin/wildcards por roles mínimos y revalidar acceso efectivo por identidad.",
        }
    return {
        "status": "PASS",
        "confidence": "HIGH",
        "evidence_level": "E4",
        "summary": "En ambos inventarios RBAC runtime no se observaron los patrones amplios cubiertos por este control.",
        "evidence": [{
            "collector_id": "kubectl-rbac",
            "commands": sorted(REQUIRED_COMMANDS),
            "roles_scanned": role_count,
            "bindings_scanned": len(bindings),
            "scope": "point-in-time RBAC objects, not external identity effectiveness",
        }],
        "recommendation": "Mantener revisión continua de grants, probar permisos efectivos y gobernar toda excepción amplia con owner y expiración.",
    }
