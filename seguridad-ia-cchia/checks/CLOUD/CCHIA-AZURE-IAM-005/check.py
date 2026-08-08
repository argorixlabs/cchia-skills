"""Evaluación pura de evidencia runtime redacted del collector Azure RBAC."""

def evaluate(context):
    def not_assessed(summary, evidence):
        return {
            "status": "NOT_ASSESSED",
            "confidence": "HIGH",
            "evidence_level": "E0",
            "summary": summary,
            "evidence": evidence,
            "recommendation": "Ejecutar nuevamente az-role-assignments con identidad read-only y conservar ambos comandos JSON completos.",
        }

    def valid_hash(value):
        return isinstance(value, str) and len(value) == 64 and all(
            character in "0123456789abcdef" for character in value
        )

    def valid_uuid(value):
        if not isinstance(value, str):
            return False
        parts = value.strip().lower().split("-")
        return len(parts) == 5 and [len(part) for part in parts] == [8, 4, 4, 4, 12] and all(
            character in "0123456789abcdef" for part in parts for character in part
        )

    def valid_subscription_selector(value):
        if not isinstance(value, str) or not value or value != value.strip() or len(value) > 128 or ".." in value:
            return False
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._()-"
        return all(character in allowed for character in value)

    def command_subscription(command_id, argv):
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            return {"valid": False, "subscription": None}
        if command_id == "azure-account":
            if argv == ["az", "account", "show", "--output", "json"]:
                return {"valid": True, "subscription": None}
            if len(argv) == 7 and argv[:3] == ["az", "account", "show"] and argv[3] == "--subscription" and argv[5:] == ["--output", "json"] and valid_subscription_selector(argv[4]):
                return {"valid": True, "subscription": argv[4]}
        if command_id == "role-assignments":
            if argv == ["az", "role", "assignment", "list", "--all", "--output", "json"]:
                return {"valid": True, "subscription": None}
            if len(argv) == 9 and argv[:5] == ["az", "role", "assignment", "list", "--all"] and argv[5] == "--subscription" and argv[7:] == ["--output", "json"] and valid_subscription_selector(argv[6]):
                return {"valid": True, "subscription": argv[6]}
        return {"valid": False, "subscription": None}

    collectors = context.get("collectors", [])
    if not isinstance(collectors, list):
        return not_assessed(
            "El contexto runtime no contiene una lista de collectors válida.",
            [{"collector_id": "az-role-assignments", "issue": "collectors-not-a-list"}],
        )
    matches = []
    for collector in collectors:
        if isinstance(collector, dict) and collector.get("collector_id") == "az-role-assignments":
            matches.append(collector)
    if len(matches) != 1:
        return not_assessed(
            "Se requiere exactamente una evidencia az-role-assignments para evaluar Azure RBAC.",
            [{"collector_id": "az-role-assignments", "matching_results": len(matches)}],
        )

    collector = matches[0]
    collector_status = collector.get("status")
    if collector_status != "AVAILABLE":
        safe_status = collector_status if collector_status in ("UNAVAILABLE", "ERROR") else "INVALID"
        return not_assessed(
            "El collector Azure no terminó AVAILABLE; Azure RBAC no quedó demostrado.",
            [{"collector_id": "az-role-assignments", "collector_status": safe_status}],
        )
    if collector.get("schema_version") != "1.0" or collector.get("collector_version") != "1.0.0":
        return not_assessed(
            "La versión de la evidencia Azure no coincide con el contrato evaluado.",
            [{"collector_id": "az-role-assignments", "issue": "unsupported-collector-contract"}],
        )
    if collector.get("mode") != "read_only":
        return not_assessed(
            "La evidencia Azure no declara mode=read_only.",
            [{"collector_id": "az-role-assignments", "issue": "invalid-mode"}],
        )
    redaction = collector.get("redaction")
    if not isinstance(redaction, dict) or redaction.get("applied") is not True or redaction.get("strategy") != "cchia-default-v1" or redaction.get("replacement") != "[REDACTED]":
        return not_assessed(
            "La evidencia Azure no acredita el perfil de redacción esperado.",
            [{"collector_id": "az-role-assignments", "issue": "redaction-contract-missing"}],
        )
    evidence_hash = collector.get("evidence_sha256")
    if not valid_hash(evidence_hash):
        return not_assessed(
            "La evidencia Azure no contiene un hash canónico con formato válido.",
            [{"collector_id": "az-role-assignments", "issue": "invalid-evidence-hash"}],
        )

    provenance = collector.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("provider") != "azure":
        return not_assessed(
            "La provenance no identifica una consulta Azure válida.",
            [{"collector_id": "az-role-assignments", "issue": "invalid-provider-provenance"}],
        )
    interface = provenance.get("interface")
    if not isinstance(interface, dict) or interface.get("kind") != "command" or interface.get("tool") != "az" or interface.get("sdk") != "Azure CLI" or interface.get("executable_available") is not True or not isinstance(interface.get("resolved_executable"), str) or not interface.get("resolved_executable").strip():
        return not_assessed(
            "La provenance no demuestra un cliente Azure CLI resuelto.",
            [{"collector_id": "az-role-assignments", "issue": "invalid-interface-provenance"}],
        )

    required = {
        "azure-account": "az.account.show.v1",
        "role-assignments": "az.role.assignment.list.v1",
    }
    commands = provenance.get("commands")
    if not isinstance(commands, list):
        return not_assessed(
            "La provenance no contiene una lista de comandos Azure válida.",
            [{"collector_id": "az-role-assignments", "issue": "commands-not-a-list"}],
        )
    commands_by_id = {}
    subscriptions = []
    for command in commands:
        if not isinstance(command, dict):
            return not_assessed(
                "La provenance contiene un comando no estructurado.",
                [{"collector_id": "az-role-assignments", "issue": "invalid-command-record"}],
            )
        command_id = command.get("command_id")
        if not isinstance(command_id, str) or command_id not in required:
            return not_assessed(
                "La provenance contiene un comando fuera del contrato Azure.",
                [{"collector_id": "az-role-assignments", "issue": "unexpected-command"}],
            )
        if command_id in commands_by_id:
            return not_assessed(
                "La provenance contiene un comando Azure duplicado.",
                [{"collector_id": "az-role-assignments", "command_id": command_id, "issue": "duplicate-command"}],
            )
        shape = command_subscription(command_id, command.get("argv"))
        if command.get("policy_id") != required[command_id] or command.get("status") != "AVAILABLE" or command.get("exit_code") != 0 or not valid_hash(command.get("stdout_sha256")) or not shape["valid"]:
            return not_assessed(
                "No se demostró la ejecución allow-listed de un comando Azure requerido.",
                [{"collector_id": "az-role-assignments", "command_id": command_id, "issue": "required-command-incomplete"}],
            )
        commands_by_id[command_id] = command
        subscriptions.append(shape["subscription"])
    if len(commands_by_id) != len(required) or subscriptions[0] != subscriptions[1]:
        return not_assessed(
            "Los dos comandos Azure no demuestran una selección de suscripción coherente.",
            [{"collector_id": "az-role-assignments", "issue": "subscription-selector-mismatch"}],
        )

    runtime_evidence = collector.get("evidence")
    if not isinstance(runtime_evidence, list):
        return not_assessed(
            "El collector Azure no contiene una lista de evidencia válida.",
            [{"collector_id": "az-role-assignments", "issue": "evidence-not-a-list"}],
        )
    evidence_by_id = {}
    for item in runtime_evidence:
        if not isinstance(item, dict):
            return not_assessed(
                "El collector Azure contiene evidencia no estructurada.",
                [{"collector_id": "az-role-assignments", "issue": "invalid-evidence-record"}],
            )
        command_id = item.get("command_id")
        if not isinstance(command_id, str) or command_id not in required:
            return not_assessed(
                "El collector Azure contiene evidencia fuera del contrato.",
                [{"collector_id": "az-role-assignments", "issue": "unexpected-evidence"}],
            )
        if command_id in evidence_by_id:
            return not_assessed(
                "El collector Azure contiene payloads duplicados.",
                [{"collector_id": "az-role-assignments", "command_id": command_id, "issue": "duplicate-evidence"}],
            )
        if item.get("status") != "AVAILABLE" or item.get("content_type") != "application/json":
            return not_assessed(
                "Un payload Azure requerido no es JSON AVAILABLE; puede estar ausente, errado o truncado.",
                [{"collector_id": "az-role-assignments", "command_id": command_id, "issue": "required-payload-incomplete"}],
            )
        evidence_by_id[command_id] = item
    if len(evidence_by_id) != len(required):
        return not_assessed(
            "Falta evidencia JSON de un comando Azure requerido.",
            [{"collector_id": "az-role-assignments", "issue": "required-payload-missing"}],
        )

    account = evidence_by_id["azure-account"].get("data")
    if not isinstance(account, dict) or not valid_uuid(account.get("id")) or not valid_uuid(account.get("tenantId")):
        return not_assessed(
            "El payload az account show no identifica suscripción y tenant con estructura suficiente.",
            [{"collector_id": "az-role-assignments", "command_id": "azure-account", "issue": "invalid-account-payload"}],
        )
    subscription_selector = subscriptions[0]
    if valid_uuid(subscription_selector) and subscription_selector.lower() != account.get("id").lower():
        return not_assessed(
            "La suscripción solicitada no coincide con el account payload.",
            [{"collector_id": "az-role-assignments", "issue": "subscription-account-mismatch"}],
        )

    assignments = evidence_by_id["role-assignments"].get("data")
    if not isinstance(assignments, list):
        return not_assessed(
            "El payload de role assignments no es una lista completa evaluable.",
            [{"collector_id": "az-role-assignments", "command_id": "role-assignments", "issue": "invalid-assignments-payload"}],
        )

    owner_id = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
    access_admin_id = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"
    known_principal_types = ("user", "group", "serviceprincipal", "managedidentity", "foreigngroup", "device")
    public_names = ("*", "allusers", "all users", "allauthenticatedusers", "all authenticated users", "everyone", "anonymous", "public")
    subscription_scope = "/subscriptions/" + account.get("id").lower()
    findings = []
    total_findings = 0
    for assignment_index, assignment in enumerate(assignments):
        if not isinstance(assignment, dict):
            return not_assessed(
                "El payload Azure contiene una asignación no estructurada.",
                [{"collector_id": "az-role-assignments", "assignment_index": assignment_index, "issue": "invalid-assignment"}],
            )
        role_name = assignment.get("roleDefinitionName")
        role_id = assignment.get("roleDefinitionId")
        scope = assignment.get("scope")
        principal_id = assignment.get("principalId")
        principal_type = assignment.get("principalType")
        principal_name = assignment.get("principalName")
        if not isinstance(role_name, str) or not role_name.strip() or not isinstance(role_id, str) or not role_id.strip() or not isinstance(scope, str) or not scope.strip() or not valid_uuid(principal_id) or not isinstance(principal_type, str) or not principal_type.strip() or (principal_name is not None and not isinstance(principal_name, str)):
            return not_assessed(
                "Una asignación Azure no contiene todos los campos críticos evaluables.",
                [{"collector_id": "az-role-assignments", "assignment_index": assignment_index, "issue": "incomplete-assignment"}],
            )
        critical_values = [role_name, role_id, scope, principal_id, principal_type]
        if isinstance(principal_name, str):
            critical_values.append(principal_name)
        if any("[redacted]" in value.lower() for value in critical_values):
            return not_assessed(
                "La redacción ocultó un campo crítico de una asignación Azure.",
                [{"collector_id": "az-role-assignments", "assignment_index": assignment_index, "issue": "critical-field-redacted"}],
            )
        role_uuid = role_id.strip().lower().split("/")[-1]
        if not valid_uuid(role_uuid) or not scope.strip().startswith("/"):
            return not_assessed(
                "Una asignación contiene roleDefinitionId o scope no normalizable.",
                [{"collector_id": "az-role-assignments", "assignment_index": assignment_index, "issue": "invalid-role-or-scope"}],
            )

        normalized_role = role_name.strip().lower()
        privileged_role = None
        if normalized_role == "owner" or role_uuid == owner_id:
            privileged_role = "Owner"
        elif normalized_role == "user access administrator" or role_uuid == access_admin_id:
            privileged_role = "User Access Administrator"

        normalized_scope = scope.strip().lower()
        if normalized_scope != "/":
            normalized_scope = normalized_scope.rstrip("/")
        broad_scope = None
        if normalized_scope == "/":
            broad_scope = "root"
        elif normalized_scope == subscription_scope:
            broad_scope = "subscription"
        elif normalized_scope.startswith("/providers/microsoft.management/managementgroups/"):
            broad_scope = "management-group"

        normalized_type = principal_type.strip().lower()
        normalized_name = principal_name.strip().lower() if isinstance(principal_name, str) else None
        patterns = []
        principal_pattern = None
        if privileged_role is not None and broad_scope is not None:
            patterns.append("privileged-role-broad-scope")
        if normalized_type not in known_principal_types:
            patterns.append("unknown-principal")
            principal_pattern = "unknown"
        if normalized_name in public_names:
            patterns.append("public-like-principal")
            principal_pattern = "public-like"
        if patterns:
            total_findings += 1
            if len(findings) < 20:
                finding = {
                    "collector_id": "az-role-assignments",
                    "command_id": "role-assignments",
                    "assignment_index": assignment_index,
                    "patterns": patterns,
                }
                if privileged_role is not None and broad_scope is not None:
                    finding["privileged_role"] = privileged_role
                    finding["broad_scope"] = broad_scope
                if principal_pattern is not None:
                    finding["principal_pattern"] = principal_pattern
                findings.append(finding)

    if findings:
        if total_findings > len(findings):
            findings.append({
                "collector_id": "az-role-assignments",
                "command_id": "role-assignments",
                "issue": "finding-evidence-truncated",
                "total_findings": total_findings,
                "reported_findings": len(findings),
            })
        return {
            "status": "FAIL",
            "confidence": "HIGH",
            "evidence_level": "E4",
            "summary": "El snapshot Azure RBAC contiene roles privilegiados en scopes amplios o principals anómalos.",
            "evidence": findings,
            "recommendation": "Reducir scopes/roles, eliminar principals desconocidos o public-like y volver a recolectar Azure RBAC con identidad read-only.",
        }

    return {
        "status": "PASS",
        "confidence": "HIGH",
        "evidence_level": "E4",
        "summary": "El snapshot observado no contiene Owner/User Access Administrator en scopes amplios ni principals desconocidos/public-like.",
        "evidence": [{
            "collector_id": "az-role-assignments",
            "command_id": "role-assignments",
            "commands_verified": len(required),
            "assignments_evaluated": len(assignments),
            "collector_evidence_sha256": evidence_hash,
        }],
        "recommendation": "Mantener mínimo privilegio y monitoreo continuo; revisar aparte herencia, PIM, custom roles, Entra roles y drift.",
    }
