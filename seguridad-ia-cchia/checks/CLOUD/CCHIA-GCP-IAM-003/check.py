"""Evaluación pura de evidencia runtime redacted del collector gcloud-iam."""

def evaluate(context):
    def not_assessed(summary, evidence):
        return {
            "status": "NOT_ASSESSED",
            "confidence": "HIGH",
            "evidence_level": "E0",
            "summary": summary,
            "evidence": evidence,
            "recommendation": "Ejecutar nuevamente gcloud-iam con identidad read-only y conservar los tres comandos requeridos como JSON completo.",
        }

    collectors = context.get("collectors", [])
    if not isinstance(collectors, list):
        return not_assessed(
            "El contexto runtime no contiene una lista de collectors válida.",
            [{"collector_id": "gcloud-iam", "issue": "collectors-not-a-list"}],
        )

    matches = []
    for collector in collectors:
        if isinstance(collector, dict) and collector.get("collector_id") == "gcloud-iam":
            matches.append(collector)
    if len(matches) != 1:
        return not_assessed(
            "Se requiere exactamente una evidencia gcloud-iam para evaluar IAM efectivo.",
            [{"collector_id": "gcloud-iam", "matching_results": len(matches)}],
        )

    collector = matches[0]
    collector_status = collector.get("status")
    if collector_status != "AVAILABLE":
        safe_collector_status = collector_status if collector_status in ("UNAVAILABLE", "ERROR") else "INVALID"
        return not_assessed(
            "El collector gcloud-iam no terminó AVAILABLE; el estado IAM no quedó demostrado.",
            [{"collector_id": "gcloud-iam", "collector_status": safe_collector_status}],
        )
    if collector.get("schema_version") != "1.0" or collector.get("collector_version") != "1.0.0":
        return not_assessed(
            "La versión de la evidencia gcloud-iam no coincide con el contrato evaluado.",
            [{"collector_id": "gcloud-iam", "issue": "unsupported-collector-contract"}],
        )
    if collector.get("mode") != "read_only":
        return not_assessed(
            "La evidencia gcloud-iam no declara mode=read_only.",
            [{"collector_id": "gcloud-iam", "issue": "invalid-mode"}],
        )

    redaction = collector.get("redaction")
    if not isinstance(redaction, dict) or redaction.get("applied") is not True or redaction.get("strategy") != "cchia-default-v1" or redaction.get("replacement") != "[REDACTED]":
        return not_assessed(
            "La evidencia gcloud-iam no acredita el perfil de redacción esperado.",
            [{"collector_id": "gcloud-iam", "issue": "redaction-contract-missing"}],
        )

    evidence_hash = collector.get("evidence_sha256")
    if not isinstance(evidence_hash, str) or len(evidence_hash) != 64 or not all(character in "0123456789abcdef" for character in evidence_hash):
        return not_assessed(
            "La evidencia gcloud-iam no contiene un hash canónico válido.",
            [{"collector_id": "gcloud-iam", "issue": "invalid-evidence-hash"}],
        )

    provenance = collector.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("provider") != "gcp":
        return not_assessed(
            "La provenance no identifica una consulta GCP válida.",
            [{"collector_id": "gcloud-iam", "issue": "invalid-provider-provenance"}],
        )
    interface = provenance.get("interface")
    if not isinstance(interface, dict) or interface.get("tool") != "gcloud" or interface.get("executable_available") is not True or not isinstance(interface.get("resolved_executable"), str) or not interface.get("resolved_executable").strip():
        return not_assessed(
            "La provenance no demuestra un cliente gcloud disponible.",
            [{"collector_id": "gcloud-iam", "issue": "invalid-interface-provenance"}],
        )

    required = {
        "project-description": "gcloud.projects.describe.v1",
        "project-iam-policy": "gcloud.projects.get-iam-policy.v1",
        "service-accounts": "gcloud.iam.service-accounts.list.v1",
    }
    commands = provenance.get("commands")
    if not isinstance(commands, list):
        return not_assessed(
            "La provenance no contiene la lista de comandos requeridos.",
            [{"collector_id": "gcloud-iam", "issue": "commands-not-a-list"}],
        )
    commands_by_id = {}
    for command in commands:
        if not isinstance(command, dict):
            return not_assessed(
                "La provenance contiene un registro de comando inválido.",
                [{"collector_id": "gcloud-iam", "issue": "invalid-command-record"}],
            )
        command_id = command.get("command_id")
        known_command_id = isinstance(command_id, str) and command_id in required
        if known_command_id:
            if command_id in commands_by_id:
                return not_assessed(
                    "La provenance contiene comandos requeridos duplicados.",
                    [{"collector_id": "gcloud-iam", "command_id": command_id, "issue": "duplicate-command"}],
                )
            commands_by_id[command_id] = command
        if command.get("status") != "AVAILABLE":
            safe_command_id = command_id if known_command_id else "unrecognized-command"
            command_status = command.get("status")
            safe_command_status = command_status if command_status in ("UNAVAILABLE", "ERROR") else "INVALID"
            return not_assessed(
                "Al menos un comando del collector no terminó AVAILABLE.",
                [{"collector_id": "gcloud-iam", "command_id": safe_command_id, "command_status": safe_command_status}],
            )
    for command_id, policy_id in required.items():
        command = commands_by_id.get(command_id)
        command_hash = command.get("stdout_sha256") if isinstance(command, dict) else None
        valid_command_hash = isinstance(command_hash, str) and len(command_hash) == 64 and all(character in "0123456789abcdef" for character in command_hash)
        if not isinstance(command, dict) or command.get("policy_id") != policy_id or command.get("status") != "AVAILABLE" or command.get("exit_code") != 0 or not valid_command_hash:
            return not_assessed(
                "No se demostró la ejecución exitosa de todos los comandos gcloud-iam requeridos.",
                [{"collector_id": "gcloud-iam", "command_id": command_id, "issue": "required-command-incomplete"}],
            )

    runtime_evidence = collector.get("evidence")
    if not isinstance(runtime_evidence, list):
        return not_assessed(
            "El collector no contiene una lista de evidencia runtime válida.",
            [{"collector_id": "gcloud-iam", "issue": "evidence-not-a-list"}],
        )
    evidence_by_id = {}
    for item in runtime_evidence:
        if not isinstance(item, dict):
            return not_assessed(
                "El collector contiene un elemento de evidencia inválido.",
                [{"collector_id": "gcloud-iam", "issue": "invalid-evidence-record"}],
            )
        command_id = item.get("command_id")
        known_command_id = isinstance(command_id, str) and command_id in required
        if known_command_id:
            if command_id in evidence_by_id:
                return not_assessed(
                    "El collector contiene payloads requeridos duplicados.",
                    [{"collector_id": "gcloud-iam", "command_id": command_id, "issue": "duplicate-evidence"}],
                )
            evidence_by_id[command_id] = item
        if item.get("status") != "AVAILABLE":
            safe_command_id = command_id if known_command_id else "unrecognized-command"
            evidence_status = item.get("status")
            safe_evidence_status = evidence_status if evidence_status == "ERROR" else "INVALID"
            return not_assessed(
                "Al menos un payload del collector no terminó AVAILABLE.",
                [{"collector_id": "gcloud-iam", "command_id": safe_command_id, "evidence_status": safe_evidence_status}],
            )
    for command_id in required:
        item = evidence_by_id.get(command_id)
        if not isinstance(item, dict) or item.get("status") != "AVAILABLE" or item.get("content_type") != "application/json":
            return not_assessed(
                "Falta evidencia JSON AVAILABLE para un comando gcloud-iam requerido.",
                [{"collector_id": "gcloud-iam", "command_id": command_id, "issue": "required-payload-incomplete"}],
            )

    project = evidence_by_id["project-description"].get("data")
    if not isinstance(project, dict) or not isinstance(project.get("projectId"), str) or not project.get("projectId").strip() or "[redacted]" in project.get("projectId").lower():
        return not_assessed(
            "El payload de descripción del proyecto no tiene estructura suficiente.",
            [{"collector_id": "gcloud-iam", "command_id": "project-description", "issue": "invalid-project-payload"}],
        )

    service_accounts = evidence_by_id["service-accounts"].get("data")
    if not isinstance(service_accounts, list) or not all(isinstance(account, dict) for account in service_accounts):
        return not_assessed(
            "El payload de service accounts no tiene estructura suficiente.",
            [{"collector_id": "gcloud-iam", "command_id": "service-accounts", "issue": "invalid-service-account-payload"}],
        )

    policy = evidence_by_id["project-iam-policy"].get("data")
    if not isinstance(policy, dict) or "bindings" not in policy or not isinstance(policy.get("bindings"), list):
        return not_assessed(
            "El payload IAM no contiene una lista de bindings estructuralmente válida.",
            [{"collector_id": "gcloud-iam", "command_id": "project-iam-policy", "issue": "invalid-policy-payload"}],
        )

    findings = []
    basic_roles = ("roles/owner", "roles/editor", "roles/viewer")
    public_members = {
        "allusers": "allUsers",
        "allauthenticatedusers": "allAuthenticatedUsers",
    }
    for binding_index, binding in enumerate(policy.get("bindings")):
        if not isinstance(binding, dict):
            return not_assessed(
                "El payload IAM contiene un binding no estructurado.",
                [{"collector_id": "gcloud-iam", "binding_index": binding_index, "issue": "invalid-binding"}],
            )
        role = binding.get("role")
        members = binding.get("members")
        if not isinstance(role, str) or not role.strip() or not isinstance(members, list) or not members or not all(isinstance(member, str) and member.strip() for member in members):
            return not_assessed(
                "El payload IAM contiene un binding incompleto.",
                [{"collector_id": "gcloud-iam", "binding_index": binding_index, "issue": "incomplete-binding"}],
            )
        normalized_role = role.strip().lower()
        normalized_members = [member.strip().lower() for member in members]
        if "[redacted]" in normalized_role or any("[redacted]" in member for member in normalized_members):
            return not_assessed(
                "La redacción ocultó un rol o principal necesario para evaluar el binding.",
                [{"collector_id": "gcloud-iam", "binding_index": binding_index, "issue": "critical-field-redacted"}],
            )
        patterns = []
        public_observed = []
        if normalized_role in basic_roles:
            patterns.append("basic-role")
        for member in normalized_members:
            if member in public_members and public_members[member] not in public_observed:
                public_observed.append(public_members[member])
        if public_observed:
            patterns.append("public-principal")
        if patterns:
            finding = {
                "collector_id": "gcloud-iam",
                "command_id": "project-iam-policy",
                "binding_index": binding_index,
                "patterns": patterns,
                "condition_present": isinstance(binding.get("condition"), dict),
            }
            if normalized_role in basic_roles:
                finding["basic_role"] = normalized_role
            if public_observed:
                finding["public_members"] = public_observed
            findings.append(finding)

    if findings:
        return {
            "status": "FAIL",
            "confidence": "HIGH",
            "evidence_level": "E4",
            "summary": "El snapshot IAM efectivo contiene roles básicos o principals públicos.",
            "evidence": findings,
            "recommendation": "Eliminar principals públicos no justificados y sustituir roles básicos por roles predefinidos/custom mínimos; verificar nuevamente IAM efectivo.",
        }

    return {
        "status": "PASS",
        "confidence": "HIGH",
        "evidence_level": "E4",
        "summary": "El snapshot IAM efectivo no contiene roles/owner, roles/editor, roles/viewer, allUsers ni allAuthenticatedUsers en los bindings observados.",
        "evidence": [{
            "collector_id": "gcloud-iam",
            "command_id": "project-iam-policy",
            "commands_verified": len(required),
            "bindings_evaluated": len(policy.get("bindings")),
            "service_accounts_observed": len(service_accounts),
            "collector_evidence_sha256": evidence_hash,
        }],
        "recommendation": "Mantener roles granulares y monitoreo continuo; repetir el collector para detectar drift y revisar herencia/recursos fuera del snapshot de proyecto.",
    }
