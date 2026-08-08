"""Evalúa evidencia runtime redacted del collector AWS IAM sin exponer principals."""

REQUIRED_COMMANDS = {
    "caller-identity": (
        "aws.sts.get-caller-identity.v1",
        ("sts", "get-caller-identity", "--output", "json"),
    ),
    "account-summary": (
        "aws.iam.get-account-summary.v1",
        ("iam", "get-account-summary", "--output", "json"),
    ),
    "account-authorization-details": (
        "aws.iam.get-account-authorization-details.v1",
        (
            "iam",
            "get-account-authorization-details",
            "--filter",
            "User",
            "Role",
            "Group",
            "LocalManagedPolicy",
            "--output",
            "json",
        ),
    ),
}

ENTITY_LISTS = (
    ("UserDetailList", "User", "UserPolicyList"),
    ("RoleDetailList", "Role", "RolePolicyList"),
    ("GroupDetailList", "Group", "GroupPolicyList"),
)


def _not_assessed(reason, evidence):
    return {
        "status": "NOT_ASSESSED",
        "confidence": "LOW",
        "evidence_level": "E0",
        "summary": "La evidencia AWS IAM no permite una conclusión: " + reason,
        "evidence": evidence,
        "recommendation": "Ejecutar aws-iam con identidad read-only y conservar los tres payloads JSON completos, sin truncado ni campos críticos redactados.",
    }


def _is_sha256(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_string(value):
    if not isinstance(value, str) or not value.strip():
        return False
    normalized = value.lower()
    return "[redacted]" not in normalized and "[truncated" not in normalized


def _safe_profile(value):
    if not _safe_string(value) or len(value) > 128 or value.startswith("-") or ".." in value:
        return False
    letters_and_digits = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    allowed = letters_and_digits + "_.@-"
    return value[0] in letters_and_digits and all(character in allowed for character in value)


def _argv_profile(argv, expected_tail):
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        return False, ""
    if not argv or argv[0] != "aws":
        return False, ""
    if len(argv) > 2 and argv[1] == "--profile":
        profile = argv[2]
        if not _safe_profile(profile):
            return False, ""
        return tuple(argv[3:]) == expected_tail, profile
    return tuple(argv[1:]) == expected_tail, ""


def _string_values(value):
    if isinstance(value, str):
        return [value] if _safe_string(value) else None
    if not isinstance(value, list) or not value:
        return None
    if not all(_safe_string(item) for item in value):
        return None
    return value


def _policy_patterns(document):
    if not isinstance(document, dict):
        return None, "policy document no es un objeto JSON"
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return None, "policy document no contiene Statement estructurado"

    patterns = []
    for statement_index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            return None, "policy document contiene un Statement inválido"
        effect = statement.get("Effect")
        if effect not in ("Allow", "Deny"):
            return None, "policy document contiene Effect inválido"
        has_action = "Action" in statement
        has_not_action = "NotAction" in statement
        if has_action == has_not_action:
            return None, "Statement debe declarar exactamente Action o NotAction"
        action_key = "Action" if has_action else "NotAction"
        actions = _string_values(statement.get(action_key))
        if actions is None:
            return None, "Statement contiene acciones incompletas o redactadas"

        has_resource = "Resource" in statement
        has_not_resource = "NotResource" in statement
        if has_resource == has_not_resource:
            return None, "Statement debe declarar exactamente Resource o NotResource"
        resource_key = "Resource" if has_resource else "NotResource"
        resources = _string_values(statement.get(resource_key))
        if resources is None:
            return None, "Statement contiene resources incompletos o redactados"
        condition = statement.get("Condition")
        if condition is not None and not isinstance(condition, dict):
            return None, "Statement contiene Condition inválida"

        if effect == "Allow":
            if has_not_action:
                patterns.append(
                    {
                        "statement_index": statement_index,
                        "pattern": "allow-not-action",
                        "resource_global": any(item == "*" for item in resources),
                    }
                )
            elif any("*" in item for item in actions):
                patterns.append(
                    {
                        "statement_index": statement_index,
                        "pattern": "allow-action-wildcard",
                        "resource_global": any(item == "*" for item in resources),
                    }
                )
    return patterns, ""


def _is_aws_managed_policy(policy_arn):
    return ":iam::aws:policy/" in policy_arn


def _is_aws_administrator_access(policy_name, policy_arn):
    return (
        policy_name == "AdministratorAccess"
        and policy_arn.endswith(":iam::aws:policy/AdministratorAccess")
    )


def _collector_payload(context):
    collectors = context.get("collectors", [])
    if not isinstance(collectors, list):
        return None, _not_assessed(
            "context.collectors no es una lista",
            [{"collector_id": "aws-iam", "issue": "collectors-not-a-list"}],
        )
    matches = []
    for collector in collectors:
        if isinstance(collector, dict) and collector.get("collector_id") == "aws-iam":
            matches.append(collector)
    if len(matches) != 1:
        return None, _not_assessed(
            "se requiere exactamente un resultado aws-iam",
            [{"collector_id": "aws-iam", "matching_results": len(matches)}],
        )

    collector = matches[0]
    status = collector.get("status")
    if status != "AVAILABLE":
        safe_status = status if status in ("UNAVAILABLE", "ERROR") else "INVALID"
        return None, _not_assessed(
            "aws-iam no terminó AVAILABLE",
            [{"collector_id": "aws-iam", "collector_status": safe_status}],
        )
    if collector.get("schema_version") != "1.0" or collector.get("collector_version") != "1.0.0":
        return None, _not_assessed(
            "la versión del collector no coincide con el contrato evaluado",
            [{"collector_id": "aws-iam", "issue": "unsupported-collector-contract"}],
        )
    if collector.get("mode") != "read_only":
        return None, _not_assessed(
            "el collector no acredita mode=read_only",
            [{"collector_id": "aws-iam", "issue": "invalid-mode"}],
        )
    redaction = collector.get("redaction")
    if (
        not isinstance(redaction, dict)
        or redaction.get("applied") is not True
        or redaction.get("strategy") != "cchia-default-v1"
        or redaction.get("replacement") != "[REDACTED]"
    ):
        return None, _not_assessed(
            "el perfil de redacción no está acreditado",
            [{"collector_id": "aws-iam", "issue": "redaction-contract-missing"}],
        )
    evidence_hash = collector.get("evidence_sha256")
    if not _is_sha256(evidence_hash):
        return None, _not_assessed(
            "el hash de evidencia no tiene forma canónica válida",
            [{"collector_id": "aws-iam", "issue": "invalid-evidence-hash"}],
        )

    provenance = collector.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("provider") != "aws":
        return None, _not_assessed(
            "la provenance no identifica AWS",
            [{"collector_id": "aws-iam", "issue": "invalid-provider-provenance"}],
        )
    interface = provenance.get("interface")
    if (
        not isinstance(interface, dict)
        or interface.get("kind") != "command"
        or interface.get("tool") != "aws"
        or interface.get("sdk") != "AWS CLI"
        or interface.get("executable_available") is not True
        or not _safe_string(interface.get("resolved_executable"))
    ):
        return None, _not_assessed(
            "la provenance no demuestra un AWS CLI disponible",
            [{"collector_id": "aws-iam", "issue": "invalid-interface-provenance"}],
        )

    commands = provenance.get("commands")
    if not isinstance(commands, list) or len(commands) != len(REQUIRED_COMMANDS):
        return None, _not_assessed(
            "la provenance no contiene exactamente los tres comandos requeridos",
            [{"collector_id": "aws-iam", "issue": "command-set-incomplete"}],
        )
    commands_by_id = {}
    expected_profile = None
    for command in commands:
        if not isinstance(command, dict):
            return None, _not_assessed(
                "la provenance contiene metadata de comando inválida",
                [{"collector_id": "aws-iam", "issue": "invalid-command-record"}],
            )
        command_id = command.get("command_id")
        if not isinstance(command_id, str) or command_id not in REQUIRED_COMMANDS or command_id in commands_by_id:
            return None, _not_assessed(
                "la provenance contiene un comando desconocido o duplicado",
                [{"collector_id": "aws-iam", "issue": "invalid-command-identity"}],
            )
        policy_id, expected_tail = REQUIRED_COMMANDS[command_id]
        argv_valid, profile = _argv_profile(command.get("argv"), expected_tail)
        if expected_profile is None:
            expected_profile = profile
        if (
            command.get("policy_id") != policy_id
            or command.get("status") != "AVAILABLE"
            or command.get("exit_code") != 0
            or not _is_sha256(command.get("stdout_sha256"))
            or not argv_valid
            or profile != expected_profile
        ):
            return None, _not_assessed(
                "un comando requerido no acredita policy, argv, status o hash válidos",
                [{"collector_id": "aws-iam", "command_id": command_id, "issue": "required-command-incomplete"}],
            )
        commands_by_id[command_id] = command

    rows = collector.get("evidence")
    if not isinstance(rows, list) or len(rows) != len(REQUIRED_COMMANDS):
        return None, _not_assessed(
            "el collector no contiene exactamente los tres payloads requeridos",
            [{"collector_id": "aws-iam", "issue": "evidence-set-incomplete"}],
        )
    evidence_by_id = {}
    for row in rows:
        if not isinstance(row, dict):
            return None, _not_assessed(
                "el collector contiene metadata de evidencia inválida",
                [{"collector_id": "aws-iam", "issue": "invalid-evidence-record"}],
            )
        command_id = row.get("command_id")
        if not isinstance(command_id, str) or command_id not in REQUIRED_COMMANDS or command_id in evidence_by_id:
            return None, _not_assessed(
                "el collector contiene un payload desconocido o duplicado",
                [{"collector_id": "aws-iam", "issue": "invalid-evidence-identity"}],
            )
        if (
            row.get("status") != "AVAILABLE"
            or row.get("content_type") != "application/json"
            or not isinstance(row.get("data"), dict)
        ):
            return None, _not_assessed(
                "un payload requerido no es JSON AVAILABLE",
                [{"collector_id": "aws-iam", "command_id": command_id, "issue": "required-payload-incomplete"}],
            )
        evidence_by_id[command_id] = row.get("data")
    return {
        "collector": collector,
        "evidence_hash": evidence_hash,
        "payloads": evidence_by_id,
    }, None


def _validate_identity(payload):
    account = payload.get("Account")
    user_id = payload.get("UserId")
    arn = payload.get("Arn")
    if (
        not _safe_string(account)
        or len(account) != 12
        or not all(character in "0123456789" for character in account)
        or not _safe_string(user_id)
        or not _safe_string(arn)
        or not arn.startswith("arn:")
        or account not in arn
    ):
        return False
    return True


def _evaluate_authorization(payload):
    if payload.get("IsTruncated") is not False:
        return None, None, "el inventario IAM está truncado o no acredita IsTruncated=false"
    if payload.get("Marker") not in (None, "") or payload.get("NextToken") not in (None, ""):
        return None, None, "el inventario IAM contiene continuidad de paginación pendiente"

    findings = []
    counters = {
        "principals": 0,
        "inline_policies": 0,
        "local_managed_policies": 0,
    }
    attached_policy_arns = set()
    for list_name, principal_type, inline_name in ENTITY_LISTS:
        entities = payload.get(list_name)
        if not isinstance(entities, list):
            return None, None, list_name + " no es una lista completa"
        for entity_index, entity in enumerate(entities):
            if not isinstance(entity, dict):
                return None, None, list_name + " contiene un principal no estructurado"
            counters["principals"] += 1
            attached = entity.get("AttachedManagedPolicies")
            inline = entity.get(inline_name)
            if not isinstance(attached, list) or not isinstance(inline, list):
                return None, None, "un principal no contiene listas completas de políticas"
            for attachment_index, attachment in enumerate(attached):
                if not isinstance(attachment, dict):
                    return None, None, "AttachedManagedPolicies contiene metadata inválida"
                policy_name = attachment.get("PolicyName")
                policy_arn = attachment.get("PolicyArn")
                if not _safe_string(policy_name) or not _safe_string(policy_arn):
                    return None, None, "una política adjunta tiene campos críticos incompletos o redactados"
                attached_policy_arns.add(policy_arn)
                if _is_aws_administrator_access(policy_name, policy_arn):
                    findings.append(
                        {
                            "collector_id": "aws-iam",
                            "command_id": "account-authorization-details",
                            "pattern": "administrator-access-attached",
                            "principal_type": principal_type,
                            "principal_index": entity_index,
                            "attachment_index": attachment_index,
                        }
                    )
            for policy_index, policy in enumerate(inline):
                if not isinstance(policy, dict) or not _safe_string(policy.get("PolicyName")):
                    return None, None, "una política inline tiene metadata incompleta o redactada"
                patterns, problem = _policy_patterns(policy.get("PolicyDocument"))
                if patterns is None:
                    return None, None, problem
                counters["inline_policies"] += 1
                for pattern in patterns:
                    finding = {
                        "collector_id": "aws-iam",
                        "command_id": "account-authorization-details",
                        "principal_type": principal_type,
                        "principal_index": entity_index,
                        "policy_source": "inline",
                        "policy_index": policy_index,
                    }
                    finding.update(pattern)
                    findings.append(finding)

    policies = payload.get("Policies")
    if not isinstance(policies, list):
        return None, None, "Policies no es una lista completa"
    local_policy_arns = set()
    for policy_index, policy in enumerate(policies):
        if (
            not isinstance(policy, dict)
            or not _safe_string(policy.get("PolicyName"))
            or not _safe_string(policy.get("Arn"))
            or not _safe_string(policy.get("DefaultVersionId"))
        ):
            return None, None, "una política local tiene metadata incompleta o redactada"
        policy_arn = policy.get("Arn")
        if policy_arn in local_policy_arns:
            return None, None, "Policies contiene una política local duplicada"
        local_policy_arns.add(policy_arn)
        versions = policy.get("PolicyVersionList")
        if not isinstance(versions, list) or not versions:
            return None, None, "una política local no contiene versiones estructuradas"
        default_versions = []
        for version in versions:
            if (
                not isinstance(version, dict)
                or not _safe_string(version.get("VersionId"))
                or not isinstance(version.get("IsDefaultVersion"), bool)
            ):
                return None, None, "una versión de política local tiene metadata inválida"
            if version.get("IsDefaultVersion") is True:
                default_versions.append(version)
        if (
            len(default_versions) != 1
            or default_versions[0].get("VersionId") != policy.get("DefaultVersionId")
        ):
            return None, None, "la versión efectiva de una política local es ambigua"
        if policy_arn in attached_policy_arns:
            patterns, problem = _policy_patterns(default_versions[0].get("Document"))
            if patterns is None:
                return None, None, problem
            counters["local_managed_policies"] += 1
            for pattern in patterns:
                finding = {
                    "collector_id": "aws-iam",
                    "command_id": "account-authorization-details",
                    "policy_source": "local-managed",
                    "policy_index": policy_index,
                }
                finding.update(pattern)
                findings.append(finding)

    for policy_arn in attached_policy_arns:
        if not _is_aws_managed_policy(policy_arn) and policy_arn not in local_policy_arns:
            return None, None, "una política local adjunta no tiene documento evaluable en Policies"

    return findings[:200], counters, ""


def evaluate(context):
    runtime, result = _collector_payload(context)
    if runtime is None:
        return result
    payloads = runtime["payloads"]
    if not _validate_identity(payloads["caller-identity"]):
        return _not_assessed(
            "caller identity no tiene estructura suficiente",
            [{"collector_id": "aws-iam", "command_id": "caller-identity", "issue": "invalid-identity-payload"}],
        )

    account_summary = payloads["account-summary"]
    summary = account_summary.get("SummaryMap")
    if not isinstance(summary, dict):
        return _not_assessed(
            "account summary no contiene SummaryMap",
            [{"collector_id": "aws-iam", "command_id": "account-summary", "issue": "invalid-summary-payload"}],
        )
    root_mfa = summary.get("AccountMFAEnabled")
    root_keys = summary.get("AccountAccessKeysPresent")
    if (
        not isinstance(root_mfa, int)
        or isinstance(root_mfa, bool)
        or root_mfa not in (0, 1)
        or not isinstance(root_keys, int)
        or isinstance(root_keys, bool)
        or root_keys not in (0, 1)
    ):
        return _not_assessed(
            "SummaryMap no demuestra los indicadores de seguridad del root user",
            [{"collector_id": "aws-iam", "command_id": "account-summary", "issue": "root-summary-incomplete"}],
        )

    policy_findings, counters, problem = _evaluate_authorization(
        payloads["account-authorization-details"]
    )
    if policy_findings is None:
        return _not_assessed(
            problem,
            [{"collector_id": "aws-iam", "command_id": "account-authorization-details", "issue": "authorization-payload-incomplete"}],
        )

    findings = []
    if root_mfa == 0:
        findings.append(
            {
                "collector_id": "aws-iam",
                "command_id": "account-summary",
                "pattern": "root-mfa-disabled",
            }
        )
    if root_keys == 1:
        findings.append(
            {
                "collector_id": "aws-iam",
                "command_id": "account-summary",
                "pattern": "root-access-keys-present",
            }
        )
    findings.extend(policy_findings)
    if findings:
        return {
            "status": "FAIL",
            "confidence": "HIGH",
            "evidence_level": "E4",
            "summary": "El snapshot AWS contiene riesgo del root user o privilegios IAM administrativos/wildcard.",
            "evidence": findings[:200],
            "recommendation": "Habilitar MFA del root user, eliminar sus access keys y sustituir AdministratorAccess/wildcards por políticas mínimas; recolectar nuevamente evidencia completa.",
        }

    return {
        "status": "PASS",
        "confidence": "HIGH",
        "evidence_level": "E4",
        "summary": "El snapshot completo no observó root sin MFA, access keys del root, AdministratorAccess adjunto ni acciones wildcard permitidas.",
        "evidence": [
            {
                "collector_id": "aws-iam",
                "commands_verified": len(REQUIRED_COMMANDS),
                "principals_scanned": counters["principals"],
                "inline_policies_scanned": counters["inline_policies"],
                "local_managed_policies_scanned": counters["local_managed_policies"],
                "collector_evidence_sha256": runtime["evidence_hash"],
                "scope": "point-in-time identity policies; excludes SCP, resource policies and IAM Identity Center",
            }
        ],
        "recommendation": "Mantener MFA y ausencia de credenciales root, revisar least privilege y repetir la recolección para detectar drift.",
    }
