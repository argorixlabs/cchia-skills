"""Evaluación pura de rulesets y permisos GitHub Actions desde evidencia gh redacted."""

REQUIRED_COMMANDS = {
    "repo-view": "gh.repo.view.v1",
    "repo-metadata": "gh.api.repo.v1",
    "repo-rulesets": "gh.api.repo.rulesets.v1",
    "actions-workflow-permissions": "gh.api.repo.actions-workflow-permissions.v1",
}
API_HEADERS = (
    "-H",
    "Accept: application/vnd.github+json",
    "-H",
    "X-GitHub-Api-Version: 2022-11-28",
)


def _not_assessed(issue):
    return {
        "status": "NOT_ASSESSED",
        "confidence": "LOW",
        "evidence_level": "E0",
        "summary": "La evidencia GitHub no permite una conclusión: " + issue,
        "evidence": [{"collector_id": "gh-repo-security", "issue": "runtime-evidence-incomplete"}],
        "recommendation": "Reejecutar gh-repo-security con Administration:read y conservar los cuatro payloads JSON completos.",
    }


def _valid_hash(value):
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _collector_and_payloads(context):
    collectors = context.get("collectors", [])
    if not isinstance(collectors, list):
        return None, None, "context.collectors no es una lista"
    matches = []
    for collector in collectors:
        if isinstance(collector, dict) and collector.get("collector_id") == "gh-repo-security":
            matches.append(collector)
    if len(matches) != 1:
        return None, None, "se requiere exactamente un resultado gh-repo-security"
    collector = matches[0]
    if collector.get("status") != "AVAILABLE":
        return None, None, "gh-repo-security no terminó AVAILABLE"
    if collector.get("schema_version") != "1.0" or collector.get("collector_version") != "1.0.0":
        return None, None, "la versión del collector no coincide con el contrato evaluado"
    if collector.get("mode") != "read_only":
        return None, None, "el collector no acredita mode=read_only"
    redaction = collector.get("redaction")
    if (
        not isinstance(redaction, dict)
        or redaction.get("applied") is not True
        or redaction.get("strategy") != "cchia-default-v1"
        or redaction.get("replacement") != "[REDACTED]"
    ):
        return None, None, "el collector no acredita el perfil de redacción esperado"
    if not _valid_hash(collector.get("evidence_sha256")):
        return None, None, "el collector no contiene un hash canónico válido"

    provenance = collector.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("provider") != "github":
        return None, None, "la provenance no identifica GitHub"
    interface = provenance.get("interface")
    if (
        not isinstance(interface, dict)
        or interface.get("kind") != "command"
        or interface.get("tool") != "gh"
        or interface.get("sdk") != "GitHub CLI"
        or interface.get("executable_available") is not True
        or not isinstance(interface.get("resolved_executable"), str)
        or not interface.get("resolved_executable").strip()
    ):
        return None, None, "la provenance no demuestra un cliente gh disponible"

    commands = provenance.get("commands")
    if not isinstance(commands, list) or len(commands) != len(REQUIRED_COMMANDS):
        return None, None, "la provenance no contiene exactamente los cuatro comandos requeridos"
    commands_by_id = {}
    for command in commands:
        if (
            not isinstance(command, dict)
            or not isinstance(command.get("command_id"), str)
            or not isinstance(command.get("policy_id"), str)
        ):
            return None, None, "la provenance contiene metadata de comando inválida"
        command_id = command.get("command_id")
        if command_id not in REQUIRED_COMMANDS or command_id in commands_by_id:
            return None, None, "la provenance contiene comandos desconocidos o duplicados"
        if command.get("status") != "AVAILABLE":
            return None, None, "al menos un comando no terminó AVAILABLE"
        if (
            command.get("policy_id") != REQUIRED_COMMANDS[command_id]
            or command.get("exit_code") != 0
            or not _valid_hash(command.get("stdout_sha256"))
            or not isinstance(command.get("argv"), list)
            or any(not isinstance(argument, str) for argument in command.get("argv", []))
        ):
            return None, None, "un comando requerido no acredita policy, argv, exit code y hash completos"
        commands_by_id[command_id] = command

    repo_view_argv = commands_by_id["repo-view"].get("argv", [])
    if (
        len(repo_view_argv) != 6
        or repo_view_argv[:3] != ["gh", "repo", "view"]
        or repo_view_argv[4:] != ["--json", "nameWithOwner,defaultBranchRef,visibility,isArchived"]
    ):
        return None, None, "argv de repo-view no coincide con el contrato read-only"
    repository = repo_view_argv[3]
    parts = repository.split("/") if isinstance(repository, str) else []
    if len(parts) != 2 or not parts[0] or not parts[1] or any(value in repository for value in (" ", "..", "://")):
        return None, None, "selector owner/repo inválido en provenance"
    expected_argv = {
        "repo-metadata": ["gh", "api", "repos/" + repository, *API_HEADERS],
        "repo-rulesets": ["gh", "api", "repos/" + repository + "/rulesets", *API_HEADERS],
        "actions-workflow-permissions": [
            "gh", "api", "repos/" + repository + "/actions/permissions/workflow", *API_HEADERS
        ],
    }
    for command_id, argv in expected_argv.items():
        if commands_by_id[command_id].get("argv") != argv:
            return None, None, "argv de un endpoint API no coincide con el contrato read-only"

    evidence = collector.get("evidence")
    if not isinstance(evidence, list) or len(evidence) != len(REQUIRED_COMMANDS):
        return None, None, "el collector no contiene exactamente los cuatro payloads requeridos"
    payloads = {}
    for row in evidence:
        if not isinstance(row, dict) or not isinstance(row.get("command_id"), str):
            return None, None, "el collector contiene metadata de evidencia inválida"
        command_id = row.get("command_id")
        if command_id not in REQUIRED_COMMANDS or command_id in payloads:
            return None, None, "el collector contiene payloads desconocidos o duplicados"
        if row.get("status") != "AVAILABLE" or row.get("content_type") != "application/json":
            return None, None, "al menos un payload no es JSON AVAILABLE"
        if row.get("data") is None:
            return None, None, "al menos un payload requerido está vacío"
        payloads[command_id] = row.get("data")
    return collector, payloads, ""


def _critical_string(value):
    return (
        isinstance(value, str)
        and bool(value.strip())
        and "[redacted]" not in value.lower()
    )


def _targets_default_branch(ruleset, default_branch):
    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        return None
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        return None
    included = ref_name.get("include")
    excluded = ref_name.get("exclude", [])
    if (
        not isinstance(included, list)
        or not isinstance(excluded, list)
        or any(not isinstance(value, str) for value in included + excluded)
    ):
        return None
    direct = "refs/heads/" + default_branch
    all_tokens = ("~ALL", "refs/heads/*", "refs/heads/**")
    targets = "~DEFAULT_BRANCH" in included or direct in included or any(token in included for token in all_tokens)
    excludes = "~DEFAULT_BRANCH" in excluded or direct in excluded or any(token in excluded for token in all_tokens)
    return targets and not excludes


def _approval_count(ruleset):
    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        return None
    approval_count = 0
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get("type"), str):
            return None
        if rule.get("type") == "pull_request":
            parameters = rule.get("parameters")
            if not isinstance(parameters, dict):
                return None
            observed = parameters.get("required_approving_review_count")
            if isinstance(observed, bool) or not isinstance(observed, int) or not 0 <= observed <= 10:
                return None
            approval_count = max(approval_count, observed)
    return approval_count


def evaluate(context):
    collector, payloads, problem = _collector_and_payloads(context)
    if collector is None:
        return _not_assessed(problem)

    repo_view = payloads.get("repo-view")
    metadata = payloads.get("repo-metadata")
    rulesets = payloads.get("repo-rulesets")
    workflow = payloads.get("actions-workflow-permissions")
    if not isinstance(repo_view, dict) or not isinstance(metadata, dict):
        return _not_assessed("repo-view/repo-metadata no tienen estructura de objeto")
    if not isinstance(rulesets, list) or not isinstance(workflow, dict):
        return _not_assessed("rulesets/workflow permissions no tienen estructura esperada")
    if len(rulesets) >= 30:
        return _not_assessed("la lista de rulesets alcanzó el límite de página y puede estar truncada")

    name_with_owner = repo_view.get("nameWithOwner")
    full_name = metadata.get("full_name")
    default_ref = repo_view.get("defaultBranchRef")
    default_branch = metadata.get("default_branch")
    view_visibility = repo_view.get("visibility")
    api_visibility = metadata.get("visibility")
    view_archived = repo_view.get("isArchived")
    api_archived = metadata.get("archived")
    api_private = metadata.get("private")
    repo_view_command = None
    for command in collector.get("provenance", {}).get("commands", []):
        if command.get("command_id") == "repo-view":
            repo_view_command = command
    selected_repository = (
        repo_view_command.get("argv", [None, None, None, None])[3]
        if isinstance(repo_view_command, dict)
        else None
    )
    if (
        not _critical_string(name_with_owner)
        or not _critical_string(full_name)
        or name_with_owner.lower() != full_name.lower()
        or not isinstance(selected_repository, str)
        or name_with_owner.lower() != selected_repository.lower()
        or not isinstance(default_ref, dict)
        or not _critical_string(default_ref.get("name"))
        or not _critical_string(default_branch)
        or default_ref.get("name").lower() != default_branch.lower()
    ):
        return _not_assessed("identidad/default branch ausente, inconsistente o redactada")
    if (
        not isinstance(view_visibility, str)
        or not isinstance(api_visibility, str)
        or view_visibility.lower() != api_visibility.lower()
        or api_visibility.lower() not in ("public", "private", "internal")
        or not isinstance(view_archived, bool)
        or not isinstance(api_archived, bool)
        or view_archived != api_archived
        or not isinstance(api_private, bool)
        or api_private != (api_visibility.lower() == "private")
    ):
        return _not_assessed("visibility/archive metadata ausente o inconsistente")
    visibility = api_visibility.lower()
    archived = api_archived

    default_permissions = workflow.get("default_workflow_permissions")
    can_approve = workflow.get("can_approve_pull_request_reviews")
    if default_permissions not in ("read", "write") or not isinstance(can_approve, bool):
        return _not_assessed("workflow permissions no contienen ambos campos contractuales")

    enforced_for_default = 0
    best_approval_count = 0
    for ruleset in rulesets:
        if not isinstance(ruleset, dict):
            return _not_assessed("rulesets contiene un item no estructurado")
        enforcement = ruleset.get("enforcement")
        target = ruleset.get("target")
        if not isinstance(enforcement, str) or enforcement not in ("active", "enabled", "evaluate", "disabled"):
            return _not_assessed("ruleset sin enforcement contractual")
        if not isinstance(target, str) or target not in ("branch", "tag", "push"):
            return _not_assessed("ruleset sin target contractual")
        if enforcement not in ("active", "enabled") or target != "branch":
            continue
        targets_default = _targets_default_branch(ruleset, default_branch)
        approval_count = _approval_count(ruleset)
        if targets_default is None or approval_count is None:
            return _not_assessed("ruleset activo sin conditions/rules suficientes para evaluar la rama por defecto")
        if targets_default:
            enforced_for_default += 1
            best_approval_count = max(best_approval_count, approval_count)

    findings = []
    if enforced_for_default == 0:
        findings.append({
            "collector_id": "gh-repo-security",
            "command_id": "repo-rulesets",
            "pattern": "default-branch-ruleset-not-observed",
            "visibility": visibility,
            "archived": archived,
        })
    elif best_approval_count < 1:
        findings.append({
            "collector_id": "gh-repo-security",
            "command_id": "repo-rulesets",
            "pattern": "pull-request-approvals-not-required",
            "visibility": visibility,
            "archived": archived,
            "required_approvals": best_approval_count,
        })
    if default_permissions == "write":
        findings.append({
            "collector_id": "gh-repo-security",
            "command_id": "actions-workflow-permissions",
            "pattern": "default-workflow-token-write",
            "visibility": visibility,
            "archived": archived,
        })
    if can_approve:
        findings.append({
            "collector_id": "gh-repo-security",
            "command_id": "actions-workflow-permissions",
            "pattern": "actions-can-approve-pull-requests",
            "visibility": visibility,
            "archived": archived,
        })

    if findings:
        directly_unsafe = any(
            item.get("pattern") in (
                "pull-request-approvals-not-required",
                "default-workflow-token-write",
                "actions-can-approve-pull-requests",
            )
            for item in findings
        )
        status = "FAIL" if visibility == "public" and not archived and directly_unsafe else "PARTIAL"
        return {
            "status": status,
            "confidence": "HIGH" if directly_unsafe else "MEDIUM",
            "evidence_level": "E4",
            "summary": "El snapshot GitHub muestra controles de cambio o permisos Actions insuficientes para el riesgo observado.",
            "evidence": findings,
            "recommendation": "Aplicar ruleset activo a la rama por defecto con al menos una aprobación y fijar GITHUB_TOKEN read sin aprobación de PRs.",
        }
    return {
        "status": "PASS",
        "confidence": "HIGH",
        "evidence_level": "E4",
        "summary": "El snapshot demuestra ruleset activo con aprobación y defaults restringidos de GitHub Actions.",
        "evidence": [{
            "collector_id": "gh-repo-security",
            "commands_verified": len(REQUIRED_COMMANDS),
            "visibility": visibility,
            "archived": archived,
            "rulesets_observed": len(rulesets),
            "default_branch_rulesets": enforced_for_default,
            "required_approvals": best_approval_count,
            "default_workflow_permissions": default_permissions,
            "actions_can_approve_pull_requests": can_approve,
            "collector_evidence_sha256": collector.get("evidence_sha256"),
        }],
        "recommendation": "Mantener monitoreo de drift, revisar bypass actors y validar también protección legacy fuera de este snapshot.",
    }
