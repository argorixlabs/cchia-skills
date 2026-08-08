"""Evalúa workloads Kubernetes runtime desde evidencia redacted y read-only."""

SUPPORTED_KINDS = (
    "Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "CronJob", "Job",
)


def _not_assessed(reason, evidence):
    return {
        "status": "NOT_ASSESSED",
        "confidence": "LOW",
        "evidence_level": "E0",
        "summary": "La evidencia runtime de workloads no permite una conclusión: " + reason,
        "evidence": evidence,
        "recommendation": "Ejecutar kubectl-workloads con get/list suficiente y conservar el payload JSON completo.",
    }


def _workload_payload(context):
    matches = []
    for item in context.get("collectors", []):
        if isinstance(item, dict) and item.get("collector_id") == "kubectl-workloads":
            matches.append(item)
    if len(matches) != 1:
        return None, "se requiere exactamente un resultado kubectl-workloads"
    collector = matches[0]
    if collector.get("schema_version") != "1.0" or collector.get("collector_version") != "1.0.0":
        return None, "la versión del collector no coincide con el contrato evaluado"
    if collector.get("mode") != "read_only":
        return None, "el collector no acredita mode=read_only"
    if collector.get("status") != "AVAILABLE":
        return None, "kubectl-workloads no terminó AVAILABLE"
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
    if not isinstance(commands, list):
        return None, "provenance.commands no es una lista"
    for command in commands:
        if not isinstance(command, dict):
            return None, "provenance contiene un registro de comando inválido"
        if not isinstance(command.get("command_id"), str) or not isinstance(command.get("policy_id"), str):
            return None, "provenance contiene metadata de comando inválida"
        if command.get("status") != "AVAILABLE":
            return None, "al menos un comando del collector no terminó AVAILABLE"
    command_matches = []
    for command in commands:
        if isinstance(command, dict) and command.get("command_id") == "workloads":
            command_matches.append(command)
    if len(command_matches) != 1:
        return None, "falta provenance único para workloads"
    command = command_matches[0]
    stdout_hash = command.get("stdout_sha256")
    valid_stdout_hash = (
        isinstance(stdout_hash, str)
        and len(stdout_hash) == 64
        and all(character in "0123456789abcdef" for character in stdout_hash)
    )
    if (
        command.get("policy_id") != "kubectl.workloads.v1"
        or command.get("status") != "AVAILABLE"
        or command.get("exit_code") != 0
        or not valid_stdout_hash
    ):
        return None, "el comando workloads no terminó AVAILABLE"

    rows = collector.get("evidence", [])
    if not isinstance(rows, list):
        return None, "collector.evidence no es una lista"
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("command_id"), str):
            return None, "collector contiene metadata de evidencia inválida"
        if row.get("status") != "AVAILABLE":
            return None, "al menos un payload del collector no terminó AVAILABLE"
    row_matches = []
    for row in rows:
        if isinstance(row, dict) and row.get("command_id") == "workloads":
            row_matches.append(row)
    if len(row_matches) != 1:
        return None, "falta evidencia única para workloads"
    row = row_matches[0]
    if row.get("status") != "AVAILABLE" or row.get("content_type") != "application/json":
        return None, "la evidencia workloads no es JSON AVAILABLE"
    data = row.get("data")
    if not isinstance(data, dict):
        return None, "el payload workloads no es objeto"
    if data.get("kind") != "List" or not isinstance(data.get("apiVersion"), str):
        return None, "el payload no acredita una lista Kubernetes"
    if not isinstance(data.get("items"), list):
        return None, "items no es una lista"
    return data.get("items", []), ""


def _pod_spec(item):
    kind = item.get("kind")
    spec = item.get("spec")
    if not isinstance(spec, dict):
        return None
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job_template = spec.get("jobTemplate")
        job_spec = job_template.get("spec") if isinstance(job_template, dict) else None
        template = job_spec.get("template") if isinstance(job_spec, dict) else None
        return template.get("spec") if isinstance(template, dict) else None
    template = spec.get("template")
    return template.get("spec") if isinstance(template, dict) else None


def _has_resource(mapping, name):
    return isinstance(mapping, dict) and mapping.get(name) not in (None, "")


def _resource_gaps(container, pod_spec):
    resources = container.get("resources", {})
    if not isinstance(resources, dict):
        resources = {}
    requests = resources.get("requests", {})
    limits = resources.get("limits", {})
    pod_resources = pod_spec.get("resources", {})
    if not isinstance(pod_resources, dict):
        pod_resources = {}
    pod_requests = pod_resources.get("requests", {})
    pod_limits = pod_resources.get("limits", {})
    gaps = []
    for resource in ("cpu", "memory"):
        has_limit = _has_resource(limits, resource) or _has_resource(pod_limits, resource)
        # Kubernetes puede derivar request=limit cuando el request no fue
        # especificado y admission no aportó otro valor.
        has_request = (
            _has_resource(requests, resource)
            or _has_resource(pod_requests, resource)
            or has_limit
        )
        if not has_request:
            gaps.append("request." + resource)
        if not has_limit:
            gaps.append("limit." + resource)
    return gaps


def _validate_items(items):
    normalized = []
    for item in items:
        if not isinstance(item, dict) or item.get("kind") not in SUPPORTED_KINDS:
            return None, "item no soportado o no estructurado"
        metadata = item.get("metadata")
        api_version = item.get("apiVersion")
        if not isinstance(metadata, dict) or not isinstance(api_version, str) or not api_version:
            return None, "workload sin metadata"
        name = metadata.get("name")
        namespace = metadata.get("namespace")
        if (
            not isinstance(name, str)
            or not name
            or "[redacted]" in name.lower()
            or not isinstance(namespace, str)
            or not namespace
            or "[redacted]" in namespace.lower()
        ):
            return None, "workload sin metadata.name/namespace"
        pod_spec = _pod_spec(item)
        if not isinstance(pod_spec, dict):
            return None, "workload sin PodSpec resoluble: " + item.get("kind", "UNKNOWN") + "/" + name
        containers = pod_spec.get("containers")
        if not isinstance(containers, list) or not containers:
            return None, "PodSpec sin containers estructurados: " + item.get("kind", "UNKNOWN") + "/" + name
        for field in ("containers", "initContainers", "ephemeralContainers", "volumes"):
            if field in pod_spec and not isinstance(pod_spec.get(field), list):
                return None, "PodSpec con " + field + " inválido: " + item.get("kind", "UNKNOWN") + "/" + name
        for field in ("containers", "initContainers", "ephemeralContainers"):
            for container in pod_spec.get(field, []):
                if not isinstance(container, dict) or not isinstance(container.get("name"), str) or not container.get("name"):
                    return None, "container no estructurado: " + item.get("kind", "UNKNOWN") + "/" + name
                security = container.get("securityContext", {})
                if security is not None and not isinstance(security, dict):
                    return None, "securityContext inválido"
                if isinstance(security, dict):
                    for security_field in ("privileged", "allowPrivilegeEscalation"):
                        if security_field in security and security.get(security_field) not in (True, False, None):
                            return None, "campo crítico de securityContext ambiguo"
                resources = container.get("resources", {})
                if resources is not None and not isinstance(resources, dict):
                    return None, "resources de container inválido"
                if isinstance(resources, dict):
                    for resource_field in ("requests", "limits"):
                        values = resources.get(resource_field, {})
                        if values is not None and not isinstance(values, dict):
                            return None, "resources requests/limits inválido"
                        if isinstance(values, dict):
                            for resource_name in ("cpu", "memory"):
                                value = values.get(resource_name)
                                if value is not None and (not isinstance(value, str) or not value.strip() or "[redacted]" in value.lower()):
                                    return None, "cantidad de recurso crítica incompleta o redactada"
        pod_resources = pod_spec.get("resources", {})
        if pod_resources is not None and not isinstance(pod_resources, dict):
            return None, "resources a nivel Pod inválido"
        if isinstance(pod_resources, dict):
            for resource_field in ("requests", "limits"):
                values = pod_resources.get(resource_field, {})
                if values is not None and not isinstance(values, dict):
                    return None, "resources a nivel Pod requests/limits inválido"
                if isinstance(values, dict):
                    for resource_name in ("cpu", "memory"):
                        value = values.get(resource_name)
                        if value is not None and (not isinstance(value, str) or not value.strip() or "[redacted]" in value.lower()):
                            return None, "cantidad de recurso Pod incompleta o redactada"
        for host_field in ("hostNetwork", "hostPID", "hostIPC"):
            if host_field in pod_spec and pod_spec.get(host_field) not in (True, False, None):
                return None, "campo host namespace ambiguo"
        os_spec = pod_spec.get("os")
        if os_spec is not None and (
            not isinstance(os_spec, dict)
            or not isinstance(os_spec.get("name"), str)
            or os_spec.get("name", "").lower() not in ("linux", "windows")
        ):
            return None, "PodSpec contiene os ambiguo"
        for volume in pod_spec.get("volumes", []):
            if not isinstance(volume, dict):
                return None, "volume no estructurado: " + item.get("kind", "UNKNOWN") + "/" + name
        normalized.append({
            "kind": item.get("kind"),
            "name": name,
            "namespace": namespace,
            "pod_spec": pod_spec,
        })
    return normalized, ""


def evaluate(context):
    items, problem = _workload_payload(context)
    if items is None:
        return _not_assessed(problem, [])
    workloads, problem = _validate_items(items)
    if workloads is None:
        return _not_assessed(problem, [{"collector_id": "kubectl-workloads", "payload_structurally_complete": False}])

    findings = []
    container_count = 0
    for workload in workloads:
        pod_spec = workload["pod_spec"]
        base = {
            "collector_id": "kubectl-workloads",
            "command_id": "workloads",
            "workload_kind": workload["kind"],
            "workload": workload["name"],
            "namespace": workload["namespace"],
        }
        for field, pattern in (
            ("hostNetwork", "host-network"),
            ("hostPID", "host-pid"),
            ("hostIPC", "host-ipc"),
        ):
            if pod_spec.get(field) is True:
                finding = dict(base)
                finding["pattern"] = pattern
                findings.append(finding)
        for volume in pod_spec.get("volumes", []):
            if "hostPath" in volume and volume.get("hostPath") is not None:
                finding = dict(base)
                finding["pattern"] = "host-path-volume"
                finding["volume"] = str(volume.get("name", "unnamed"))
                findings.append(finding)

        os_name = ""
        os_spec = pod_spec.get("os", {})
        if isinstance(os_spec, dict):
            os_name = str(os_spec.get("name", "")).lower()
        for field, require_resources in (
            ("containers", True),
            ("initContainers", True),
            ("ephemeralContainers", False),
        ):
            for container in pod_spec.get(field, []):
                container_count += 1
                container_base = dict(base)
                container_base["container_type"] = field
                container_base["container"] = container.get("name")
                security = container.get("securityContext", {}) or {}
                if security.get("privileged") is True:
                    finding = dict(container_base)
                    finding["pattern"] = "privileged-container"
                    findings.append(finding)
                if os_name != "windows" and security.get("allowPrivilegeEscalation") is not False:
                    finding = dict(container_base)
                    finding["pattern"] = "privilege-escalation-not-disabled"
                    finding["observed"] = security.get("allowPrivilegeEscalation")
                    findings.append(finding)
                if require_resources:
                    gaps = _resource_gaps(container, pod_spec)
                    if gaps:
                        finding = dict(container_base)
                        finding["pattern"] = "container-resources-incomplete"
                        finding["missing"] = gaps
                        findings.append(finding)
        if len(findings) >= 200:
            break

    if findings:
        return {
            "status": "FAIL",
            "confidence": "HIGH",
            "evidence_level": "E4",
            "summary": "El snapshot runtime contiene workloads con aislamiento peligroso o recursos CPU/memoria incompletos.",
            "evidence": findings[:200],
            "recommendation": "Eliminar privilegios/host access, fijar allowPrivilegeEscalation=false y definir requests/limits efectivos de CPU y memoria.",
        }
    return {
        "status": "PASS",
        "confidence": "HIGH",
        "evidence_level": "E4",
        "summary": "No se observaron los patrones de aislamiento o recursos cubiertos en el inventario runtime estructuralmente completo.",
        "evidence": [{
            "collector_id": "kubectl-workloads",
            "command_id": "workloads",
            "workloads_scanned": len(workloads),
            "containers_scanned": container_count,
            "scope": "point-in-time API objects, not admission enforcement or future drift",
        }],
        "recommendation": "Mantener Pod Security/admission y políticas de recursos; repetir la recolección para detectar drift.",
    }
