# CCHIA-K8S-WL-003 — Workloads runtime

Evalúa exclusivamente el resultado redacted del collector opt-in `kubectl-workloads`. Requiere el comando
`workloads` en estado `AVAILABLE`, exit code 0 y un payload Kubernetes `List` estructuralmente completo.
`UNAVAILABLE`, `ERROR`, salida textual, items desconocidos o PodSpecs ambiguos producen `NOT_ASSESSED`, nunca PASS.

## Patrones cubiertos

- `privileged=true` y `allowPrivilegeEscalation` no deshabilitado explícitamente en contenedores Linux.
- `hostNetwork`, `hostPID`, `hostIPC` y volúmenes `hostPath`.
- Falta de requests o limits efectivos para CPU/memoria en containers e initContainers. El check reconoce recursos a
  nivel Pod y la derivación request=limit documentada por Kubernetes; no exige recursos en ephemeralContainers.

PASS solo cubre objetos devueltos por el API server en ese instante. No prueba enforcement de admission, kubelet,
runtime/cgroups, comportamiento de imágenes, ResourceQuota/LimitRange, carga real ni ausencia de drift. Los límites
óptimos dependen del workload; una excepción —por ejemplo, una política sin CPU limit— debe quedar gobernada y no se
deduce automáticamente de este control. Verificar remediaciones reejecutando el collector con identidad get/list y
complementando con políticas Pod Security/ValidatingAdmissionPolicy y métricas operativas.
