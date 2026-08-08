# CCHIA-K8S-RBAC-002 — RBAC runtime

Evalúa exclusivamente el resultado redacted del collector opt-in `kubectl-rbac`. Requiere que `cluster-rbac` y
`namespaced-rbac` hayan terminado `AVAILABLE`, exit code 0, content type JSON y payload Kubernetes `List` completo.
`UNAVAILABLE`, `ERROR`, comandos faltantes, texto libre o estructuras ambiguas producen `NOT_ASSESSED`, nunca PASS.

## Patrones cubiertos

- `ClusterRole/cluster-admin` concedido mediante RoleBinding o ClusterRoleBinding.
- Role/ClusterRole referenciado que combina wildcards con verbos sensibles o expone `bind`, `escalate` o
  `impersonate`.
- Subjects `system:anonymous`, `system:unauthenticated`, `system:authenticated` o wildcard.

PASS significa únicamente que esos patrones no aparecieron en el snapshot puntual de objetos RBAC recolectados. No
prueba la configuración del autenticador, grupos de un IdP externo, permisos efectivos vía impersonation, webhooks de
autorización ni ausencia de drift. Verificar remediaciones volviendo a ejecutar ambos comandos con una identidad
dedicada que tenga solo `get/list`, y complementar con `kubectl auth can-i` bajo identidades representativas cuando el
alcance y autorización lo permitan.
