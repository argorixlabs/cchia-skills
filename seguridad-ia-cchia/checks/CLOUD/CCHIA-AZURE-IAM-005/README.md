# CCHIA-AZURE-IAM-005 — Azure RBAC privilegiado y principals anómalos

Evalúa exclusivamente evidencia JSON redacted del collector opt-in `az-role-assignments`. Detecta asignaciones
`Owner` o `User Access Administrator` en scope raíz, management group o suscripción, además de principals con tipo
desconocido o nombre public-like. No replica `principalId`, `principalName`, tenant, subscription ni nombres de
recursos en los findings.

## Evidencia requerida

Solo puede emitir PASS con exactamente un resultado `az-role-assignments` v1.0.0, schema 1.0, `AVAILABLE`,
`read_only`, redacción CCHIA, hash sintácticamente válido, ejecutable `az` resuelto y estos dos registros/payloads
JSON exitosos:

- `azure-account` / `az.account.show.v1` / `az account show [--subscription VALUE] --output json`.
- `role-assignments` / `az.role.assignment.list.v1` / `az role assignment list --all [--subscription VALUE] --output json`.

Si se usa `--subscription`, ambos comandos deben llevar exactamente el mismo valor tipado. La cuenta debe exponer
IDs de suscripción y tenant estructuralmente válidos. Cada asignación debe incluir rol, scope, principal ID y tipo;
campos críticos ausentes/redacted, comandos distintos, texto truncado o metadata/payload incompletos terminan en
`NOT_ASSESSED`.

## Semántica

- `FAIL`: Owner/User Access Administrator en scope amplio, principal type desconocido o principalName public-like.
- `PASS`: evidencia completa y ninguno de esos patrones en las asignaciones observadas.
- `NOT_ASSESSED`: collector ausente, `UNAVAILABLE`/`ERROR`, contrato no soportado o evidencia insuficiente.

Los findings conservan solo índice, patrón normalizado, clase de rol y clase de scope. Se limitan a 20 registros y un
resumen de truncamiento para evitar que una lista grande o contenido no confiable infle el informe.

## Límites y verificación

`az role assignment list --all` enumera asignaciones bajo la suscripción seleccionada, pero esta versión no solicita
`--include-inherited`; por eso un PASS no demuestra ausencia de privilegios heredados desde management groups. Tampoco
evalúa PIM/roles elegibles, deny assignments, custom roles equivalentes, condiciones ABAC, Entra directory roles,
historia ni drift posterior. El hash canónico se verifica en el compiler/gate antes del check; dentro del worker se
valida forma y contrato, no se recalcula criptográficamente.

Para verificar, revisar/remediar assignments, ejecutar una nueva compilación con el collector Azure usando una
identidad limitada a lectura y comparar hashes/provenance/resultados. Este check no implica certificación ni
conformidad global.
