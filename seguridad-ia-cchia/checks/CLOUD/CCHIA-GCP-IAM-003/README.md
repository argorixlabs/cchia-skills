# CCHIA-GCP-IAM-003 — IAM efectivo de GCP

Evalúa exclusivamente la evidencia JSON redacted del collector opt-in `gcloud-iam`. Busca principals públicos
`allUsers`/`allAuthenticatedUsers` y los roles básicos `roles/owner`, `roles/editor` y `roles/viewer` en los bindings
efectivos devueltos por `gcloud projects get-iam-policy`.

## Evidencia requerida

El control solo puede emitir PASS cuando existe exactamente un resultado `gcloud-iam` v1.0.0, schema 1.0,
`AVAILABLE`, `read_only`, con perfil de redacción CCHIA y hashes válidos. Además exige ejecutable resuelto, provenance
y payload JSON exitoso para:

- `project-description` / `gcloud.projects.describe.v1`.
- `project-iam-policy` / `gcloud.projects.get-iam-policy.v1`.
- `service-accounts` / `gcloud.iam.service-accounts.list.v1`.

Si el collector está `UNAVAILABLE`/`ERROR`, falta un comando/payload, hay duplicados, la estructura no permite revisar
todos los bindings o la redacción ocultó roles/principals, retorna `NOT_ASSESSED`. Nunca interpreta evidencia ausente
como IAM limpio.

## Semántica

- `FAIL`: al menos un binding observado usa un rol básico o principal público.
- `PASS`: los tres comandos y payloads requeridos son completos y no contienen los cinco patrones evaluados.
- `NOT_ASSESSED`: la evidencia runtime no es suficiente para sostener PASS o FAIL.

La evidencia del finding conserva solo patrón, índice de binding, rol básico y principal público; no replica otros
miembros de IAM. El check no invoca `gcloud`, no accede a red/filesystem y no recibe credenciales.

## Límites y verificación

Es un snapshot puntual a nivel del proyecto consultado. No prueba ausencia de drift posterior, historia, condiciones
efectivas, herencia organizacional, IAM de cada recurso, acceso por otros mecanismos ni mínimo privilegio funcional de
roles predefinidos/custom. Un PASS no implica certificación ni conformidad global.

Para verificar: corregir bindings, ejecutar otra compilación con `--collector gcloud-iam --gcp-project <id>` usando
una identidad externamente limitada a lectura y confirmar el nuevo resultado junto con sus hashes y provenance.
