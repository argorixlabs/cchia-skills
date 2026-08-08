# CCHIA-AWS-IAM-004 — Root user y privilegios AWS IAM

Evalúa exclusivamente evidencia JSON redacted del collector opt-in `aws-iam`. Detecta `AccountMFAEnabled=0`,
`AccountAccessKeysPresent=1`, adjuntos `AdministratorAccess` y statements `Allow` con `Action` wildcard o
`NotAction` en políticas inline y políticas locales administradas por la cuenta.

## Evidencia requerida

Solo puede emitir PASS con exactamente un resultado `aws-iam` v1.0.0/schema 1.0, `AVAILABLE`, `read_only`, redacción
CCHIA, ejecutable resuelto y hashes válidos. Exige los siguientes comandos JSON, todos exitosos y con el mismo profile
opcional:

- `caller-identity` / `aws.sts.get-caller-identity.v1`.
- `account-summary` / `aws.iam.get-account-summary.v1`.
- `account-authorization-details` / `aws.iam.get-account-authorization-details.v1`.

El inventario debe incluir `UserDetailList`, `RoleDetailList`, `GroupDetailList`, `Policies` e
`IsTruncated=false`. Las políticas inline y la versión por defecto de cada política local deben ser estructuralmente
evaluables. `UNAVAILABLE`, `ERROR`, paginación pendiente, redacción de campos críticos, metadata/comandos/payloads
incompletos o hashes inválidos producen `NOT_ASSESSED`, nunca PASS.

## Privacidad de evidencia

Los findings conservan únicamente patrón, tipo de principal e índices de entidad/política/statement. No copian
account ID, UserId, ARN, profile, nombre del principal ni nombre de políticas particulares. `AdministratorAccess` se
identifica como patrón estándar sin replicar el resto de adjuntos.

## Semántica y límites

- `FAIL`: se observó al menos un riesgo root, AdministratorAccess adjunto o una acción wildcard permitida.
- `PASS`: el snapshot completo no contiene los patrones cubiertos.
- `NOT_ASSESSED`: no existe evidencia suficiente para sostener PASS o FAIL.

Es un snapshot puntual de identity-based IAM. No cubre SCP, resource policies, permission sets de IAM Identity Center,
políticas AWS administradas distintas de AdministratorAccess, historia de uso, credenciales fuera del inventario ni
drift posterior. Un PASS no demuestra mínimo privilegio funcional ni conformidad global.

Para verificar, corregir root/policies, ejecutar otra compilación con `--collector aws-iam` y, si corresponde,
`--aws-profile <nombre>`, usando una identidad externamente limitada a las tres consultas de lectura.
