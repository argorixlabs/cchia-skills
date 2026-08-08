# CCHIA-GH-REPO-006 — Repositorio GitHub con reglas y permisos Actions mínimos

Comprueba, mediante un snapshot read-only y explícitamente solicitado, que la rama por defecto está cubierta por un ruleset activo con al menos una aprobación de pull request, que `GITHUB_TOKEN` usa `read` por defecto y que GitHub Actions no puede aprobar pull requests. La visibilidad y el estado archivado ajustan la severidad, pero no reemplazan evidencia.

## Activación y opciones

El control aplica con `runtime-github-repo-security` o `collector-gh-repo-security-requested`. El collector `gh-repo-security` exige `github_repo=owner/repo`; rechaza URLs, espacios, flags, traversal y argumentos libres. `timeout_seconds` es opcional, entero entre 1 y 300.

No ejecuta `gh` durante validación de catálogo o fixtures. En una compilación runtime opt-in usa exactamente:

```text
repo-view / gh.repo.view.v1
gh repo view OWNER/REPO --json nameWithOwner,defaultBranchRef,visibility,isArchived

repo-metadata / gh.api.repo.v1
gh api repos/OWNER/REPO -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28"

repo-rulesets / gh.api.repo.rulesets.v1
gh api repos/OWNER/REPO/rulesets -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28"

actions-workflow-permissions / gh.api.repo.actions-workflow-permissions.v1
gh api repos/OWNER/REPO/actions/permissions/workflow -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28"
```

## Decisión

- `PASS`: los cuatro comandos y payloads cumplen el contrato, el ruleset activo cubre la rama por defecto con una o más aprobaciones, los permisos Actions son `read` y Actions no puede aprobar PRs.
- `FAIL`: en un repositorio público, no archivado, la evidencia demuestra aprobación ausente, token `write` por defecto o capacidad de aprobar PRs.
- `PARTIAL`: existe una brecha demostrada con menor exposición (por ejemplo, repositorio privado/interno/archivado), o no se observó ruleset aplicable. La ausencia de un ruleset en este endpoint no demuestra ausencia de protección de rama legacy.
- `NOT_ASSESSED`: collector ausente/no AVAILABLE, 403/404/error, versión/metadata/hash/policy/argv incompletos, payload desconocido, identidad inconsistente, detalle de ruleset insuficiente o lista potencialmente paginada (30 o más elementos).

El resultado publica patrones y conteos, no nombres de organización, repositorio o rama. Un hash de evidencia acredita integridad del snapshot redacted, no autenticidad remota ni seguridad futura.

## Alcance y límites reales

Los endpoints requieren una identidad `gh` autenticada; leer la configuración de permisos Actions puede requerir `Administration:read`. Los cuatro GET no alteran GitHub, pero el cliente `gh` puede leer su configuración y cache fuera del target. El listado de rulesets puede omitir `rules` detalladas y paginar; en esos casos el check falla cerrado a `NOT_ASSESSED`. Este control no prueba actores de bypass, reglas heredadas efectivas, branch protection legacy, historial de merges, workflows individuales, ambientes, secrets, apps ni drift posterior.

Para verificar una remediación, configure un ruleset activo sobre la rama por defecto, exija al menos una aprobación, seleccione permisos de workflow de solo lectura y desactive la aprobación de PRs por Actions; después reejecute el collector opt-in y conserve el JSON redacted del informe.
