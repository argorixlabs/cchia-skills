# CCHIA Security Compiler — Product Specification (engine 0.5.0)

## 1. Visión

Convertir la inteligencia CCHIA en un sistema repetible de assurance: recibir arquitectura, repositorio, IaC,
Kubernetes, MCP/agentes o una descripción; decidir qué controles aplican; construir un plan; ejecutar comprobaciones
read-only; conservar evidencia verificable; y emitir una vista de riesgo CCHIA con crosswalks NIST/ISO.

El producto no certifica ni promete seguridad total. Su unidad de valor es una conclusión acotada cuya evidencia,
versión, fuente, ejecutor y limitaciones pueden auditarse.

## 2. Capas

### Layer 1 — CCHIA Security Intelligence

La skill define método, lenguaje de riesgo, evidencia E0–E5, modos de evaluación, cobertura técnica/regulatoria,
quality gates y formatos ejecutivos/técnicos. Usa referencias de carga progresiva para evitar un prompt monolítico.

### Layer 2 — CCHIA Checks

Cada control es un paquete autocontenido:

```text
checks/<DOMAIN>/<CCHIA-ID>/
  control.yaml    identidad SemVer, intención, riesgo, applicability y finding
  check.py        evaluador puro sobre contexto serializado
  expected.json   contrato de salida
  mapping.yaml    crosswalk razonado y fuentes
  README.md       alcance, límites y verificación
  fixtures/
    positive.json     hallazgo FAIL o PARTIAL
    negative.json     evidencia suficiente para PASS
    no_evidence.json  evidencia insuficiente para NOT_ASSESSED
```

Los 500–1.000 controles futuros comparten catálogo, collector, runner, schemas, evidencia y reporting. Agregar un
control no modifica el motor.

### Layer 3 — CCHIA Security Compiler

Pipeline implementado:

```text
INPUT -> INTAKE -> SIGNALS/CONFIDENCE -> APPLICABILITY -> PLAN
      -> OPTIONAL READ-ONLY COLLECTORS -> BOUNDED CHECK WORKERS
      -> EVIDENCE JSON -> FINDINGS/SCORES -> CCHIA/NIST/ISO REPORTS -> HASH MANIFEST
```

## 3. Entradas

- Directorio de repositorio o IaC.
- Archivo individual Terraform, Kubernetes o configuración.
- Descripción estructurada YAML/JSON.
- Arquitectura Markdown o texto libre.
- Catálogo versionado de CCHIA Checks.
- Selección explícita de controles cuando el operador desea acotar el alcance.
- Collectors runtime seleccionados explícitamente, nunca por inferencia automática.

## 4. Detección de aplicabilidad

El selector v2 infiere señales con confidence y provenance: repository, terraform, kubernetes, cloud/provider, AI,
agent, MCP, tools de alto impacto, approval, entrada externa y datos sensibles. Cada `control.yaml` declara `all_of`,
`any_of` y `none_of`. `plan.json` conserva selecciones, exclusiones, razones y `signal_details`.

Las declaraciones explícitas, campos estructurados y firmas técnicas pueden activar señales. Las menciones genéricas
—incluidos proveedores citados en documentación o roadmap— quedan registradas con confidence baja, pero no activan
controles por sí solas. `signals` se mantiene como lista compatible y contiene únicamente señales activas.

La inferencia no es una decisión de compliance: identifica qué vale la pena evaluar. El check decide PASS/FAIL/
PARTIAL/NOT_ASSESSED solo dentro de su alcance.

La ventana estática declara `collection.complete`. Si límites de cantidad/tamaño o errores de lectura/decodificación
dejan candidatos fuera, un PASS se degrada a `NOT_ASSESSED`, `LOW`, `E0`. Un FAIL observado no se elimina, pero debe
interpretarse bajo cobertura incompleta. `NOT_APPLICABLE` sigue reservado para una exclusión justificada de alcance.

La aplicabilidad runtime usa un puente de dos señales. Todo resultado de un collector conocido activa
`collector-<id>-requested`; por eso `UNAVAILABLE` o `ERROR` selecciona el check correspondiente, que debe concluir
`NOT_ASSESSED` y no desaparecer como `NOT_APPLICABLE`. Solo `AVAILABLE`, tras validar contrato y hash canónico, activa
las señales `runtime-*` y de proveedor. Solicitud y disponibilidad quedan así separadas y auditables.

En 0.5.0 los nuevos pares son `collector-aws-iam-requested`/`runtime-aws-iam`,
`collector-az-role-assignments-requested`/`runtime-azure-role-assignments` y
`collector-gh-repo-security-requested`/`runtime-github-repo-security`. Los controles asociados son, respectivamente,
`CCHIA-AWS-IAM-004`, `CCHIA-AZURE-IAM-005` y `CCHIA-GH-REPO-006`.

## 5. Collectors runtime

Los collectors son opt-in y están separados de selector, evaluator, policy y reporter. Una compilación sin
`--collector` no descubre ni ejecuta herramientas externas. El catálogo actual ofrece siete collectors: AWS IAM,
Azure RBAC, GCP IAM, seguridad de repositorios GitHub y tres inventarios Kubernetes (cluster, RBAC y workloads).

Cada collector usa opciones tipadas, argv allow-listed completo, `shell=False`, timeout y redacción. No admite comandos
libres ni recolecta Secrets/ConfigMaps Kubernetes. Resuelve el cliente a ruta absoluta, usa cwd temporal neutral y
cierra stdin; hereda el entorno para las credenciales configuradas. Sus estados son `AVAILABLE`, `UNAVAILABLE` y
`ERROR`; solo el primero prueba que el comando respondió en ese momento. Las identidades de `gcloud`/`kubectl` deben limitarse externamente a
lectura, porque una validación de argv no reduce permisos de una credencial sobredimensionada. Las CLI pueden mantener
cache/configuración local incluso cuando la operación remota es read-only.

El ejecutor compartido limita la persistencia/evaluación de stdout a 4 MiB. La comprobación ocurre después de que
`subprocess.run(capture_output)` captura la salida: si se excede, el payload se descarta, el comando y el collector
quedan `ERROR` con `OUTPUT_LIMIT`, y ningún check puede convertirlo en PASS. No es una cuota de memoria ni captura
streaming; stdout todavía se materializa en memoria. El streaming acotado sigue en roadmap.

El compilador verifica `evidence_sha256` sobre el payload canónico `{collector_id, collector_version, evidence}` antes
de enriquecer el contexto. La evidencia collector ya es evaluada directamente por seis checks:

| Collector | Check runtime | Resultado sin evidencia AVAILABLE y completa |
|---|---|---|
| `aws-iam` | `CCHIA-AWS-IAM-004` | `NOT_ASSESSED` |
| `az-role-assignments` | `CCHIA-AZURE-IAM-005` | `NOT_ASSESSED` |
| `gcloud-iam` | `CCHIA-GCP-IAM-003` | `NOT_ASSESSED` |
| `gh-repo-security` | `CCHIA-GH-REPO-006` | `NOT_ASSESSED` |
| `kubectl-rbac` | `CCHIA-K8S-RBAC-002` | `NOT_ASSESSED` |
| `kubectl-workloads` | `CCHIA-K8S-WL-003` | `NOT_ASSESSED` |

`kubectl-cluster` aporta inventario y señales de Kubernetes, pero todavía no tiene un check runtime dedicado.
Un gap GitHub observado con evidencia AVAILABLE puede producir `FAIL` o `PARTIAL` según visibilidad/archivo y alcance
demostrable; `UNAVAILABLE`, `ERROR` o evidencia estructuralmente incompleta producen `NOT_ASSESSED`.

Opciones de selección: `--aws-profile`, `--azure-subscription`, `--gcp-project`, `--github-repo`, `--kube-context`,
`--kube-namespace` y `--collector-timeout`. Los argv lógicos autorizados son:

| Collector | Plan de comandos allow-listed |
|---|---|
| `aws-iam` | `aws [--profile PROFILE] sts get-caller-identity --output json`; `aws [--profile PROFILE] iam get-account-summary --output json`; `aws [--profile PROFILE] iam get-account-authorization-details --filter User Role Group LocalManagedPolicy --output json` |
| `az-role-assignments` | `az account show [--subscription SUBSCRIPTION] --output json`; `az role assignment list --all [--subscription SUBSCRIPTION] --output json` |
| `gcloud-iam` | `gcloud projects describe PROJECT --format=json --quiet`; `gcloud projects get-iam-policy PROJECT --format=json --quiet`; `gcloud iam service-accounts list --project PROJECT --format=json --quiet` |
| `gh-repo-security` | `gh repo view OWNER/REPO --json nameWithOwner,defaultBranchRef,visibility,isArchived`; `gh api repos/OWNER/REPO`; `gh api repos/OWNER/REPO/rulesets`; `gh api repos/OWNER/REPO/actions/permissions/workflow`; los tres GET usan exactamente `-H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28"` |
| `kubectl-cluster` | `kubectl [--context CONTEXT] version -o json`; `kubectl [--context CONTEXT] get namespaces -o json` |
| `kubectl-rbac` | `kubectl [--context CONTEXT] get clusterroles,clusterrolebindings -o json`; `kubectl [--context CONTEXT] get roles,rolebindings (--namespace NAMESPACE|--all-namespaces) -o json` |
| `kubectl-workloads` | `kubectl [--context CONTEXT] get deployments,statefulsets,daemonsets,replicasets,cronjobs,jobs,pods (--namespace NAMESPACE|--all-namespaces) -o json` |

Límites provider-specific: AWS no cubre SCP, resource policies ni permission sets de IAM Identity Center; Azure no
demuestra asignaciones heredadas desde management groups; GitHub puede paginar rulesets, omitir detalle de reglas y
requiere `Administration:read` para workflow permissions. Un error de permiso, paginación/forma no demostrablemente
completa, contrato/hash inválido, truncamiento o `OUTPUT_LIMIT` no habilita PASS.

## 6. Trust model

- El target y su contenido son no confiables.
- El modelo/skill no puede cambiar el resultado de un check determinista.
- `check.py` se trata como código revisado: AST gate, builtins mínimos, `python -I -S -B -X utf8`, contexto serializado, entorno
  allow-listed, cwd temporal, stdin cerrado y timeout.
- El contenido de los archivos se entrega solo al worker; `context.json` exportado conserva hashes/metadatos y la
  descripción `system`, no el código completo recolectado.
- La evidencia de secretos conserva patrón/ruta/línea, nunca el valor.
- El compilador crea sus artefactos solo en un output nuevo/vacío y rechaza mezcla de corridas; las CLI collector
  externas pueden mantener cache/configuración propios.
- Hashes pre/post demuestran invariancia de la ventana recolectada; cobertura incompleta queda declarada.
- `manifest.json` detecta alteración posterior de los artefactos emitidos, pero un hash no aporta identidad de firmante.
- Una salida inválida o timeout produce `ERROR`; cobertura incompleta impide conservar PASS.
- El runner intenta rlimits/session/killpg en POSIX y Job Object con cuotas/kill-on-close en Windows.
- El sandbox publica controles, límites requested/enforced, fallbacks, outcome y `strong_os_boundary=false`;
  red/filesystem no tienen aislamiento OS.
- Si un control OS falla, continúa con capas portables y registra el fallback; no es fail-closed.
- Las restricciones son defensa best-effort para checks revisados, no un hipervisor ni aislamiento absoluto.
- Para código de check hostil se requiere una frontera externa de SO/contenedor y catálogo revisado/firmado.

## 7. Contratos y versionado

Los schemas v1.0 cubren control, expected, mapping, fixtures, evidence, plan, assessment, collectors y system intake.
El engine distribuido es `0.5.0`. Cada control tiene una versión SemVer independiente —los once actuales son
`1.0.0`— que se propaga a selección, evidencia, findings e informes. Cambios incompatibles del contrato de un control
requieren versión mayor; cambios compatibles usan minor/patch. El ID CCHIA permanece estable para el mismo objetivo y
un objetivo nuevo recibe ID nuevo.

## 8. Evidencia y reporting

Cada corrida genera:

- Plan y contexto/fingerprint.
- Evidencia separada por control con SHA-256 del check.
- Evidencia redacted separada para cada collector runtime solicitado.
- Versión/fingerprint del motor y fingerprint del catálogo usado.
- Conteo de controles/fixtures; el fingerprint del catálogo incluye todos los archivos de cada paquete, incluidos
  mappings, README y fixtures.
- Assessment JSON como fuente canónica.
- Finding completo por resultado no PASS.
- Scores por dominio y overall sin ocultar dominios deficientes.
- Informes CCHIA, NIST e ISO derivados del mismo JSON.
- Manifest con SHA-256 de todos los artefactos.

Los mappings declaran `direct`, `conceptual` o ausencia de mapping. ISO se referencia sin copiar texto protegido.

## 9. Escalabilidad operacional

- Organización por dominio y carga lazy desde `control.yaml`.
- Contexto recolectado una vez y reutilizado por todos los checks.
- Selectores conservan evidencia débil sin convertirla en aplicabilidad.
- Collectors son opt-in y reutilizan contratos/policies tipadas, no shell libre.
- Checks sin SDK/provider reducen dependencias y facilitan revisión.
- Timeout y ERROR explícito evitan convertir fallos de ejecución en PASS.
- El scaffold crea los cinco archivos base y deja explícita la autoría de los fixtures.
- `cchia validate` es el gate global: detecta IDs duplicados, SemVer/contratos rotos, domains incorrectos, código no
  permitido, matrices ausentes, status inesperados y hashes collector inválidos ejecutando los fixtures sin invocar
  collectors reales.

Para catálogos masivos, la siguiente optimización compatible es ejecutar workers en un pool limitado por CPU/memoria,
manteniendo evidencia determinista y ordenada por ID.

## 10. Criterios de aceptación del MVP

- Once paquetes completos en cinco dominios, todos en versión `1.0.0`.
- Treinta y tres fixtures contractuales ejecutables: positivo, negativo y sin evidencia por control.
- Entrada de repo + system y system-only.
- Selección automática con razones.
- Confidence/provenance y rechazo de menciones documentales como señal activa.
- Cobertura incompleta visible y PASS degradado a NOT_ASSESSED.
- Plan-only y selección explícita.
- Detección real en Python/repo, Terraform GCP, Kubernetes y MCP/agentes.
- Evidencia sin secreto crudo.
- Invariancia pre/post del target recolectado.
- Tres informes y manifest de hashes.
- Rechazo de imports/I/O y de outputs reutilizados.
- Siete collectors opt-in allow-listed para AWS IAM, Azure RBAC, GCP IAM, GitHub y Kubernetes, con estados, redacción,
  límite post-captura de 4 MiB y hash canónico verificado.
- Evaluación de evidencia runtime por AWS IAM, Azure RBAC, GCP IAM, GitHub, Kubernetes RBAC y workloads; ausencia,
  error, `OUTPUT_LIMIT` o cobertura crítica insuficiente nunca produce PASS.
- Baseline de 137 tests de catálogo, safety, scaffold y flujo E2E. Tests y E2E runtime usan mocks/fixtures sintéticos:
  no prueban autenticación ni estado de tenants, cuentas, clusters o repositorios reales.
- Skill válida e instalada por junction en Codex.

## 11. Evolución sin romper arquitectura

1. Profundizar la cobertura basal ya implementada de AWS/Azure/GitHub y ampliar superficies GCP/Kubernetes: SCP,
   Identity Center, resource policies, management-group inheritance, PIM, custom roles, paginación/detalle de
   rulesets y ámbitos organization/enterprise, entre otros.
2. Firmar catálogo y attestations de evidencia (por ejemplo, Sigstore/in-toto) para una cadena de custodia fuerte.
3. Incorporar policy engine para scopes/approvals y un pool de workers paralelo con cuotas, junto con captura de
   stdout realmente streaming y acotada.
4. Implementar continuous assurance con scheduler, diff de evidencia y apertura de findings, sin otorgar sellos
   automáticos.
5. Ofrecer un sandbox externo fuerte —VM/contenedor con filesystem read-only y red bloqueada— para ejecutar catálogos
   cuyo código no pueda tratarse como revisado y confiable.

Estas extensiones no requieren cambiar la unidad CCHIA Check ni el assessment JSON; amplían collectors, ejecución y
distribución alrededor de contratos ya versionados.
