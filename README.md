# CCHIA Security Compiler

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

Skill y motor evidence-first para controles CCHIA de ciberseguridad, seguridad/gobierno de IA y compliance técnico.
El repositorio publica una implementación técnica; sus resultados no constituyen una certificación ni una declaración
institucional de conformidad. La publicación y mantenimiento se describen en [GOVERNANCE.md](GOVERNANCE.md).

La versión actual del motor es **0.5.0**. El catálogo incluido contiene **11 CCHIA Checks versionados**, una matriz
obligatoria de **33 fixtures ejecutables** y **7 collectors runtime opt-in**.

El repositorio ya no genera scripts aislados. Cada prueba es un paquete **CCHIA Check** y todos comparten un solo
motor que selecciona aplicabilidad, ejecuta en modo read-only, conserva evidencia JSON y genera informes CCHIA,
NIST e ISO.

## Arquitectura

```text
seguridad-ia-cchia/
├── SKILL.md                         Orquestación y reglas evidence-first
├── agents/openai.yaml               Metadata para Codex
├── cchia_engine/                    Motor, selector, runner, compiler y reporter
│   └── collectors/                  Collectors runtime opt-in y allow-lists
├── checks/<DOMAIN>/<CCHIA-ID>/      Controles autocontenidos y escalables
├── schemas/                         Contratos JSON Schema v1.0
├── scripts/cchia.py                 CLI sin instalación de paquete
├── references/                      Conocimiento de carga progresiva
├── assets/                          Plantillas CCHIA/ANCI
├── examples/                        Sistema y target adversarial de demostración
└── tests/                            Contratos, safety gate y E2E
```

Cada control contiene:

```text
control.yaml + check.py + expected.json + mapping.yaml + README.md
fixtures/positive.json + fixtures/negative.json + fixtures/no_evidence.json
```

## Inicio rápido

```powershell
python -m pip install -r seguridad-ia-cchia\requirements.txt
python seguridad-ia-cchia\scripts\cchia.py validate
python seguridad-ia-cchia\scripts\cchia.py list
python seguridad-ia-cchia\scripts\cchia.py collectors
```

`validate` es el gate del catálogo: valida contratos, SemVer, perfil read-only y ejecuta los tres fixtures de cada
control. En el catálogo distribuido debe terminar con `OK: 11 CCHIA Checks y 33 fixtures válidos`; un fixture ausente,
un status distinto del esperado o un hash de collector inválido produce salida no cero.

Requiere Python 3.10 o superior. Cada assessment debe usar un directorio `--output` nuevo o vacío para evitar
mezclar evidencia de corridas distintas.

Ejecutar la demostración completa:

```powershell
python seguridad-ia-cchia\scripts\cchia.py compile `
  --target seguridad-ia-cchia\examples\demo-target `
  --system seguridad-ia-cchia\examples\system.yaml `
  --output artifacts\demo
```

También puede compilar únicamente una arquitectura o descripción: omitir `--target` y pasar `--system` en YAML,
JSON, Markdown o texto plano.

Genera `plan.json`, `context.json`, evidencia por control, `assessment.json`, informes CCHIA/NIST/ISO y un
`manifest.json` con SHA-256. El target se compara antes/después dentro de la ventana recolectada; `context.json` y
los informes declaran si esa ventana quedó incompleta.

## Selector de aplicabilidad v2

El selector distingue evidencia de uso de una mención documental. `system.signals`, campos estructurados como
`components[].cloud_provider` y firmas técnicas —por ejemplo un provider Terraform— pueden activar una señal con
confidence trazable. Una referencia a AWS/Azure/GCP en un roadmap queda registrada como mención `LOW`, pero no
selecciona por sí sola controles de esos proveedores.

`context.json` conserva tres vistas:

- `signals`: lista compatible de señales activas usada por `all_of`, `any_of` y `none_of`.
- `signal_evidence`: fuentes resumidas para consumidores existentes.
- `signal_details`: estado, confidence y provenance de declaraciones, inferencias y menciones descartadas.

La aplicabilidad decide qué vale la pena comprobar; no es una conclusión de compliance.

## Cobertura de recolección

El intake limita por defecto la ventana a 2.000 archivos de texto soportados y 1 MB por archivo. `collection.complete`
solo es `true` si ningún candidato quedó fuera por esos límites, error de lectura o decodificación. Si la cobertura es
incompleta, el contexto conserva razones, contadores y muestras; un `PASS` no puede sobrevivir como tal y se degrada
a `NOT_ASSESSED`, confidence `LOW` y evidencia `E0`. Esto expresa evidencia faltante, no un incumplimiento.

Los límites protegen disponibilidad, no demuestran que el resto del árbol carezca de cambios. Los hashes pre/post
solo cubren los archivos incluidos en la ventana y cualquier exclusión se debe interpretar junto con
`collection.incomplete_reasons`.

## Collectors runtime: siempre opt-in

Listar collectors no ejecuta herramientas externas:

```powershell
python seguridad-ia-cchia\scripts\cchia.py collectors
```

GCP IAM requiere selección explícita y proyecto explícito:

```powershell
python seguridad-ia-cchia\scripts\cchia.py compile `
  --target C:\repo `
  --output C:\evidencia-nueva `
  --collector gcloud-iam `
  --gcp-project mi-proyecto
```

Kubernetes permite repetir `--collector` y fijar contexto/namespace:

```powershell
python seguridad-ia-cchia\scripts\cchia.py compile `
  --target C:\repo `
  --output C:\evidencia-nueva `
  --collector kubectl-cluster `
  --collector kubectl-rbac `
  --collector kubectl-workloads `
  --kube-context auditoria@cluster `
  --kube-namespace produccion
```

AWS, Azure y GitHub agregan selección explícita y opciones tipadas; el profile/suscripción son opcionales, mientras
que GitHub exige `owner/repo`:

```powershell
python seguridad-ia-cchia\scripts\cchia.py compile `
  --target C:\repo --output C:\evidencia-aws `
  --collector aws-iam --aws-profile auditoria

python seguridad-ia-cchia\scripts\cchia.py compile `
  --target C:\repo --output C:\evidencia-azure `
  --collector az-role-assignments --azure-subscription suscripcion-auditada

python seguridad-ia-cchia\scripts\cchia.py compile `
  --target C:\repo --output C:\evidencia-github `
  --collector gh-repo-security --github-repo OWNER/REPO
```

Los siete collectors y sus argv lógicos allow-listed son:

| Collector | Comandos permitidos, resumidos exactamente |
|---|---|
| `aws-iam` | `aws [--profile PROFILE] sts get-caller-identity --output json`; `aws [--profile PROFILE] iam get-account-summary --output json`; `aws [--profile PROFILE] iam get-account-authorization-details --filter User Role Group LocalManagedPolicy --output json` |
| `az-role-assignments` | `az account show [--subscription SUBSCRIPTION] --output json`; `az role assignment list --all [--subscription SUBSCRIPTION] --output json` |
| `gcloud-iam` | `gcloud projects describe PROJECT --format=json --quiet`; `gcloud projects get-iam-policy PROJECT --format=json --quiet`; `gcloud iam service-accounts list --project PROJECT --format=json --quiet` |
| `gh-repo-security` | `gh repo view OWNER/REPO --json nameWithOwner,defaultBranchRef,visibility,isArchived`; `gh api repos/OWNER/REPO`; `gh api repos/OWNER/REPO/rulesets`; `gh api repos/OWNER/REPO/actions/permissions/workflow`; los tres GET usan exactamente `-H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28"` |
| `kubectl-cluster` | `kubectl [--context CONTEXT] version -o json`; `kubectl [--context CONTEXT] get namespaces -o json` |
| `kubectl-rbac` | `kubectl [--context CONTEXT] get clusterroles,clusterrolebindings -o json`; `kubectl [--context CONTEXT] get roles,rolebindings (--namespace NAMESPACE|--all-namespaces) -o json` |
| `kubectl-workloads` | `kubectl [--context CONTEXT] get deployments,statefulsets,daemonsets,replicasets,cronjobs,jobs,pods (--namespace NAMESPACE|--all-namespaces) -o json` |

No aceptan comandos libres: validan opciones tipadas, el argv completo contra una allow-list, ejecutan con
`shell=False`, aplican timeout, usan un cwd temporal neutral y redactan datos sensibles. El ejecutable se resuelve una
vez a ruta absoluta e `stdin` permanece cerrado. Si stdout supera 4 MiB después de que `subprocess.run` lo captura, el
payload completo se descarta: el comando y el collector quedan `ERROR` con `OUTPUT_LIMIT`, no se persiste ni evalúa el
payload y nunca puede resultar en `PASS`. Es un límite post-captura de persistencia/evaluación, no streaming ni cuota
de memoria: `capture_output` todavía materializa stdout en memoria.

Si falta el cliente, credenciales o permisos, el resultado es `UNAVAILABLE` o `ERROR`; esa ausencia nunca se convierte
en evidencia runtime. Las identidades deben restringirse externamente a lectura. El nombre read-only describe los
comandos remotos permitidos; los clientes heredan el entorno para usar credenciales configuradas y pueden mantener
cache/configuración local. Use una cuenta de SO dedicada y un entorno mínimo para mayor assurance.

El puente de aplicabilidad conserva dos hechos distintos. Solicitar un collector activa
`collector-<id>-requested`, incluso si termina `UNAVAILABLE` o `ERROR`, para seleccionar el control y producir
`NOT_ASSESSED` en vez de ocultarlo como no aplicable. Solo un resultado `AVAILABLE` con contrato y hash canónico
verificados activa señales `runtime-*` y de proveedor. Seis checks consumen evidencia runtime directamente:

| Collector | Señal solicitada | Señal runtime | Check |
|---|---|---|---|
| `aws-iam` | `collector-aws-iam-requested` | `runtime-aws-iam` | `CCHIA-AWS-IAM-004` |
| `az-role-assignments` | `collector-az-role-assignments-requested` | `runtime-azure-role-assignments` | `CCHIA-AZURE-IAM-005` |
| `gcloud-iam` | `collector-gcloud-iam-requested` | `runtime-gcp-iam` | `CCHIA-GCP-IAM-003` |
| `gh-repo-security` | `collector-gh-repo-security-requested` | `runtime-github-repo-security` | `CCHIA-GH-REPO-006` |
| `kubectl-rbac` | `collector-kubectl-rbac-requested` | `runtime-k8s-rbac` | `CCHIA-K8S-RBAC-002` |
| `kubectl-workloads` | `collector-kubectl-workloads-requested` | `runtime-k8s-workloads` | `CCHIA-K8S-WL-003` |

`kubectl-cluster` activa `collector-kubectl-cluster-requested` y, solo cuando queda `AVAILABLE`,
`runtime-kubernetes`; aporta inventario/señales, pero aún no tiene un evaluador runtime dedicado. Este puente es
fail-closed respecto de la evidencia: `UNAVAILABLE`, `ERROR`, `OUTPUT_LIMIT`, hash/contrato inválido, paginación o
payload crítico incompleto nunca habilitan `PASS`.

`--plan-only` evita ejecutar checks, pero un `--collector` solicitado explícitamente sí se ejecuta para incorporarlo al
plan. Para garantizar cero comandos runtime, no pase `--collector`.

## Crear un control

```powershell
python seguridad-ia-cchia\scripts\cchia.py new-check `
  --id CCHIA-API-001 --domain API --title "Autorización de objetos"
python seguridad-ia-cchia\scripts\cchia.py validate
```

El scaffold crea los cinco archivos base con `version: 1.0.0`. El autor debe agregar los tres fixtures canónicos antes
de que `validate` acepte el control. `check.py` recibe un snapshot serializado y se ejecuta con un perfil
best-effort en capas: AST/builtins, `python -I -S -B -X utf8`, cwd temporal, entorno allow-listed, stdin cerrado, timeout y
terminación del grupo de procesos. POSIX intenta session/rlimits; Windows intenta Job Object con kill-on-close y cuotas
de memoria, CPU y procesos. La salida combinada también tiene cuota. Cada ejecución registra controles, límites,
fallbacks, limitaciones y outcome.

El perfil declara `strong_os_boundary=false`: no ofrece aislamiento OS de red ni filesystem. Si Job Object/rlimit no
está disponible, mantiene las capas portables por compatibilidad y registra el fallback; no falla cerrado. Por ello no
es una frontera suficiente para checks hostiles. Consulte [security-compiler.md](seguridad-ia-cchia/references/security-compiler.md).

## Pruebas

```powershell
python -m unittest discover -s seguridad-ia-cchia\tests -v
```

Baseline de engine 0.5.0: **137 tests** y el gate de **11 checks/33 fixtures**. Los artefactos E2E se generan localmente
y se excluyen del repositorio mediante `.gitignore` para evitar publicar snapshots o rutas del entorno evaluado. Los
tests, fixtures y el E2E runtime usan respuestas sintéticas/mocks contractuales: demuestran wiring, estados, redacción,
hashes y evaluación, pero **no prueban consultas autenticadas ni el estado de tenants/cuentas/clusters/repositorios
reales**.

## Instalación de la skill

En Codex (junction para desarrollo):

```powershell
$skillSource = (Resolve-Path .\seguridad-ia-cchia).Path
cmd /c mklink /J "$env:USERPROFILE\.codex\skills\seguridad-ia-cchia" "$skillSource"
```

En Claude Code:

```powershell
$skillSource = (Resolve-Path .\seguridad-ia-cchia).Path
cmd /c mklink /J "$env:USERPROFILE\.claude\skills\seguridad-ia-cchia" "$skillSource"
```

## Estado 0.5.0 y roadmap

La cobertura basal de AWS IAM, Azure RBAC y seguridad de repositorios GitHub ya está implementada junto con GCP IAM y
Kubernetes. “Basal” no significa cobertura completa del proveedor. Quedan, entre otras superficies, AWS
Organizations/SCP, resource policies e IAM Identity Center; herencia de Azure management groups, PIM/eligible roles,
custom roles y deny assignments; y paginación/detalle completo de rulesets y superficies organization/enterprise de
GitHub.

La evolución compatible prioriza firma/attestation del catálogo y evidencia, policy engine para scopes/approvals, pool
acotado de workers, continuous assurance con diff/scheduler, captura de stdout realmente streaming y acotada, y un
sandbox externo fuerte para ejecutar checks no confiables. Estas capacidades siguen pendientes; el worker actual no
debe presentarse como aislamiento absoluto.

## Límites

Un `PASS` cubre solo el patrón y evidencia suministrada; no significa “seguro” ni “certificado”. Los mappings son
referencias justificadas, no declaraciones de conformidad. El compilador escribe sus artefactos en `--output`; los
collectors opt-in invocan clientes instalados por el operador y dependen de sus credenciales, permisos y conducta
local. Orientación técnica, no asesoría legal.

Los snapshots actuales no prueban historia, drift, acceso efectivo ni cobertura total. En particular, `aws-iam` no
incluye SCP ni IAM Identity Center; `az-role-assignments` no demuestra asignaciones heredadas desde management groups;
y `gh-repo-security` puede encontrar paginación o ausencia de detalle de rulesets y requiere permisos de lectura de
Administration para workflow permissions. Esas limitaciones o errores se conservan como evidencia insuficiente, nunca
como `PASS`.

La versión SemVer de cada control viaja en plan, evidencia, findings e informes. El fingerprint del catálogo incluye
todos los archivos del paquete, incluidos README, mappings y fixtures; detecta cambios, pero no sustituye una firma de
catálogo ni una attestation de identidad.

Los valores `$id` bajo `https://cchia.cl/schemas/` son identificadores de namespace de JSON Schema; esta versión no
afirma que esos recursos estén alojados públicamente en esas URLs. Consulte [NOTICE.md](NOTICE.md) para procedencia.
