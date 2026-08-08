# CCHIA Security Compiler 0.5.0

## Pipeline

```text
arquitectura + repo + IaC + K8s + MCP/agentes
        -> intake read-only + señales con confidence/provenance
        -> collectors runtime read-only (solo opt-in)
        -> validación de contrato + hash canónico del collector
        -> applicability + plan.json
        -> workers acotados + checks puros
        -> evidence/<control>.json
        -> assessment.json
        -> report-cchia.md + report-nist.md + report-iso.md
        -> manifest.json con SHA-256
```

## Uso

```powershell
python scripts/cchia.py validate
python scripts/cchia.py list
python scripts/cchia.py collectors
python scripts/cchia.py compile --target C:\repo --system C:\system.yaml --output C:\evidencia
python scripts/cchia.py compile --target C:\repo --output C:\plan --plan-only
python scripts/cchia.py compile --target C:\repo --output C:\evidencia --control CCHIA-IAM-001
python scripts/cchia.py compile --system C:\arquitectura.md --output C:\evidencia-arquitectura
```

Usar un directorio `--output` nuevo o vacío por assessment. El compilador rechaza directorios no vacíos para que
evidencia residual de otra corrida no quede incluida en el manifest actual.

`system.yaml` puede documentar name, description, owner, jurisdictions, data_categories, components, agents, tools,
human_oversight, monitoring, decommissioning y señales explícitas. El schema está en `schemas/system.schema.json`.

## Selector de aplicabilidad v2

El contexto conserva `signals` como lista estable para los controles existentes y agrega `signal_details`. Cada
detalle incluye `active`, confidence numérica/label y evidencia con source, kind y provenance. Las fuentes tienen
distinto peso:

- `system.signals` es una declaración explícita del operador.
- Campos estructurados, firmas Terraform/Kubernetes/MCP y SDKs detectados son evidencia técnica o declarativa.
- Texto libre solo activa un proveedor cuando expresa uso/despliegue; una mención genérica o de roadmap queda `LOW`
  con `supports_activation=false`.
- Las señales derivadas identifican su origen, por ejemplo `cloud` derivada de `gcp`.

Solo las señales activas alimentan `all_of`, `any_of` y `none_of`. Las menciones débiles permanecen en
`signal_details` para que la exclusión sea auditable. El operador puede usar `--control` para acotar explícitamente el
plan; esto fuerza selección, pero no transforma evidencia ausente en PASS.

### Puente requested/runtime

El contexto distingue solicitud de disponibilidad:

- Todo resultado de un collector conocido activa `collector-<id>-requested`, aunque su status sea `UNAVAILABLE` o
  `ERROR`. Los checks runtime declaran esa señal en `any_of`, quedan seleccionados y responden `NOT_ASSESSED` cuando
  no existe evidencia suficiente.
- Solo `AVAILABLE`, con contrato válido y `evidence_sha256` verificado, activa las señales de proveedor y
  `runtime-*`. Por ejemplo, `gcloud-iam` activa `gcp`, `cloud` y `runtime-gcp-iam`; un error no lo hace.

Los pares incorporados en 0.5.0 son:

| Collector | Requested | Runtime/proveedor | Check seleccionado |
|---|---|---|---|
| `aws-iam` | `collector-aws-iam-requested` | `runtime-aws-iam`, `aws`, `cloud` | `CCHIA-AWS-IAM-004` |
| `az-role-assignments` | `collector-az-role-assignments-requested` | `runtime-azure-role-assignments`, `azure`, `cloud` | `CCHIA-AZURE-IAM-005` |
| `gh-repo-security` | `collector-gh-repo-security-requested` | `runtime-github-repo-security`, `github`, `repository` | `CCHIA-GH-REPO-006` |

Así, la ausencia operacional queda visible como cobertura no evaluada y no se confunde con `NOT_APPLICABLE`. El hash
se calcula sobre `{collector_id, collector_version, evidence}` y se verifica antes del enriquecimiento y evaluación.

## Cobertura y semántica de estados

La recolección está acotada por `max_files=2000` y `max_file_bytes=1000000`. `context.collection` publica límite,
candidatos, archivos leídos, exclusiones por límite, errores, muestras, `truncated`, `complete` y `pass_eligible`.
Un archivo candidato fuera de la ventana conserva la señal `repository`, de modo que el control correspondiente sea
evaluado con limitación en vez de desaparecer como `NOT_APPLICABLE`.

Si `collection.complete=false`, cualquier resultado originalmente `PASS` se degrada centralmente a
`NOT_ASSESSED`, confidence `LOW` y nivel `E0`. `NOT_ASSESSED` significa que no existe evidencia suficiente para
concluir; no equivale a `FAIL`. Un FAIL observado puede mantenerse aunque la ventana sea incompleta, pero no prueba
que sea el único hallazgo.

Los snapshots pre/post usan la misma ventana acotada. `target_integrity.unchanged=true` demuestra invariancia de los
archivos incluidos, no de candidatos omitidos ni de recursos runtime externos.

## Collectors opt-in

`collectors` lista el catálogo sin descubrir ni ejecutar clientes. La secuencia vacía es un no-op: una compilación
normal no llama `aws`, `az`, `gcloud`, `gh` ni `kubectl`. La ejecución se solicita expresamente con `--collector`
repetible:

```powershell
python scripts/cchia.py compile --target C:\repo --output C:\evidencia-gcp `
  --collector gcloud-iam --gcp-project mi-proyecto

python scripts/cchia.py compile --target C:\repo --output C:\evidencia-k8s `
  --collector kubectl-cluster --collector kubectl-rbac --collector kubectl-workloads `
  --kube-context auditoria@cluster --kube-namespace produccion --collector-timeout 30

python scripts/cchia.py compile --target C:\repo --output C:\evidencia-aws `
  --collector aws-iam --aws-profile auditoria

python scripts/cchia.py compile --target C:\repo --output C:\evidencia-azure `
  --collector az-role-assignments --azure-subscription suscripcion-auditada

python scripts/cchia.py compile --target C:\repo --output C:\evidencia-github `
  --collector gh-repo-security --github-repo OWNER/REPO
```

Siete superficies implementadas:

| Collector | Comandos remotos allow-listed | Opción tipada | Evaluación actual |
|---|---|---|---|
| `aws-iam` | `aws [--profile PROFILE] sts get-caller-identity --output json`; `aws [--profile PROFILE] iam get-account-summary --output json`; `aws [--profile PROFILE] iam get-account-authorization-details --filter User Role Group LocalManagedPolicy --output json` | `--aws-profile` opcional | `CCHIA-AWS-IAM-004` |
| `az-role-assignments` | `az account show [--subscription SUBSCRIPTION] --output json`; `az role assignment list --all [--subscription SUBSCRIPTION] --output json` | `--azure-subscription` opcional | `CCHIA-AZURE-IAM-005` |
| `gcloud-iam` | `gcloud projects describe PROJECT --format=json --quiet`; `gcloud projects get-iam-policy PROJECT --format=json --quiet`; `gcloud iam service-accounts list --project PROJECT --format=json --quiet` | `--gcp-project` obligatorio | `CCHIA-GCP-IAM-003` |
| `gh-repo-security` | `gh repo view OWNER/REPO --json nameWithOwner,defaultBranchRef,visibility,isArchived`; `gh api repos/OWNER/REPO`; `gh api repos/OWNER/REPO/rulesets`; `gh api repos/OWNER/REPO/actions/permissions/workflow`; los GET API usan exactamente `-H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: 2022-11-28"` | `--github-repo` obligatorio | `CCHIA-GH-REPO-006` |
| `kubectl-cluster` | `kubectl [--context CONTEXT] version -o json`; `kubectl [--context CONTEXT] get namespaces -o json` | `--kube-context` opcional | Inventario/señales; sin check runtime dedicado. |
| `kubectl-rbac` | `kubectl [--context CONTEXT] get clusterroles,clusterrolebindings -o json`; `kubectl [--context CONTEXT] get roles,rolebindings (--namespace NAMESPACE\|--all-namespaces) -o json` | `--kube-context`/`--kube-namespace` opcionales | `CCHIA-K8S-RBAC-002` |
| `kubectl-workloads` | `kubectl [--context CONTEXT] get deployments,statefulsets,daemonsets,replicasets,cronjobs,jobs,pods (--namespace NAMESPACE\|--all-namespaces) -o json`; excluye Secrets/ConfigMaps | `--kube-context`/`--kube-namespace` opcionales | `CCHIA-K8S-WL-003` |

No existe entrada de shell libre. Las opciones son tipadas, cada argv completo debe coincidir con una policy
allow-listed, `shell=False`, y el timeout aceptado es 1–300 segundos por comando. La salida se parsea como JSON cuando
es posible, se redacta por claves/patrones sensibles y el texto se trunca a una ventana acotada. La evidencia conserva
provenance, comandos, estado y hash. El compilador rechaza un hash que no corresponda al payload canónico del
collector; un digest válido aporta integridad, no identidad de firmante.

El executor aplica además un límite post-captura de 4 MiB a stdout. `subprocess.run(capture_output)` todavía
materializa la salida completa en memoria; después se mide. Si excede el límite, se descarta íntegramente, no se
redacta/persiste ni se entrega al evaluator, y el comando y collector terminan `ERROR` con `OUTPUT_LIMIT`. Por tanto
nunca habilita PASS. Esto no debe describirse como streaming ni como cuota de memoria; una captura realmente streaming
y acotada sigue pendiente.

El ejecutable se descubre y resuelve una vez a ruta absoluta; el subprocess usa cwd temporal neutral y stdin cerrado.
El entorno se hereda intencionalmente para que `aws`/`az`/`gcloud`/`gh`/`kubectl` encuentren sus credenciales y
configuración. Por ello
el operador debe minimizar variables, archivos de configuración y privilegios de la cuenta de SO que lanza el motor.

`UNAVAILABLE` indica que el cliente no estaba en PATH y no se ejecutó ningún comando. `ERROR` cubre timeout, permisos,
credenciales, endpoint u otro fallo y no demuestra estado runtime. `AVAILABLE` solo demuestra que los comandos
permitidos respondieron en ese momento. La allow-list limita la intención del comando, pero no puede convertir una
identidad privilegiada en read-only: el operador debe configurar todas las identidades CLI con permisos de lectura.
Los clientes externos además pueden escribir sus propios caches/configuración local fuera del target.

La cobertura de proveedor es basal y fail-closed ante evidencia insuficiente:

- AWS no evalúa SCP, resource policies, permission sets de IAM Identity Center ni permisos fuera de la cuenta.
- Azure `role assignment list --all` no demuestra asignaciones heredadas desde management groups, PIM/eligibilidad,
  deny assignments ni custom roles equivalentes.
- GitHub puede paginar la lista de rulesets, omitir el detalle de reglas y exige `Administration:read` para workflow
  permissions. Error de permiso, paginación o detalle crítico ausente nunca se interpreta como configuración segura.

En todos los casos `UNAVAILABLE`, `ERROR`, `OUTPUT_LIMIT`, hash/contrato inválido, payload no JSON, truncado o
estructuralmente incompleto impide PASS. Los checks distinguen un gap observado (`FAIL` o, cuando el alcance observable
solo permite una conclusión parcial, `PARTIAL`) de evidencia ausente (`NOT_ASSESSED`).

`--plan-only` omite los CCHIA Checks, pero no cancela collectors solicitados explícitamente: estos se ejecutan antes de
emitir el plan para registrar su evidencia. Usar `--plan-only` sin `--collector` cuando se requiera cero acceso runtime.

## Artefactos

- `context.json`: fingerprint, señales, razones y metadatos; excluye `content` de los archivos recolectados, pero
  conserva la descripción `system` suministrada.
- `plan.json`: alcance, señales, catálogo completo, versión de engine/control, conteo de controles/fixtures, decisión
  y razón de cada control.
- `collector-evidence/*.json`: respuesta runtime redacted por collector opt-in; no existe si no se solicitó ninguno.
- `evidence/*.json`: resultado, nivel/confidence, hash del check, mappings y hash de evidencia.
- `assessment.json`: fuente estructurada para findings, scores, limitaciones e integridad.
- `report-*.md`: vistas CCHIA, NIST e ISO de la misma evidencia.
- `manifest.json`: SHA-256 de cada artefacto para detectar cambios posteriores.

El fingerprint del catálogo recorre todos los archivos de cada paquete versionado, incluidos `control.yaml`, lógica,
mappings, documentación y `fixtures/*.json`. Un cambio de fixture altera el fingerprint aunque el check no cambie.

## Versionado y gate del catálogo

El engine actual es `0.5.0`; distribuye once controles, 33 fixtures y siete collectors. Los once controles usan SemVer
`1.0.0`. La versión del control queda en
`plan.json`, cada evidencia, findings e informes, de modo que ID y revisión no se confundan.

```powershell
python scripts/cchia.py validate
```

Este comando carga contratos y perfil read-only, exige `positive.json`, `negative.json` y `no_evidence.json` por
control, verifica collectors embebidos y sus hashes, ejecuta los checks contra los fixtures y compara el status real
con el esperado. No ejecuta `aws`, `az`, `gcloud`, `gh` ni `kubectl`. En esta distribución el gate exitoso informa
`11 CCHIA Checks y 33 fixtures válidos`; cualquier error retorna código no cero.

La baseline 0.5.0 es de 138 tests. Los unit tests, fixtures y E2E runtime usan evidencia sintética y procesos
mockeados: prueban contratos, allow-lists, wiring, estados, redacción, hashes y evaluación determinista, pero no
autentican ni prueban el estado de tenants AWS/Azure/GCP, clusters Kubernetes o repositorios GitHub reales.

## Límites de seguridad

Read-only describe la recolección y los comandos remotos allow-listed; el compilador sí escribe en `--output`. Si
output está dentro del target, se excluye explícitamente del fingerprint. Un cliente collector puede mantener cache o
configuración propia y por ello debe ejecutarse bajo una cuenta de SO dedicada cuando el assurance lo requiera.

### Perfil del worker y fallbacks

Cada evidencia publica `execution.isolation=layered-best-effort` y un objeto `execution.sandbox` con `profile`,
`platform`, controles efectivos, límites `requested/enforced`, fallbacks, limitaciones y outcome. `strong_os_boundary`
siempre es `false`.

Capas portables:

- AST gate y builtins mínimos, más validación estricta del contrato de salida.
- Intérprete `python -I -S -B -X utf8`, cwd temporal, entorno allow-listed y stdin `DEVNULL`.
- Timeout con terminación del árbol/grupo de procesos cuando la plataforma lo permite.
- Captura combinada stdout/stderr con límite; excederlo termina el árbol y produce `ERROR`.

Controles OS intentados:

- POSIX: sesión nueva, rlimits de memoria/CPU y `killpg` al vencer el timeout. El backend portable no aplica
  `RLIMIT_NPROC`: ese límite cuenta todos los procesos del UID, no solo el árbol del worker, y podría interferir con
  procesos ajenos. Una cuota de procesos por árbol requiere un UID dedicado o un controlador cgroup `pids`.
- Windows: Job Object con kill-on-close y límites de memoria, CPU y procesos activos.

Estos controles son defensa en profundidad y pueden no estar disponibles. El fallback no es fail-closed: si Job Object
o rlimit falla, el runner conserva las capas portables para compatibilidad y registra el fallo en `fallbacks` y
`limitations`. No hay aislamiento OS de red ni filesystem y esos controles aparecen inactivos. Un PASS bajo fallback
solo cubre la evaluación funcional; el consumidor debe decidir si la ausencia del control OS invalida su política de
ejecución.

La evidencia también conserva límites solicitados frente a los efectivamente aplicados. En Windows existe una pequeña
ventana entre crear el proceso y asignarlo al Job Object; en POSIX la semántica de `RLIMIT_AS` depende del kernel y
contenedor, y `max_processes` se declara no aplicado. Estas condiciones quedan declaradas, no se promueven a garantía
fuerte.

Esto reduce la superficie accidental de checks revisados, pero no convierte `exec` de Python en una frontera de
seguridad absoluta ni prueba ausencia de bypass del intérprete. No ejecutar checks no confiables únicamente sobre esta
base; revisar/firmar el catálogo y usar una VM/contenedor o frontera externa con filesystem read-only y red bloqueada
cuando el threat model incluya código de check hostil. Un timeout o salida inválida termina en `ERROR`, nunca en PASS.

El intake estático no prueba estado cloud/runtime, ausencia de drift, efectividad de approvals ni llegada/no llegada
al destino. Los collectors actuales agregan snapshots puntuales de AWS IAM, Azure RBAC, GCP IAM, GitHub y Kubernetes,
pero tampoco prueban historia, efectividad, no llegada al destino ni cobertura completa del proveedor. Para E4/E5 se
requieren fuentes autenticadas, pruebas independientes y cadena de custodia, manteniendo separados collector,
evaluator, policy y reporter.

## Estado 0.5.0 y evolución

AWS, Azure y GitHub ya tienen collector y control runtime basales; el roadmap no debe describirlos como proveedores
por incorporar desde cero. La evolución pendiente profundiza superficies (SCP/Identity Center/resource policies,
management-group inheritance/PIM/custom roles, ruleset detail/pagination y ámbitos organization/enterprise), firma y
attestation de catálogo/evidencia, policy engine y pool acotado de workers, continuous assurance, captura collector
streaming acotada y un sandbox externo fuerte con filesystem read-only y red bloqueada.
