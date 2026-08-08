# seguridad-ia-cchia

Skill autocontenida con conocimiento CCHIA, catálogo de checks y el CCHIA Security Compiler. La guía de uso,
arquitectura, instalación, comandos y pruebas se mantiene en el [README del repositorio](../README.md); las reglas
operativas para el agente están en [SKILL.md](SKILL.md).

El motor **0.5.0** distribuye **11 checks, 33 fixtures y 7 collectors runtime opt-in**. Cubre IAM/repositorios,
inventario de IA, aprobación de agentes/MCP, IAM de GCP en Terraform, hardening estático de Kubernetes y seis
evaluadores runtime: `CCHIA-AWS-IAM-004`, `CCHIA-AZURE-IAM-005`, `CCHIA-GCP-IAM-003`, `CCHIA-GH-REPO-006`,
`CCHIA-K8S-RBAC-002` y `CCHIA-K8S-WL-003`. Está diseñado para crecer a cientos de controles sin duplicar el motor.

El intake usa el selector v2: conserva `signals` por compatibilidad y agrega `signal_details` con confidence,
evidencia y provenance para separar una tecnología declarada/usada de una simple mención documental. Si los límites
de archivos, tamaño, lectura o decodificación dejan cobertura incompleta, `collection.complete=false` impide mantener
un `PASS`: el resultado se representa como `NOT_ASSESSED` por falta de evidencia.

Los collectors runtime están desactivados por defecto. `python scripts/cchia.py collectors` solo lista el catálogo;
la ejecución requiere uno o más `--collector`. El catálogo contiene `aws-iam`, `az-role-assignments`, `gcloud-iam`,
`gh-repo-security`, `kubectl-cluster`, `kubectl-rbac` y `kubectl-workloads`. Las opciones de selección son
`--aws-profile`, `--azure-subscription`, `--gcp-project`, `--github-repo`, `--kube-context` y `--kube-namespace`;
`--collector-timeout` acepta 1–300 segundos. Requieren identidades configuradas externamente con permisos de solo
lectura y no aceptan comandos libres.

AWS ejecuta únicamente caller identity, account summary y account authorization details; Azure ejecuta exactamente
`az account show [--subscription VALUE] --output json` y
`az role assignment list --all [--subscription VALUE] --output json`; GitHub ejecuta un `gh repo view` con cuatro
campos fijos y tres GET `gh api` fijos para metadata, rulesets y Actions workflow permissions. La matriz completa de
argv permitidos está en [references/security-compiler.md](references/security-compiler.md).

El ejecutor compartido resuelve una sola ruta absoluta, usa `shell=False`, cwd temporal e `stdin` cerrado. Si stdout
supera 4 MiB después de ser capturado, descarta el payload y emite `ERROR`/`OUTPUT_LIMIT`; nunca lo persiste, evalúa ni
convierte en `PASS`. Es un límite post-captura: `capture_output` aún materializa stdout en memoria y no constituye
streaming acotado.

El puente requested/runtime evita falsos `NOT_APPLICABLE`: todo resultado de un collector conocido activa la señal
`collector-<id>-requested`; si termina `UNAVAILABLE` o `ERROR`, el check se selecciona y responde `NOT_ASSESSED`.
Solo `AVAILABLE`, con contrato y `evidence_sha256` canónico verificados, activa señales runtime/proveedor y habilita
una posible conclusión `PASS` o `FAIL` según la suficiencia estructural de la evidencia.

Los tres providers nuevos mantienen la misma separación: `aws-iam` activa
`collector-aws-iam-requested`/`runtime-aws-iam`; `az-role-assignments`,
`collector-az-role-assignments-requested`/`runtime-azure-role-assignments`; y `gh-repo-security`,
`collector-gh-repo-security-requested`/`runtime-github-repo-security`. La señal runtime aparece solo con evidencia
`AVAILABLE` válida. Un error, truncamiento, `OUTPUT_LIMIT`, hash/contrato inválido, paginación o payload crítico
incompleto queda fail-closed como `NOT_ASSESSED` o el estado conservador definido por el check, nunca como PASS.

Cada `control.yaml` lleva una versión SemVer independiente, actualmente `1.0.0`, propagada a plan, evidencia,
findings e informes. Los tres fixtures obligatorios —positivo, negativo y sin evidencia— forman parte del paquete y
del fingerprint del catálogo. `python scripts/cchia.py validate` es el gate ejecutable: exige la matriz completa,
valida contratos/hashes y debe informar `11 CCHIA Checks y 33 fixtures válidos` para esta distribución.

La baseline 0.5.0 es de **137 tests**. Las pruebas y E2E runtime usan mocks/fixtures sintéticos; verifican contratos,
wiring, redacción y semántica, pero no consultan ni prueban tenants AWS/Azure/GCP, clusters o repositorios GitHub reales.

AWS/Azure/GitHub ya tienen cobertura basal, no exhaustiva. Quedan superficies más profundas —incluidos SCP/Identity
Center, herencia de management groups y detalle/paginación de rulesets—, firma/attestation, policy engine y pool de
workers, continuous assurance, captura streaming acotada y un sandbox externo fuerte.

El worker aplica un perfil `layered-best-effort`: capas portables y controles OS opcionales con fallback registrado.
Siempre declara `strong_os_boundary=false`, porque red y filesystem no tienen aislamiento de SO. Ninguna
documentación debe describirlo como hipervisor o aislamiento absoluto. Las garantías y degradaciones vigentes están
en [references/security-compiler.md](references/security-compiler.md).
