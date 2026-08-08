# Autoría de CCHIA Checks

## Anatomía obligatoria

Cada control es una unidad versionable con los cinco archivos base y tres fixtures obligatorios. El motor es
compartido; el check contiene solo la lógica específica.

```text
checks/<DOMAIN>/<CCHIA-ID>/
├── control.yaml
├── check.py
├── expected.json
├── mapping.yaml
├── README.md
└── fixtures/
    ├── positive.json
    ├── negative.json
    └── no_evidence.json
```

- `control.yaml`: identidad y versión SemVer, objetivo, severidad, nivel de evidencia, aplicabilidad, timeout read-only y plantilla de finding.
- `check.py`: una función pura `evaluate(context)`; sin imports, filesystem, red, subprocess, introspección ni credenciales.
- `expected.json`: statuses y campos obligatorios del resultado.
- `mapping.yaml`: mappings directos/conceptuales con rationale, fuente primaria y fecha de verificación.
- `README.md`: alcance, evidencia, falsos positivos, límites y verificación.

Los schemas canónicos están en `schemas/`. Crear con `python scripts/cchia.py new-check ...` y validar con
`python scripts/cchia.py validate`.

El scaffold crea los cinco archivos base con `version: 1.0.0`; no inventa contextos de prueba. El autor debe completar
los tres fixtures antes de que `validate` acepte el paquete.

## Versionado

`control.yaml.version` usa SemVer `X.Y.Z` y es independiente de la versión del engine (`0.5.0` actualmente). Mantener
el ID para el mismo objetivo de control: usar patch para correcciones compatibles, minor para ampliaciones compatibles
y major cuando cambie de forma incompatible el contrato o significado. La versión se propaga a plan, evidencia,
findings e informes.

El fingerprint del catálogo incluye todos los archivos del paquete, también README, mappings y fixtures. Esto permite
detectar que cambió la revisión efectiva evaluada, pero no sustituye una firma del catálogo.

## Contrato de salida

Retornar:

```python
{
    "status": "PASS|FAIL|PARTIAL|NOT_ASSESSED",
    "confidence": "HIGH|MEDIUM|LOW",
    "evidence_level": "E0|E1|E2|E3|E4|E5",
    "summary": "observación acotada",
    "evidence": [{"path": "...", "line": 1, "pattern": "..."}],
    "recommendation": "acción y verificación concretas",
}
```

No incluir secretos o PII crudos en evidencia. Reportar identificadores, hashes, rutas y líneas. Un PASS debe decir
qué cubrió y qué no cubrió. No concluir compliance global desde el resultado.

## Contrato de fixtures

Cada JSON contiene exactamente `schema_version`, `control_id`, `case`, `expected_status` y `context`:

- `positive.json`: debe producir `FAIL` o `PARTIAL`.
- `negative.json`: evidencia suficiente y cobertura completa para `PASS`.
- `no_evidence.json`: debe producir `NOT_ASSESSED`, nunca PASS.

Si el contexto incluye resultados collector, deben validar `collector-result.schema.json` y su `evidence_sha256`
debe corresponder al payload canónico `{collector_id, collector_version, evidence}`. Los fixtures usan evidencia
sintética/redacted y el gate los ejecuta sin invocar herramientas externas.

## Applicability

Usar señales `repository`, `terraform`, `kubernetes`, `cloud`, `gcp`, `aws`, `azure`, `github`, `ai`, `agent`, `mcp`,
`high-impact-tools`, `human-approval`, `external-input` o `sensitive-data`. Combinar `all_of`, `any_of` y `none_of`.
La selección siempre debe conservar razones en `plan.json`.

Para controles runtime combinar en `any_of` la señal disponible y la solicitada, por ejemplo
`[runtime-gcp-iam, collector-gcloud-iam-requested]`. El puente activa `collector-<id>-requested` para cualquier
resultado conocido, incluido `UNAVAILABLE/ERROR`, de modo que el check se seleccione y concluya `NOT_ASSESSED`.
Solo `AVAILABLE` con contrato y hash válido activa señales `runtime-*`/proveedor. Los evaluadores actuales son:
`CCHIA-AWS-IAM-004`, `CCHIA-AZURE-IAM-005`, `CCHIA-GCP-IAM-003`, `CCHIA-GH-REPO-006`,
`CCHIA-K8S-RBAC-002` y `CCHIA-K8S-WL-003`.

Los pares nuevos son:

- `aws-iam`: `collector-aws-iam-requested` + `runtime-aws-iam`.
- `az-role-assignments`: `collector-az-role-assignments-requested` + `runtime-azure-role-assignments`.
- `gh-repo-security`: `collector-gh-repo-security-requested` + `runtime-github-repo-security`.

Un evaluator runtime debe validar status, versión, mode, redacción, hash, provider/interface, policy IDs, argv exactos,
estado de cada comando, content type y estructura completa del payload antes de permitir PASS/FAIL. `UNAVAILABLE`,
`ERROR`, `OUTPUT_LIMIT`, truncamiento, paginación no demostrablemente completa, metadata/comandos/payload incompletos o
campos críticos redacted terminan `NOT_ASSESSED` (o `PARTIAL` solo cuando existe un gap observado pero el alcance no
permite una conclusión completa), nunca PASS.

## Read-only y determinismo

El motor entrega un snapshot serializado; el check no recibe rutas ni clientes cloud con capacidad de acción. El
worker usa Python aislado, builtins mínimos y timeout. El compilador compara hashes pre/post del target. Los collectors
actuales usan clientes externos con credenciales configuradas explícitamente para lectura y permanecen separados del
evaluator; el check solo consume su evidencia JSON redacted.

El executor de collectors descarta stdout superior a 4 MiB después de que `capture_output` lo materializa. Registra
`ERROR`/`OUTPUT_LIMIT` y no persiste ni entrega el payload al evaluator. Este límite post-captura no es streaming ni
cuota de memoria; una captura realmente acotada sigue pendiente.

## Quality gate del control

1. ID/carpeta/domain coinciden y el catálogo valida.
2. Aplicabilidad selecciona y excluye correctamente.
3. Existe fixture positivo, negativo y sin evidencia.
4. La evidencia no contiene secretos.
5. Mapping y fuente están verificados, sin copiar material ISO protegido.
6. Timeout/error producen ERROR, no PASS.
7. El README declara límites y procedimiento de verificación.

Ejecutar `python scripts/cchia.py validate` como gate final. El engine 0.5.0 distribuye 11 checks, 33 fixtures y 7
collectors; el catálogo debe reportar
`11 CCHIA Checks y 33 fixtures válidos`; un fixture ausente, un status inesperado, un contrato roto o un hash collector
inválido debe hacer fallar el comando.

La baseline es de 138 tests. Los fixtures y E2E runtime usan collectors mockeados y evidencia sintética: prueban el
contrato del paquete y la semántica fail-closed, no el estado ni la autenticación de tenants/cuentas/clusters/repositorios
reales. AWS/Azure/GitHub ya están cubiertos de forma basal; profundidad de proveedor, firma/attestation, policy/pool,
continuous assurance, streaming acotado y sandbox externo fuerte permanecen en roadmap.
