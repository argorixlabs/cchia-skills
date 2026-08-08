# Cobertura, marcos y modos CCHIA

## Selección de marcos

Verificar vigencia en fuente primaria cuando la versión sea material. Usar solo lo aplicable:

- NIST CSF 2.0 para outcomes macro; RMF SP 800-37 para ciclo de autorización; SP 800-53/53A para controles y evaluación.
- NIST SP 800-30/34/39/61/63/92/115/137/160/161/171/172/190/207/218 según riesgo y tecnología.
- NIST AI RMF, Playbook y NIST AI 600-1 para IA/GenAI; declarar si AI RMF está en revisión.
- ISO/IEC 27001/27002/27005/27017/27018/27701 para seguridad/privacidad; 42001/23894/22989/23053/38507/42005 y
  familia 24027/24028/24029 para IA; 22301/31000 para continuidad/riesgo. Separar requisitos certificables de guidance.
- CIS Controls y Benchmarks como baselines; OWASP Top 10/API/ASVS/SAMM/MASVS/LLM/Agentic según superficie.
- MITRE ATT&CK/ATLAS para comportamientos adversarios, no como prueba automática de vulnerabilidad.
- CSA CCM y arquitecturas oficiales de proveedor para cloud; PCI DSS/SOC 2 solo si alcance/relación aplican.

## Dominios mínimos

- Cloud AWS/Azure/GCP: IAM, federation, PAM, workload identity, secrets/KMS, exposición, red, logs, backup/DR,
  storage/database/serverless, CI/CD, registries, landing zones y SaaS.
- Kubernetes/containers: provenance, signing, secrets, RBAC, service accounts, NetworkPolicy, Pod Security, privileged,
  capabilities, host mounts, metadata, control plane, etcd, audit, resources, admission y runtime detection.
- SDLC/supply chain: requirements, threat modeling, code review, SAST/DAST/SCA/IaC/container/secrets/fuzzing, build
  integrity, approvals, provenance, SBOM, SLSA, SPDX/CycloneDX, signing, pinning y disclosure.
- App/API: authn/authz, sesión, input/output, injection, SSRF, deserialización, paths/files, crypto, BOLA/BFLA,
  mass assignment, rate limits, webhook/replay, GraphQL, inventory y service identity.
- IAM/Zero Trust: lifecycle, MFA resistente a phishing, PAM/JIT/JEA, orphan/shared accounts, machine/agent identity,
  device/workload posture, continuous authorization, segmentation y telemetry.
- IA/agentes: prompt injection directa/indirecta, tool abuse, excessive agency, approval, identidad/autorización,
  memory/RAG poisoning e isolation, model/data supply chain, MCP trust, output handling, audit trail y kill switch.
- Datos/privacidad: ciclo create-to-delete, clasificación, access, encryption, retention, deletion, backups, residency,
  transfers, DLP, minimización, finalidad, titulares, subprocessors, DPIA/PIA y privacy by design/default.
- Terceros/resiliencia: acceso/datos/criticidad, fourth parties, incident history verificado, SLA, RTO/RPO, breach notice,
  portability/exit, BIA, backups inmutables y recuperación probada.
- OT/ICS cuando exista: NIST SP 800-82, IEC 62443, safety, availability, segmentación, legacy y acceso remoto. No aplicar
  cambios IT destructivos sin considerar safety.
- Criptografía: algoritmos, tamaños, KMS/HSM, TLS, certificates, rotación, crypto agility y migración post-cuántica.

## Modos

Reconocer `/security-assessment`, `/compliance`, `/crosswalk`, `/ai-security`, `/agent-security`, `/ai-governance`,
`/iso27001`, `/iso42001`, `/nist`, `/csf`, `/800-53`, `/cloud`, `/appsec`, `/api-security`, `/devsecops`,
`/supply-chain`, `/vendor-risk`, `/privacy`, `/incident`, `/threat-model`, `/architecture`, `/executive`, `/policy`,
`/control-design`, `/evidence` y `/roadmap`.

Para “evalúa esto”, producir por defecto: Executive Summary, Scope, Architecture/Context, Assets & Data, Threat
Surface, Findings, AI, Privacy, Cloud/Infrastructure, App/API, Identity, Supply Chain, Regulatory Considerations,
Framework Mapping, Risk Matrix, Quick Wins, 30/60/90, Strategic Roadmap, Evidence Missing y Residual Risk.

## Chile e internacional

Para Chile cargar `marco-legal-chile.md` y verificar ANCI/BCN en vivo antes de concluir vigencia o plazos. Distinguir
Ley 21.663, 21.459, régimen de datos y Ley 21.719 con calendario, regulación sectorial y proyectos no vigentes.
No dar conclusión legal definitiva.

Según jurisdicción/sector, evaluar GDPR, NIS2, DORA, EU AI Act, Cyber Resilience Act, FISMA/FedRAMP/CMMC,
HIPAA/GLBA/SEC/state privacy, LGPD, PCI DSS o regulación local. Nunca asumir jurisdicción.
