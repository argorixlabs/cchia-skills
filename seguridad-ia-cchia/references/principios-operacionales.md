# Principios operacionales CCHIA

## Contenido

1. Evidencia y certeza
2. Riesgo, madurez y assurance
3. Findings y gap analysis
4. Defensa, roadmap y métricas
5. Informes y scores
6. Quality gate

## 1. Evidencia y certeza

Clasificar cada afirmación como evidencia observada, declaración del usuario, inferencia, suposición, información
faltante, requisito normativo, recomendación o buena práctica. No usar una política, certificación, página comercial,
badge o declaración de proveedor como prueba automática de implementación.

Niveles independientes de madurez:

| Nivel | Significado |
|---|---|
| E0 | Sin evidencia |
| E1 | Declarado sin soporte |
| E2 | Documentado |
| E3 | Implementado/configurado |
| E4 | Probado independientemente |
| E5 | Assurance continuo |

Orden de confianza: `Policy < Configuration < Runtime Evidence < Independent Test < Continuous Assurance`.

## 2. Riesgo, madurez y assurance

Fundamentar likelihood mediante exposición, explotabilidad, capacidad del atacante, precondiciones y controles.
Fundamentar impact mediante confidencialidad, integridad, disponibilidad, privacidad, finanzas, operación, legal,
reputación, safety y autonomía. Usar `CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL` y confidence `HIGH/MEDIUM/LOW`.

Madurez organizacional: 0 inexistente, 1 inicial/ad hoc, 2 repetible inconsistente, 3 definido/institucionalizado,
4 gestionado con métricas, 5 optimizado con mejora y assurance. No otorgar nivel 5 por automatización sola.

Para cada componente preguntar: si se compromete por completo, ¿hasta dónde llega el atacante? Reducir blast radius
con segmentación, identidades aisladas, mínimo privilegio, policy enforcement y sandboxing.

## 3. Findings y gap analysis

Cada finding debe contener ID, título, severity, confidence, activo/proceso, evidencia, observación, riesgo, impacto de
negocio, impacto técnico, impacto regulatorio si aplica, mapping justificado, root cause si es determinable,
recomendación, prioridad, owner, verificación y riesgo residual.

Estados de gap: `COMPLIANT`, `PARTIALLY COMPLIANT`, `NON-COMPLIANT`, `NOT ASSESSED`, `NOT APPLICABLE`. Usar el
primero solo cuando el alcance y evidencia permiten esa conclusión; un check técnico normalmente produce una
observación de control, no certificación de conformidad.

En crosswalks, no rellenar casillas por simetría. Usar `No direct mapping identified` cuando no exista equivalencia
defendible. Distinguir mapping directo, conceptual e informativo.

## 4. Defensa, roadmap y métricas

Diseñar defense in depth: prevenir, detectar, responder y recuperar. Para prompt injection no basta filtrar prompts:
combinar least privilege, separación de contexto, autorización de retrieval, output validation, aprobación, límites,
monitoring, sandbox, revocación y rollback.

Roadmap: Immediate 0–30 días, Near Term 30–90, Medium Term 3–6 meses, Strategic 6–18 meses. Para cada iniciativa
indicar objetivo, control, riesgo reducido, owner, complejidad, dependencias y evidencia de cierre.

Usar KPIs/KRIs accionables: cobertura MFA/PAM, vulnerabilidades fuera de SLA, MTTD/MTTR, recuperaciones probadas,
artefactos firmados, sistemas IA registrados, agentes con overrides, unsafe tool-call rate y concentración de proveedor.

## 5. Informes y scores

Para directorio: resumen, riesgo global, top 5, exposición, dependencias, decisiones inmediatas, plan 90 días y
recomendaciones estratégicas. Traducir a dinero, operación, continuidad, confianza, privacidad, reputación y safety.

Para audiencia técnica: arquitectura, evidencia, findings, componentes, condiciones, gaps, remediación, validación y
mappings. Nunca ocultar incertidumbre.

Si se calcula score 0–100, separar dominios: Governance, Asset Management, IAM, Infrastructure, Cloud, AppSec, Data,
Privacy, Detection, Incident Response, Resilience, Supply Chain, AI Governance, AI Security y Agentic Security. No
permitir que el promedio oculte categorías deficientes. El score es indicador interno, no sello ni certificación.

## 6. Quality gate

Verificar antes de entregar:

- Versiones/fuentes correctas y fecha de corte.
- Aplicabilidad justificada y alcance/exclusiones visibles.
- Cada conclusión soportada por evidencia proporcional.
- Separación de seguridad, compliance, resiliencia y privacidad/legal.
- IA evaluada como sistema sociotécnico; agentes como identidad + software + modelo + permisos + memoria + APIs + datos + acción.
- Supply chain, terceros, recuperación y observabilidad considerados.
- Recomendaciones operables y verificables.
