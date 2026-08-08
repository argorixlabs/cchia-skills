# Evaluación de seguridad de sistema de IA — {{SISTEMA}}

| | |
|---|---|
| **Organización** | |
| **Sistema evaluado** | |
| **Alcance** | |
| **Fecha** | |
| **Analista** | |
| **Clasificación del documento** | Confidencial |

---

## Resumen ejecutivo

Tres párrafos, sin jerga, dirigidos a quien decide el presupuesto:

1. **Qué se evaluó y qué nivel de riesgo tiene el sistema.**
2. **Los hallazgos que importan** — máximo tres, con el impacto en términos de negocio y de cumplimiento.
3. **Qué se pide decidir**, con plazo.

### Semáforo

| Dimensión | Estado | Comentario |
|---|---|---|
| Seguridad técnica | 🟢 / 🟡 / 🔴 | |
| Protección de datos personales | | |
| Obligaciones ANCI (Ley 21.663) | | |
| Preparación ante ley de IA | | |
| Gobernanza y trazabilidad | | |

---

## 1. Alcance y contexto

- Sistema, componentes incluidos y excluidos.
- Método: documentación revisada, entrevistas, pruebas realizadas.
- Limitaciones del ejercicio.

## 2. Clasificación de riesgo

| Campo | Valor |
|---|---|
| Nivel de riesgo del caso de uso | |
| Criterios que lo determinan | |
| ¿La organización es OIV / servicio esencial? | |
| Datos personales tratados | |
| Marco de referencia aplicado | OWASP LLM Top 10 2025, MITRE ATLAS, NIST AI RMF, ISO/IEC 42001 |

## 3. Arquitectura y superficie de ataque

Diagrama de flujo con límites de confianza y una tabla de zonas con su exposición.

## 4. Hallazgos

Un bloque por hallazgo, ordenados por riesgo.

### H-01 · {{Título del hallazgo}}

| | |
|---|---|
| **Severidad** | Crítica / Alta / Media / Baja |
| **Categoría** | LLM0X — nombre / ATLAS técnica |
| **Componente** | |
| **Explotable hoy** | Sí / No / Requiere precondición |

**Descripción.** Qué está mal, en términos concretos y verificables.

**Evidencia.** Referencia al log, a la configuración, al fragmento de código o al resultado de la prueba.

**Escenario de explotación.** Quién, con qué acceso, en qué pasos, con qué resultado. Concreto.

**Impacto.** En confidencialidad, integridad y disponibilidad. Cuántas personas o registros.

**Implicancia normativa.** Qué obligación chilena se activa o se incumple, si alguna.

**Recomendación.** Acción específica, control del catálogo que la cubre, esfuerzo estimado.

| Responsable | Plazo propuesto |
|---|---|
| | |

---

## 5. Brechas de control

| ID | Control | Estado | Riesgo residual | Prioridad |
|---|---|---|---|---|
| | | ausente / parcial | | |

## 6. Obligaciones normativas aplicables

| Norma | Obligación concreta | Estado actual | Responsable | Plazo |
|---|---|---|---|---|
| Ley 21.663 | | cumple / brecha / n/a | | |
| Ley 21.719 (01-12-2026) | | | | |
| Proyecto ley IA (anticipación) | | | | |

## 7. Plan de remediación

Ordenado por riesgo × esfuerzo, no por severidad nominal.

| # | Acción | Hallazgos que cierra | Esfuerzo | Responsable | Plazo | Estado |
|---|---|---|---|---|---|---|
| 1 | | | | | | |

**Antes del próximo despliegue:**
**Dentro de 30 días:**
**Dentro del trimestre:**
**Backlog con fecha:**

## 8. Lo que está bien

Controles efectivos ya implementados. No es cortesía: evita que se desmonten en una refactorización.

## 9. Reevaluación

Este análisis caduca si cambia el modelo, la arquitectura, el conjunto de herramientas, el tipo de datos
o el universo de usuarios. Próxima revisión programada: ______.

---

*Documento técnico. No constituye asesoría legal. Datos normativos con fecha de corte {{MES-AÑO}}.*
