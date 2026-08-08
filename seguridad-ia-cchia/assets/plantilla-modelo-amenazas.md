# Modelo de amenazas — {{NOMBRE DEL SISTEMA}}

| Campo | Valor |
|---|---|
| Sistema | |
| Versión / fecha de análisis | |
| Analista | |
| Dueño técnico / dueño de producto | |
| Nivel de riesgo (paso 2) | inaceptable / alto / limitado / mínimo |
| Organización es OIV o servicio esencial | sí / no |
| Trata datos personales | no / sí / sí, sensibles |

## 1. Descripción del sistema

Qué hace, para quién, y qué decide o ejecuta. Tres párrafos como máximo.

## 2. Flujo de datos y límites de confianza

```
[usuario] --(1)--> [aplicación] --(2)--> [prompt] --(3)--> [modelo]
                          |                                   |
                          +--(4)--> [índice RAG]              +--(5)--> [herramientas]
                                                              |
                                        [consumidor] <--(7)-- +--(6)--> [salida]
```

Reemplaza el diagrama por el real. Para cada arista indica: qué datos viajan, quién puede escribir en
ellos y si cruza un límite de confianza.

| # | Origen → destino | Datos | Quién puede escribir | ¿Límite de confianza? |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |

## 3. Activos a proteger

| Activo | Tipo | Confidencialidad | Integridad | Disponibilidad |
|---|---|---|---|---|
| | datos / modelo / servicio / reputación | alta/media/baja | | |

## 4. Actores de amenaza

| Actor | Motivación | Capacidad | Acceso disponible |
|---|---|---|---|
| Usuario legítimo curioso | | baja | cuenta válida |
| Usuario malicioso autenticado | | media | cuenta válida |
| Externo no autenticado | | | |
| Insider | | | |
| Proveedor comprometido | | | cadena de suministro |

## 5. Amenazas identificadas

Una fila por amenaza. **Explotabilidad** se evalúa en esta arquitectura, hoy — no en abstracto.

| ID | Amenaza | OWASP LLM / ATLAS | Vector concreto | Precondición | Impacto (C/I/D) | Explotabilidad | Control existente | Riesgo residual |
|---|---|---|---|---|---|---|---|---|
| T-01 | | LLM01 | | | | alta/media/baja | | crítico/alto/medio/bajo |
| T-02 | | | | | | | | |

## 6. Amenazas descartadas y por qué

Documentar lo descartado evita rediscutirlo y muestra el alcance real del análisis.

| Amenaza | Razón del descarte |
|---|---|
| | |

## 7. Brechas de control priorizadas

| Prioridad | Control ausente (ID del catálogo) | Amenaza que mitiga | Esfuerzo | Responsable | Plazo |
|---|---|---|---|---|---|
| 1 | | | S / M / L | | |

## 8. Supuestos y límites del análisis

- Qué no se revisó y por qué.
- Qué información no estuvo disponible.
- Qué habría que reevaluar si cambia (modelo, arquitectura, tipo de datos, alcance de usuarios).
