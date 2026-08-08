# Catálogo de controles y mapeo a estándares

Referencia para el paso 5 del flujo. Los controles están agrupados por zona de la arquitectura y
priorizados por nivel de riesgo del sistema.

**Cómo usarlo**: toma la columna del nivel de riesgo del sistema (paso 2) y evalúa solo los controles
marcados. Registra cada uno como `implementado` / `parcial` / `ausente` y anota el riesgo residual.

Leyenda: ● obligatorio · ○ recomendado · – no exigible a este nivel

---

## Zona 1-2 · Entrada y prompt

| ID | Control | Mín | Lim | Alto |
|---|---|:--:|:--:|:--:|
| E-01 | Autenticación de usuario y atribución de cada solicitud a una identidad | ○ | ● | ● |
| E-02 | Separación estructural entre instrucciones y datos (mensajes/roles distintos, delimitadores, nunca concatenación cruda) | ● | ● | ● |
| E-03 | Límites de tamaño de entrada y de archivos adjuntos | ● | ● | ● |
| E-04 | Normalización de entrada: quitar caracteres invisibles, Unicode tags, texto oculto en documentos e imágenes | – | ○ | ● |
| E-05 | Sin secretos, endpoints internos ni lógica de autorización en el prompt de sistema | ● | ● | ● |
| E-06 | Detección de patrones de inyección como señal de monitoreo (nunca como control único) | – | ○ | ● |

## Zona 3 · Recuperación y RAG

| ID | Control | Mín | Lim | Alto |
|---|---|:--:|:--:|:--:|
| R-01 | **Autorización aplicada en la recuperación**: filtrar documentos por permisos del usuario antes de construir el contexto | ● | ● | ● |
| R-02 | Partición del índice vectorial por tenant y por dominio de datos | ○ | ● | ● |
| R-03 | Procedencia registrada por documento: quién lo subió, cuándo, desde qué fuente | ○ | ● | ● |
| R-04 | Revisión o cuarentena del contenido subido por usuarios antes de indexarlo | – | ○ | ● |
| R-05 | Cifrado en reposo y control de acceso del almacén vectorial | ● | ● | ● |
| R-06 | Procedimiento verificado de borrado de un documento del índice (soporte a derechos ARCOP) | ○ | ● | ● |
| R-07 | Marcado del contenido recuperado como datos no confiables en el contexto | – | ○ | ● |

## Zona 4 · Modelo y cadena de suministro

| ID | Control | Mín | Lim | Alto |
|---|---|:--:|:--:|:--:|
| M-01 | Inventario de modelos con versión, proveedor, licencia y fecha de incorporación | ● | ● | ● |
| M-02 | Verificación de integridad y procedencia de pesos y adaptadores descargados | ○ | ● | ● |
| M-03 | Prohibición de formatos de serialización que ejecutan código al cargar | ● | ● | ● |
| M-04 | Fijación de versión del modelo en producción; cambios pasan por pruebas de regresión | ○ | ● | ● |
| M-05 | Evaluación documentada del proveedor (ver `evaluacion-proveedores.md`) | ○ | ● | ● |
| M-06 | Plan de salida: cómo migrar si el proveedor cambia términos, precio o disponibilidad | – | ○ | ● |
| M-07 | Procedencia y versionado de datasets de entrenamiento y fine-tuning | – | ○ | ● |

## Zona 5 · Herramientas y agencia

| ID | Control | Mín | Lim | Alto |
|---|---|:--:|:--:|:--:|
| H-01 | Inventario de herramientas invocables con su alcance de permisos | ● | ● | ● |
| H-02 | Mínimo privilegio por herramienta; identidad propia por herramienta, no cuenta de servicio compartida | ● | ● | ● |
| H-03 | Propagación de la identidad del usuario a la herramienta (evita el *confused deputy*) | ○ | ● | ● |
| H-04 | Lista explícita de acciones irreversibles o de efecto externo que exigen confirmación humana | ○ | ● | ● |
| H-05 | Límite de pasos, profundidad de bucle y presupuesto por tarea | ● | ● | ● |
| H-06 | Allowlist de dominios para peticiones salientes y para renderizado de recursos remotos | ○ | ● | ● |
| H-07 | Sandbox para ejecución de código generado, sin credenciales ni red por defecto | ● | ● | ● |
| H-08 | Idempotencia en herramientas con efecto externo | – | ○ | ● |

## Zona 6-7 · Salida y consumo

| ID | Control | Mín | Lim | Alto |
|---|---|:--:|:--:|:--:|
| S-01 | Escape y validación de la salida según destino (HTML, SQL, shell, JSON, plantillas) | ● | ● | ● |
| S-02 | Prohibición de `eval`, ejecución directa y consultas construidas por concatenación con salida del modelo | ● | ● | ● |
| S-03 | Bloqueo de renderizado de imágenes y recursos remotos con URL controlada por el modelo | ○ | ● | ● |
| S-04 | Validación de esquema en salidas estructuradas antes de usarlas | ● | ● | ● |
| S-05 | Etiquetado visible de contenido generado por IA en interfaces con personas | ○ | ● | ● |
| S-06 | Citas verificables a las fuentes recuperadas en respuestas informativas | – | ○ | ● |

## Transversal · Gobernanza, observabilidad y respuesta

| ID | Control | Mín | Lim | Alto |
|---|---|:--:|:--:|:--:|
| G-01 | Sistema registrado en el inventario de IA con caso de uso y nivel de riesgo | ● | ● | ● |
| G-02 | Responsable identificado (dueño de producto y dueño técnico) | ● | ● | ● |
| G-03 | Logging de prompt, contexto recuperado, tool calls, salida y decisión, con retención definida | ○ | ● | ● |
| G-04 | Los logs no almacenan datos sensibles innecesarios ni secretos; acceso restringido y auditado | ● | ● | ● |
| G-05 | Cuotas y alertas de costo y consumo por usuario y por sesión | ● | ● | ● |
| G-06 | Evaluación de impacto (seguridad + datos personales) antes del despliegue | – | ○ | ● |
| G-07 | Pruebas adversarias periódicas (red teaming de IA) con alcance autorizado por escrito | – | ○ | ● |
| G-08 | Pruebas de regresión de seguridad en cada cambio de modelo, prompt o herramienta | – | ○ | ● |
| G-09 | Plan de respuesta a incidentes que incluye escenarios de IA y los plazos ANCI | ○ | ● | ● |
| G-10 | Supervisión humana definida y documentada en usos con efecto sobre personas | – | ○ | ● |
| G-11 | Canal para que usuarios reporten salidas dañinas o incorrectas | – | ○ | ● |
| G-12 | Documentación técnica del sistema: datos, evaluaciones, limitaciones conocidas | – | ○ | ● |

Los sistemas de **riesgo inaceptable** no se controlan: no se despliegan.

---

## Mapeo a estándares y normativa

Usa esta tabla para responder "¿contra qué estándar está esto?" sin duplicar trabajo de auditoría.

Las columnas ISO contienen únicamente identificadores de cláusulas o familias. Los nombres y requisitos oficiales no
se reproducen: deben consultarse en una copia licenciada de cada estándar. La relación con los grupos CCHIA expresa un
racional de alto nivel y no demuestra por sí sola conformidad.

| Grupo de controles | NIST AI RMF 1.0 | ISO/IEC 42001 | ISO/IEC 27001:2022 | Normativa CL |
|---|---|---|---|---|
| E-01…E-06 Entrada y prompt | MANAGE 2.2 | Anexo A, familia A.6 | Anexo A, A.8.26 | 21.663 gestión de riesgos |
| R-01…R-07 RAG y datos | MAP 2.3, MEASURE 2.10 | Anexo A, familia A.7 | Anexo A, A.5.12 y A.8.3 | 21.719 finalidad, minimización, ARCOP |
| M-01…M-07 Cadena de suministro | GOVERN 6.1, MAP 4.1 | Anexo A, familia A.10 | Anexo A, A.5.19–A.5.23 | 21.663 cadena de suministro |
| H-01…H-08 Herramientas y agencia | MANAGE 2.3, GOVERN 1.5 | Anexo A, A.6.2 | Anexo A, A.8.2 y A.8.31 | 21.595 modelo de prevención |
| S-01…S-06 Salida | MEASURE 2.5 | Anexo A, A.6.2.4 | Anexo A, A.8.28 | Proyecto ley IA: transparencia |
| G-01…G-05 Gobernanza y logs | GOVERN 1, MAP 1.1 | Anexo A, familias A.2 y A.4 | Anexo A, A.5.9 y A.8.15 | 21.663 SGSI; 21.719 trazabilidad |
| G-06…G-08 Evaluación y pruebas | MEASURE 1–4 | Anexo A, familia A.5 | Anexo A, A.8.29 | 21.719 EIPD |
| G-09 Respuesta a incidentes | MANAGE 4.1 | Anexo A, A.9.4 | Anexo A, A.5.24–A.5.28 | 21.663 art. 9 + DS 295/2024 |
| G-10…G-12 Supervisión y transparencia | GOVERN 5, MANAGE 4.3 | Anexo A, familia A.9 | — | Proyecto ley IA: alto riesgo |

### Las cuatro funciones del NIST AI RMF
- **GOVERN** — políticas, roles, cultura, gestión de terceros. Transversal a las otras tres.
- **MAP** — contexto, casos de uso, actores afectados, riesgos identificados.
- **MEASURE** — métricas, evaluación, pruebas, seguimiento de riesgos.
- **MANAGE** — priorización, tratamiento, respuesta y recuperación.

Si la organización ya tiene ISO 27001, **no montes un sistema paralelo**: extiende el SGSI existente con
el inventario de IA, los controles de este catálogo y los escenarios de IA en el plan de incidentes.
ISO/IEC 42001 se integra sobre esa base, no la reemplaza.

---

## Cómo estimar riesgo residual

Para cada brecha de control:

```
Riesgo residual = Probabilidad × Impacto × (1 − Efectividad de controles compensatorios)
```

En la práctica basta una escala de tres niveles, siempre justificada:

- **Probabilidad**: ¿existe un vector explotable hoy, en esta arquitectura, por alguien sin acceso privilegiado?
- **Impacto**: ¿qué se pierde en confidencialidad, integridad y disponibilidad, y a cuántas personas afecta?
- **Compensatorios**: ¿qué otro control detiene o detecta el ataque si este falla?

Traduce el resultado a plazo, no a etiqueta: *crítico = se corrige antes del próximo despliegue*,
*alto = 30 días*, *medio = próximo trimestre*, *bajo = backlog con fecha*.

---

## Fuentes

- [NIST AI Risk Management Framework 1.0](https://www.nist.gov/itl/ai-risk-management-framework)
- [ISO/IEC 42001:2023](https://www.iso.org/standard/81230.html)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [OWASP GenAI Security Project](https://genai.owasp.org/)
