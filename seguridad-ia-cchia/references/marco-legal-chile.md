# Marco legal chileno aplicable a sistemas de IA

**Fecha de corte: agosto 2026.** Orientación técnica, no asesoría legal. Verifica siempre en
[bcn.cl/leychile](https://www.bcn.cl/leychile) y [anci.gob.cl](https://anci.gob.cl) antes de decidir.

---

## Panorama en una tabla

| Norma | Estado | Qué exige respecto de IA | Fiscaliza |
|---|---|---|---|
| **Ley 21.663** — Marco de Ciberseguridad | Vigente (obligaciones y sanciones desde marzo 2025) | Gestión de riesgos, reporte de incidentes, deberes reforzados para OIV | ANCI / CSIRT Nacional |
| **Ley 21.719** — Datos personales | Publicada 13-12-2024, **vigente 01-12-2026** | Base de licitud, finalidad, derechos, decisiones automatizadas, brechas | Agencia de Protección de Datos Personales |
| **Ley 19.628** — Datos personales (antigua) | Vigente hasta que rija la 21.719 | Régimen mínimo actual de tratamiento | — (sin autoridad especializada) |
| **Ley 21.459** — Delitos informáticos | Vigente desde 2022 | Tipifica los ataques; define qué es delito perseguible | Ministerio Público |
| **Ley 21.595** — Delitos económicos | Vigente desde 2024 | Responsabilidad penal de la persona jurídica; modelo de prevención | Ministerio Público |
| **Boletín 16821-19** — Ley de IA | **En tramitación**, segundo trámite en el Senado | Clasificación por riesgo del uso, obligaciones por categoría | (propuesto: APDP) |
| **EU AI Act** | Vigente en la UE | Aplica si se ofrece el sistema o su salida en la UE | Autoridades UE |

---

## 1. Ley 21.663 — Ley Marco de Ciberseguridad

Publicada el 8 de abril de 2024. El grueso de las obligaciones y el régimen sancionatorio operan desde
marzo de 2025. Crea la **Agencia Nacional de Ciberseguridad (ANCI)** y da estatus legal al **CSIRT Nacional**.

### A quién aplica
- **Organismos de la Administración del Estado.**
- **Servicios esenciales** (art. 4): telecomunicaciones, energía, agua, banca y servicios financieros,
  salud, transporte, servicios digitales, entre otros.
- **Operadores de Importancia Vital (OIV)**: calificados por resolución de la ANCI. El primer
  procedimiento cerró en 2026 con ~1.154 instituciones (Resolución 187/2026 aprobó la nómina definitiva
  de la segunda etapa). Consulta la nómina vigente en el sitio de la ANCI antes de asumir el estatus.

### Deberes generales (servicios esenciales y OIV)
1. Gestión continua de riesgos de ciberseguridad.
2. Capacidad de prevención, respuesta y recuperación ante incidentes.
3. **Reporte obligatorio** de incidentes con efectos significativos (art. 9).

### Deberes reforzados solo para OIV
- Implementar y mantener un **Sistema de Gestión de Seguridad de la Información (SGSI)**.
- **Planes de continuidad operacional y de ciberseguridad**, sujetos a certificación.
- **Auditorías, evaluaciones y ejercicios** periódicos.
- Designar un **Delegado de Ciberseguridad** como contraparte formal ante la ANCI.

### Plazos de reporte (art. 9 + Decreto Supremo 295/2024)

| Hito | Plazo | Contenido mínimo |
|---|---|---|
| **Alerta temprana** | **3 horas** desde que se toma conocimiento | Identificación de la institución, datos del delegado, fecha/hora de detección, indicios del incidente, activos comprometidos |
| **Actualización** | **72 horas** desde el conocimiento — **24 horas** si es OIV y el incidente afecta la prestación del servicio esencial | Evaluación inicial, gravedad, impacto, indicadores de compromiso |
| **Informe final** | **15 días corridos** desde la alerta temprana, una vez gestionado el incidente | Descripción detallada, causa raíz, mitigación aplicada, impacto real |
| **Informes parciales** | Cada 15 días mientras el incidente siga activo | Estado y avance |

El plazo corre desde el **conocimiento del incidente**, no desde la comprensión de su causa.
Canal: plataforma de la ANCI / CSIRT Nacional ([csirt.gob.cl](https://www.csirt.gob.cl)).

### Sanciones (órdenes de magnitud, verificar articulado vigente)
| Gravedad | Régimen general | OIV |
|---|---|---|
| Leve | hasta 5.000 UTM | hasta 10.000 UTM |
| Grave | hasta 10.000 UTM | hasta 20.000 UTM |
| Gravísima | hasta 20.000 UTM | hasta 40.000 UTM |

Graduación según daño real o potencial, intencionalidad, reincidencia, cooperación con la autoridad,
capacidad económica y acciones correctivas adoptadas.

### Lectura para sistemas de IA
La ley no menciona IA. Igual aplica: si un chatbot es la puerta de entrada a un servicio esencial, un
incidente en ese chatbot es un incidente reportable. Consecuencias prácticas:

- El sistema de IA debe estar en el **inventario de activos** del SGSI, no fuera de él.
- Los **logs de prompts, contexto recuperado y tool calls** son evidencia necesaria para cumplir el plazo
  de 3 horas. Sin ellos no hay alerta temprana redactable.
- Los **proveedores de IA** son parte de la cadena de suministro: el contrato debe obligarlos a notificar
  incidentes en un plazo compatible con las 3 horas de la organización.
- Un ataque de **Unbounded Consumption** (LLM10) que degrade el servicio puede constituir un incidente con
  efectos significativos en disponibilidad.

---

## 2. Ley 21.719 — Protección de datos personales

Publicada el 13-12-2024, **entra en vigencia el 1 de diciembre de 2026**. Reemplaza a la Ley 19.628 y
crea la **Agencia de Protección de Datos Personales (APDP)**, con potestad fiscalizadora y sancionatoria.

### Lo que más impacta a sistemas de IA

| Obligación | Impacto concreto en IA |
|---|---|
| **Base de licitud** para cada tratamiento | Entrenar, hacer fine-tuning o indexar en un RAG con datos de clientes requiere base legal explícita. El consentimiento para "prestar el servicio" no cubre por defecto entrenar modelos. |
| **Principio de finalidad** | Reutilizar datos recolectados para otro fin en un modelo es un tratamiento nuevo. |
| **Minimización** | Cargar bases completas al contexto o al índice es difícil de justificar. |
| **Datos sensibles** (salud, biométricos, origen, afiliación) | Régimen reforzado. Afecta directamente reconocimiento facial, análisis de voz y casos de uso clínicos. |
| **Derechos ARCOP** (acceso, rectificación, cancelación, oposición, portabilidad) | Debe existir un procedimiento real para borrar datos de un índice vectorial y de datasets de fine-tuning. Diséñalo antes de indexar. |
| **Decisiones automatizadas** | Derecho a oposición y a explicación cuando la decisión produce efectos jurídicos o significativos. Requiere trazabilidad de la decisión, no solo del prompt. |
| **Notificación de brechas** | Notificar a la Agencia por el medio más expedito y sin dilaciones indebidas; comunicar a los titulares cuando la brecha afecte datos sensibles o pueda causar perjuicio. Muchas guías locales operan con un objetivo de 72 horas — fija ese SLA interno. |
| **Encargado de tratamiento** | El proveedor de IA es encargado: exige contrato con obligaciones de seguridad, subencargados y borrado. |
| **Delegado de Protección de Datos** | Exigible en ciertos casos; define quién es antes de diciembre de 2026. |

### Sanciones
Escalonadas por gravedad, con techos del orden de 5.000 / 10.000 / 20.000 UTM, y en reincidencia de
infracciones gravísimas multas asociadas a un porcentaje de los ingresos anuales (hasta 4% según el
régimen aplicable). Existe un Registro Nacional de Sanciones. Verificar el articulado vigente.

### Cruce con seguridad
Una fuga de datos vía LLM02 (Sensitive Information Disclosure) es simultáneamente:
un hallazgo de seguridad, una posible brecha bajo la 21.719, y —si la organización es OIV— un incidente
reportable bajo la 21.663. **Tres relojes distintos con tres destinatarios distintos.** El plan de
respuesta debe contemplarlos en paralelo, no en secuencia.

---

## 3. Ley 21.459 — Delitos informáticos, y Ley 21.595 — Delitos económicos

La Ley 21.459 (adecuación al Convenio de Budapest) tipifica, entre otros: acceso ilícito, interceptación
ilícita, ataque a la integridad de datos y de sistemas informáticos, falsificación informática, fraude
informático, receptación de datos y abuso de dispositivos.

Para IA importan tres lecturas:

1. **Ofensiva**: extraer datos de un sistema de IA ajeno, envenenar su índice o abusar de sus herramientas
   puede configurar delito. Esto acota qué se puede hacer en un ejercicio de red team: **exige autorización
   escrita, alcance definido y ventana temporal** antes de cualquier prueba adversaria sobre sistemas de
   terceros.
2. **Defensiva**: define qué se puede denunciar y qué evidencia se necesita. La cadena de custodia de logs
   de IA importa.
3. **Corporativa**: la Ley 21.595 amplió la responsabilidad penal de la persona jurídica e incorporó
   delitos informáticos al catálogo. Un **modelo de prevención de delitos** que ignora los sistemas de IA
   deja un hueco: las herramientas del agente pueden ser el instrumento del delito.

---

## 4. Proyecto de ley de IA (Boletín 16821-19)

**Estado (agosto 2026): en tramitación.** Ingresó en mayo de 2024; la Cámara de Diputados lo despachó en
octubre de 2025; se encuentra en segundo trámite en el Senado, en la Comisión de Desafíos del Futuro,
Ciencia, Tecnología e Innovación. **No es exigible todavía.** Trátalo como planificación anticipada.

### Enfoque
Regula **usos**, no la tecnología, con un modelo proporcional al riesgo — el mismo esquema conceptual del
EU AI Act, adaptado. Cuatro categorías:

| Categoría | Criterio | Consecuencia esperada |
|---|---|---|
| **Riesgo inaceptable** | Usos prohibidos (manipulación que cause daño, explotación de vulnerabilidades, ciertas formas de categorización biométrica y scoring social) | Prohibición |
| **Alto riesgo** | Usos con efecto significativo en derechos, salud, seguridad, acceso a servicios esenciales, empleo, educación, justicia | Gestión de riesgos, calidad de datos, documentación, supervisión humana, robustez y ciberseguridad, registro |
| **Riesgo limitado** | Interacción con personas, generación de contenido sintético | Deberes de transparencia y etiquetado |
| **Sin riesgo evidente** | El resto | Sin obligaciones específicas |

El texto en tramitación contempla obligaciones diferenciadas para desarrolladores, proveedores,
implementadores y distribuidores, nacionales o extranjeros, que operen en Chile, y radica la fiscalización
en la Agencia de Protección de Datos Personales. **Verifica el texto aprobado antes de citar detalles**:
las categorías y los deberes pueden cambiar en el Senado.

### Qué hacer hoy
Aunque no rija, cuatro medidas no tienen costo hundido y anticipan cualquier versión final:
1. **Inventario de sistemas de IA** con caso de uso y clasificación de riesgo (`assets/registro-sistemas-ia.csv`).
2. **Documentación técnica** por sistema: datos, entrenamiento, evaluaciones, limitaciones conocidas.
3. **Supervisión humana** definida y documentada en los usos con efecto sobre personas.
4. **Etiquetado de contenido sintético** en las interfaces que interactúan con personas.

---

## 5. Regulación sectorial y estándares aplicables

- **Financiero**: normativa de la CMF sobre gestión de riesgo operacional y ciberseguridad; Ley 21.521
  (Fintec) y su reglamentación. Los modelos de scoring caen además en decisiones automatizadas.
- **Salud**: datos sensibles bajo la 21.719 + normativa del Minsal; los sistemas de apoyo diagnóstico
  serían de alto riesgo bajo el proyecto de ley de IA.
- **Sector público**: Ley 21.180 de transformación digital; instructivos presidenciales de ciberseguridad;
  Política Nacional de Inteligencia Artificial.
- **Estándares de referencia**: ISO/IEC 27001, ISO/IEC 42001 (gestión de IA), ISO/IEC 23894 (riesgo en IA),
  NIST AI RMF 1.0 y su perfil de IA generativa, NIST CSF 2.0. Ver `controles-y-mapeo.md`.

---

## 6. Matriz de decisión rápida

Responde estas preguntas para saber qué obligaciones aplican:

| Pregunta | Si es sí |
|---|---|
| ¿La organización figura en la nómina de OIV de la ANCI? | Deberes reforzados 21.663: SGSI, continuidad certificada, delegado, auditorías |
| ¿Presta un servicio esencial del art. 4? | Deberes generales 21.663 + reporte de incidentes |
| ¿El sistema de IA trata datos personales? | 19.628 hoy; 21.719 desde el 01-12-2026 |
| ¿Trata datos sensibles o de niños, niñas y adolescentes? | Régimen reforzado; evaluación de impacto |
| ¿Toma o apoya decisiones con efecto sobre personas? | Decisiones automatizadas: oposición, explicación, supervisión humana |
| ¿Interactúa con personas o genera contenido sintético? | Transparencia y etiquetado (anticipar el proyecto de ley de IA) |
| ¿El proveedor del modelo está fuera de Chile? | Transferencia internacional de datos + contrato de encargado |
| ¿Se ofrece el sistema o su salida en la UE? | EU AI Act además de la normativa chilena |

---

## Fuentes oficiales

- [Agencia Nacional de Ciberseguridad (ANCI)](https://anci.gob.cl)
- [CSIRT Nacional](https://www.csirt.gob.cl)
- [Ley Chile — BCN](https://www.bcn.cl/leychile)
- [Tramitación Boletín 16821-19 — Senado](https://tramitacion.senado.cl/appsenado/templates/tramitacion/index.php?boletin_ini=16821-19)
- [Ministerio de Ciencia — Proyecto de ley que regula sistemas de IA](https://www.minciencia.gob.cl/areas/inteligencia-artificial/)
