# Respuesta a incidentes en sistemas de IA

Carga este archivo cuando hay un incidente activo o cuando se diseña el plan de respuesta.

> **Si el incidente está ocurriendo ahora y la organización es OIV o presta un servicio esencial:
> el plazo de alerta temprana a la ANCI es de 3 horas desde el conocimiento del incidente.**
> Redacta primero la alerta con lo que sabes (`assets/plantilla-reporte-anci.md`) y sigue investigando
> en paralelo. Reportar con información incompleta está previsto; reportar tarde no.

---

## Los tres relojes

Un mismo incidente puede activar obligaciones distintas ante destinatarios distintos, **en paralelo**:

| Reloj | Se activa cuando | Destinatario | Plazo |
|---|---|---|---|
| **Ley 21.663** | Incidente con efectos significativos y la organización es OIV, servicio esencial u organismo del Estado | ANCI / CSIRT Nacional | 3 h → 72 h (24 h si OIV con servicio afectado) → 15 días |
| **Ley 21.719** (desde 01-12-2026) | Brecha de seguridad que afecta datos personales | Agencia de Protección de Datos + titulares afectados | Sin dilaciones indebidas; fija SLA interno de 72 h |
| **Contractual** | Lo diga el contrato con clientes, proveedores o aseguradora | Contraparte | Según contrato, a veces 24 h |

Un cuarto camino, opcional pero relevante: **denuncia penal** bajo la Ley 21.459. Requiere preservar
evidencia con cadena de custodia desde el primer momento.

---

## Escenarios de incidente propios de IA

### 1. Prompt injection indirecta con efecto real
**Señales**: acciones no solicitadas por el usuario, tool calls anómalos, salidas que citan documentos
fuera del alcance de la consulta, peticiones salientes a dominios desconocidos.
**Contención inmediata**: deshabilitar las herramientas con efecto externo; poner el sistema en modo
solo-lectura; **no** parchear el prompt de sistema como única medida.
**Investigación**: identificar el documento o la fuente que contenía la instrucción, cuándo entró al
índice y quién lo subió. Determinar todas las sesiones que lo recuperaron.
**Alcance del daño**: cada sesión que recuperó el documento envenenado es una potencial víctima.

### 2. Fuga de datos vía el modelo
**Señales**: usuarios reportan ver información de terceros; logs muestran documentos recuperados fuera
del ámbito del usuario; respuestas con PII no esperada.
**Contención**: cortar el acceso al sistema afectado, no solo al usuario que reportó.
**Punto crítico**: verificar si el filtro de autorización estaba en la recuperación o solo en el prompt.
Si estaba solo en el prompt, asume que la exposición es amplia y no puntual.
**Alcance**: reconstruir desde los logs qué documentos se recuperaron para qué usuarios y en qué ventana.
Sin logs de recuperación, el alcance es indeterminable — dilo así en el informe, no lo minimices.
**Activa el reloj de datos personales.**

### 3. Envenenamiento del índice o del dataset
**Señales**: cambio de comportamiento sin cambio de código o de modelo; sesgo consistente hacia una
fuente; respuestas que promueven una acción específica.
**Contención**: congelar la indexación; revertir el índice a un snapshot previo verificado.
**Investigación**: diferencia entre snapshots; revisar qué se indexó desde la última versión buena conocida.
**Prevención de recurrencia**: requiere control R-03 y R-04, no un filtro de salida.

### 4. Abuso de herramientas / confused deputy
**Señales**: acciones ejecutadas con permisos superiores a los del solicitante; registros de la API con
identidad de servicio en operaciones que debieron ser de usuario.
**Contención**: revocar credenciales de la herramienta afectada, no solo del agente.
**Investigación**: enumerar todas las acciones ejecutadas por esa identidad en la ventana comprometida.
Es un incidente de escalamiento de privilegios, trátalo como tal.

### 5. Denial of Wallet / consumo desmedido
**Señales**: picos de costo o de tokens, latencia degradada, cuota del proveedor agotada.
**Contención**: cuotas de emergencia, rate limiting, degradar a modelo más barato antes de caer.
**Nota**: si degrada la disponibilidad de un servicio esencial, es reportable bajo la 21.663.

### 6. Compromiso de la cadena de suministro del modelo
**Señales**: cambio de comportamiento tras una actualización del proveedor; alerta del proveedor; hash
de pesos que no coincide.
**Contención**: volver a la versión fijada conocida; si es un proveedor SaaS, activar el plan de salida.
**Obligación adicional**: notificar a clientes río abajo si su servicio depende del componente afectado.

---

## Ciclo de respuesta

### Fase 0 — Detección y triaje (minutos 0-30)
1. Registrar **hora exacta de conocimiento**. Es el punto desde el que corren los plazos legales.
2. Determinar si hay datos personales involucrados y si la organización es OIV o servicio esencial.
3. Activar al Delegado de Ciberseguridad y, si aplica, al responsable de datos personales.
4. Preservar evidencia **antes** de contener: logs de prompts, contexto recuperado, tool calls, salidas,
   snapshot del índice, versión del modelo y del prompt de sistema.

### Fase 1 — Contención (0-3 h, en paralelo con la alerta temprana)
- Cortar la capacidad de acción antes que la capacidad de conversar: deshabilitar herramientas con efecto
  externo suele ser menos disruptivo y más efectivo que apagar el sistema.
- Aislar el índice o la fuente comprometida.
- Rotar credenciales expuestas al contexto del modelo.
- **Enviar alerta temprana a la ANCI si aplica.**

### Fase 2 — Erradicación (horas-días)
- Eliminar el contenido malicioso del índice y de la memoria persistente.
- Corregir el control que falló, no solo su síntoma. Un prompt reforzado no erradica LLM01.
- Revertir a versiones verificadas de modelo, prompt y datos.
- **Reporte de actualización a las 72 h (24 h si OIV con servicio esencial afectado).**

### Fase 3 — Recuperación (días)
- Restablecer herramientas de forma gradual, empezando por las de solo lectura.
- Monitoreo reforzado durante al menos un ciclo completo de uso.
- Validar con pruebas de regresión que el vector está cerrado.

### Fase 4 — Lecciones y cierre (hasta 15 días)
- **Informe final a la ANCI dentro de 15 días corridos** desde la alerta temprana; informes parciales cada
  15 días si el incidente sigue activo.
- Análisis de causa raíz orientado al control ausente, no a la persona.
- Actualizar el modelo de amenazas y el catálogo de controles del sistema.
- Incorporar el escenario a las pruebas adversarias periódicas.

---

## Evidencia mínima a preservar

Sin estos elementos, un incidente de IA no es investigable ni reportable con precisión:

- [ ] Prompts de entrada y respuestas completas, con identificador de usuario y sesión
- [ ] Documentos recuperados por consulta (IDs, no solo el texto)
- [ ] Tool calls: qué herramienta, con qué parámetros, con qué identidad, con qué resultado
- [ ] Versión del modelo, del prompt de sistema y de la configuración en el momento del incidente
- [ ] Snapshot del índice vectorial y su log de indexación
- [ ] Logs de la infraestructura y de las APIs invocadas
- [ ] Registro de acciones del equipo de respuesta con marca de tiempo (cadena de custodia)

**Diseña esto antes del incidente.** La retención debe cubrir el plazo de investigación sin violar el
principio de minimización de la 21.719: define retención por finalidad y protege los logs con control de
acceso auditado (control G-04).

---

## Preparación: ejercicio recomendado

Una vez al año, tabletop de 90 minutos con el escenario 2 (fuga de datos vía el modelo):

1. 00:00 — Un cliente reporta haber visto datos de otro cliente en una respuesta del asistente.
2. Cronometrar: ¿en cuánto tiempo el equipo determina el alcance con los logs que existen hoy?
3. ¿Se logra redactar la alerta temprana antes de los 180 minutos?
4. ¿Quién decide notificar a los titulares afectados y con qué criterio?
5. Documentar los tres huecos más grandes y convertirlos en controles con dueño y fecha.
