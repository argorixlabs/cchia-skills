# Reportes de incidente a la ANCI / CSIRT Nacional

> **Plantilla técnica no oficial.** Este documento no es un formulario de la ANCI ni del CSIRT Nacional y no está
> afiliado, aprobado, patrocinado ni avalado por esas instituciones. Antes de utilizarlo, verifica el alcance, las
> obligaciones, los contenidos, los plazos, el canal y el destinatario en las fuentes oficiales vigentes de la
> [ANCI](https://anci.gob.cl), el [CSIRT Nacional](https://www.csirt.gob.cl) y
> [Ley Chile](https://www.bcn.cl/leychile/).

Plantillas para los tres hitos del art. 9 de la Ley 21.663 y el DS 295/2024.
Enviar por la plataforma oficial de la ANCI / CSIRT Nacional. Conservar copia y acuse.

> **Regla operativa**: el plazo corre desde el **conocimiento** del incidente. Enviar con información
> parcial dentro del plazo es lo esperado; esperar a tener el cuadro completo es incumplir.

| Hito | Plazo | Contador desde |
|---|---|---|
| Alerta temprana | 3 horas | conocimiento del incidente |
| Actualización | 72 horas — **24 horas** si OIV con servicio esencial afectado | conocimiento del incidente |
| Informe final | 15 días corridos | envío de la alerta temprana |
| Informes parciales | cada 15 días mientras siga activo | informe anterior |

---

## 1 · ALERTA TEMPRANA (≤ 3 horas)

```
ASUNTO: Alerta temprana — Incidente de ciberseguridad — [ORGANIZACIÓN] — [ID INTERNO]

1. INSTITUCIÓN
   Razón social:
   RUT:
   Calidad: [ ] OIV  [ ] Servicio esencial  [ ] Organismo del Estado
   Sector:

2. DELEGADO DE CIBERSEGURIDAD
   Nombre:
   Cargo:
   Correo:                          Teléfono (24/7):

3. DETECCIÓN
   Fecha y hora de ocurrencia (estimada):
   Fecha y hora de detección:
   Fecha y hora de conocimiento (inicio del plazo):
   Medio de detección: [ ] monitoreo interno [ ] reporte de usuario [ ] proveedor
                       [ ] tercero externo   [ ] otro: ______

4. DESCRIPCIÓN PRELIMINAR
   Qué se observó, en una o dos frases:

   Tipo preliminar (taxonomía ANCI):

5. ACTIVOS COMPROMETIDOS O EN RIESGO
   Sistemas / servicios:
   Si involucra un sistema de IA: modelo y versión, prompt de sistema, índice/RAG,
   herramientas invocables, proveedor externo.

6. EFECTO SOBRE EL SERVICIO
   [ ] Interrumpido  [ ] Degradado  [ ] Sin efecto observable  [ ] En evaluación
   Alcance estimado (usuarios / clientes / regiones):

7. DATOS PERSONALES
   [ ] Sin indicios  [ ] Posible afectación  [ ] Confirmada
   Si hay afectación: activar en paralelo el procedimiento de la Ley 21.719.

8. MEDIDAS INMEDIATAS ADOPTADAS

9. ESTADO
   [ ] Activo  [ ] Contenido  [ ] En investigación

Enviado por:                        Fecha y hora de envío:
```

---

## 2 · REPORTE DE ACTUALIZACIÓN (≤ 72 h; ≤ 24 h si OIV con servicio esencial afectado)

```
ASUNTO: Actualización — Incidente [ID INTERNO] — [ORGANIZACIÓN]
Referencia a la alerta temprana: [folio / fecha y hora]

1. CONFIRMACIÓN O CORRECCIÓN DE LO REPORTADO
   Cambios respecto de la alerta temprana:

2. EVALUACIÓN DE GRAVEDAD
   Clasificación:
   Justificación:

3. IMPACTO CONSTATADO
   Confidencialidad:
   Integridad:
   Disponibilidad:
   Alcance (usuarios, registros, servicios, ventana temporal):

4. VECTOR Y CAUSA PRESUNTA
   Cómo se produjo, hasta donde se conoce:
   Si es un sistema de IA: vector según OWASP LLM Top 10 y técnica MITRE ATLAS si aplica.

5. INDICADORES DE COMPROMISO (IoC)
   Direcciones IP / dominios / hashes / cuentas / documentos indexados maliciosos:

6. MEDIDAS DE CONTENCIÓN Y MITIGACIÓN APLICADAS
   Acción · Fecha y hora · Resultado

7. ESTADO ACTUAL Y PRÓXIMOS PASOS

8. TERCEROS INVOLUCRADOS
   Proveedores afectados, notificaciones realizadas o recibidas:

9. OTRAS NOTIFICACIONES REALIZADAS
   [ ] Agencia de Protección de Datos  [ ] Titulares  [ ] Clientes
   [ ] Ministerio Público  [ ] Regulador sectorial  [ ] Aseguradora
```

---

## 3 · INFORME FINAL (≤ 15 días corridos desde la alerta temprana)

```
ASUNTO: Informe final — Incidente [ID INTERNO] — [ORGANIZACIÓN]
Referencia: alerta temprana [folio] · actualización [folio]

1. RESUMEN DEL INCIDENTE
   Cronología completa con marcas de tiempo:
   Ocurrencia → detección → conocimiento → contención → erradicación → recuperación

2. CAUSA RAÍZ
   Control ausente o fallido que permitió el incidente:
   Por qué no fue detectado antes:

3. DESCRIPCIÓN TÉCNICA DETALLADA
   Vector, cadena de ataque, activos alcanzados:

4. IMPACTO FINAL
   Datos afectados (tipo, volumen, sensibilidad):
   Servicios afectados y duración:
   Personas afectadas y notificaciones realizadas:
   Impacto económico estimado:

5. MEDIDAS DE ERRADICACIÓN Y RECUPERACIÓN

6. MEDIDAS PARA EVITAR RECURRENCIA
   Control · Estado · Responsable · Fecha comprometida

7. LECCIONES APRENDIDAS

8. EVIDENCIA CONSERVADA Y RETENCIÓN

Delegado de Ciberseguridad:                   Fecha:
```

> Si al día 15 el incidente sigue activo, enviar **informe parcial** con esta misma estructura marcada
> como parcial, y repetir cada 15 días hasta la resolución.

---

## Anexo · Datos específicos a recolectar en incidentes de IA

Para que estos reportes sean redactables en plazo, el equipo debe poder extraer en minutos:

- Ventana temporal del incidente y sesiones involucradas.
- Prompts y respuestas de las sesiones afectadas, con identificador de usuario.
- Documentos recuperados por consulta (IDs y origen).
- Tool calls ejecutados: herramienta, parámetros, identidad, resultado.
- Versión del modelo, del prompt de sistema y de la configuración vigente.
- Log de indexación: qué entró al índice, cuándo y quién lo subió.
- Confirmación de si el proveedor externo notificó o fue notificado.

Si alguno de estos datos no existe, decláralo en el reporte como limitación de la investigación en lugar
de estimar. Y conviértelo en un control con dueño y plazo en el informe final.
