# Evaluación de proveedores de IA

Carga este archivo cuando el sistema evaluado es de un tercero o cuando se está decidiendo una contratación.

La mayoría de las organizaciones chilenas no entrena modelos: consume APIs, SaaS con IA embebida o
plataformas de agentes. El riesgo se hereda del proveedor, pero **la responsabilidad legal no se
transfiere**: ante la ANCI responde el operador, y ante la Agencia de Protección de Datos responde el
responsable del tratamiento.

---

## Cuestionario de due diligence

Agrupado por lo que realmente cambia una decisión. Si el proveedor no responde algo por escrito, trátalo
como respuesta negativa.

### A. Tratamiento de datos
1. ¿Los datos enviados por la API se usan para entrenar o mejorar modelos? ¿Por defecto o por opt-in?
2. ¿Cuál es la retención de prompts y respuestas? ¿Existe opción de retención cero?
3. ¿En qué países se procesan y almacenan los datos? ¿Hay opción de residencia regional?
4. ¿Qué subencargados intervienen y cómo se notifican los cambios?
5. ¿Existe procedimiento documentado de borrado a solicitud, y en qué plazo se cumple?
6. ¿El proveedor firma un contrato de encargado de tratamiento compatible con la Ley 21.719?

### B. Seguridad del servicio
7. ¿Certificaciones vigentes? (ISO 27001, SOC 2 Tipo II, ISO 42001). Pedir el reporte, no el logo.
8. ¿Cifrado en tránsito y en reposo? ¿Gestión de claves?
9. ¿Aislamiento entre clientes en inferencia, en fine-tuning y en almacenamiento?
10. ¿Autenticación robusta, gestión de API keys, rotación y revocación?
11. ¿Registro de auditoría disponible para el cliente? ¿Exportable?
12. ¿Resultados de pruebas de penetración o red teaming de IA? ¿Fecha del último ejercicio?

### C. Incidentes
13. ¿En qué plazo notifica el proveedor un incidente de seguridad al cliente?
    **Debe ser compatible con las 3 horas de la Ley 21.663.** Si el proveedor promete 72 horas y la
    organización es OIV, hay un hueco contractual que debe cerrarse o compensarse con detección propia.
14. ¿Qué información entrega en la notificación? ¿Hay contacto y canal definido 24/7?
15. ¿Historial público de incidentes y postmortems?

### D. Modelo y comportamiento
16. ¿Qué modelo se usa exactamente y cómo se versiona? ¿Se puede fijar una versión?
17. ¿Con cuánta anticipación se avisan los cambios o la depreciación de un modelo?
18. ¿Qué evaluaciones de seguridad y sesgo publica? ¿Sobre qué población?
19. ¿Qué mecanismos de filtrado aplica y son configurables?
20. ¿Qué documentación entrega — model card, limitaciones conocidas, casos de uso desaconsejados?

### E. Continuidad y salida
21. SLA de disponibilidad y su compensación real.
22. Límites de cuota y comportamiento ante saturación.
23. ¿Cómo se exportan los datos, los índices y las configuraciones al terminar?
24. ¿Existe alternativa técnica equivalente? ¿Cuánto cuesta migrar?

### F. Cumplimiento chileno
25. ¿Acepta jurisdicción o mecanismos compatibles con la normativa chilena?
26. ¿Colabora con requerimientos de la ANCI o de la Agencia de Protección de Datos?
27. ¿Puede acreditar transferencia internacional de datos con garantías adecuadas?

---

## Semáforo de decisión

| Señal | Lectura |
|---|---|
| Usa datos del cliente para entrenar por defecto, sin opt-out | **Rojo** — incompatible con datos personales o confidenciales |
| No entrega notificación de incidentes en menos de 24 h | **Rojo** para OIV; ámbar para el resto |
| Sin certificación ni reporte de auditoría independiente | **Ámbar** — exigir evidencia alternativa y compensar con controles propios |
| No permite fijar versión del modelo | **Ámbar** — riesgo de cambio de comportamiento sin aviso |
| Sin logs exportables por el cliente | **Ámbar** — compromete la capacidad de reportar y de investigar |
| Retención cero + residencia configurable + SOC 2 + notificación 24 h | **Verde** |

---

## Cláusulas mínimas en el contrato

Redáctalas con abogado; esta es la lista de temas que no pueden faltar.

1. **Finalidad y prohibición de uso secundario** de los datos del cliente, incluido el entrenamiento.
2. **Encargado de tratamiento**: obligaciones de seguridad, confidencialidad, instrucciones documentadas,
   régimen de subencargados con derecho de objeción.
3. **Notificación de incidentes** con plazo expreso en horas, canal y contenido mínimo, alineado con la
   cadencia 3 h / 72 h / 15 días de la Ley 21.663.
4. **Cooperación regulatoria**: obligación de asistir en requerimientos de la ANCI y de la APDP, y en el
   ejercicio de derechos ARCOP de los titulares.
5. **Auditoría**: derecho a auditar o a recibir reportes de auditoría independiente con periodicidad.
6. **Localización y transferencia internacional** con garantías.
7. **Borrado certificado** al término, con plazo y evidencia.
8. **Control de cambios de modelo**: aviso previo, ventana de compatibilidad, derecho a fijar versión.
9. **Continuidad y salida**: SLA, exportación de datos e índices en formato reutilizable.
10. **Responsabilidad e indemnidad** por incumplimientos de seguridad y de protección de datos.

---

## Controles propios que no se delegan

Aunque el proveedor sea impecable, estos controles son del operador y ningún contrato los cubre:

- Qué datos se envían al proveedor (minimización en el origen).
- Qué se indexa en el RAG y quién puede subir contenido.
- Los permisos de las herramientas que el agente puede invocar.
- La validación de la salida antes de usarla río abajo.
- El logging propio: nunca dependas solo de los logs del proveedor para cumplir un plazo legal.
- La supervisión humana en decisiones con efecto sobre personas.

---

## Ficha de evaluación

```
Proveedor:
Servicio / modelo:
Fecha de evaluación:            Evaluador:
Datos que se le envían:         [ ] públicos [ ] internos [ ] personales [ ] sensibles
Rol bajo Ley 21.719:            [ ] encargado [ ] responsable conjunto [ ] n/a
Certificaciones verificadas:
Plazo contractual de notificación de incidentes:
Compatible con obligación ANCI del operador:  [ ] sí [ ] no [ ] n/a
Semáforo:                       [ ] verde [ ] ámbar [ ] rojo
Controles compensatorios requeridos:
Decisión:                       [ ] aprobar [ ] aprobar con condiciones [ ] rechazar
Reevaluación:                   ___ / ___ / ______
```
