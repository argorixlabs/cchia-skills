# Amenazas en sistemas de IA

Referencia para los pasos 3 (superficie de ataque) y 4 (modelo de amenazas) del flujo de la skill.

---

## Mapa de superficie

Todo sistema de IA moderno se descompone en las mismas siete zonas. Analiza cada una preguntando
**quién puede escribir aquí** y **qué confía en esto río abajo**.

| # | Zona | Entradas no confiables típicas | Pregunta clave |
|---|---|---|---|
| 1 | Entrada de usuario | Prompt directo, archivos subidos, imágenes, audio | ¿Hay autenticación y atribución por usuario? |
| 2 | Prompt de sistema / plantilla | Variables interpoladas, historial, metadatos de sesión | ¿Se concatenan datos de usuario sin delimitar? |
| 3 | Recuperación / RAG | Documentos indexados, páginas web, correos, tickets, repos | ¿Quién puede insertar contenido en el índice? |
| 4 | Modelo | Pesos, fine-tuning, adaptadores, proveedor externo | ¿De dónde viene el modelo y quién lo actualiza? |
| 5 | Herramientas / tool calling | Respuestas de APIs, resultados de búsqueda, salidas de scripts | ¿Con qué identidad y permisos ejecuta cada tool? |
| 6 | Salida | Texto, HTML, Markdown, SQL, código, JSON | ¿Se renderiza, ejecuta o interpola en otro sistema? |
| 7 | Consumidor | Usuario final, otro servicio, otro agente | ¿Alguien toma decisiones automáticas con esto? |

**Regla de oro**: el límite de confianza va entre la zona 5 y la 6. Todo lo que sale del modelo se trata
como entrada no confiable, igual que un parámetro HTTP.

### Cadenas de agentes
En sistemas multiagente, la salida de un agente es la entrada de otro. Cada salto multiplica la superficie:
una inyección en el agente A se propaga al agente B con los permisos de B. Modela cada salto como un
límite de confianza independiente y documenta el conjunto de permisos efectivos de la cadena completa —
suele ser mayor que el de cualquier agente individual.

---

## OWASP Top 10 for LLM Applications 2025

Publicado por el OWASP GenAI Security Project (18-11-2024). Para cada riesgo: qué es, cómo se ve en la
práctica y qué controlar.

### LLM01 — Prompt Injection
Instrucciones del atacante que alteran el comportamiento del modelo.
- **Directa**: el usuario escribe la instrucción maliciosa ("ignora las instrucciones anteriores").
- **Indirecta**: la instrucción viene en contenido que el modelo lee — un PDF del RAG, una página web, un
  correo, el README de un repo. Es la variante peligrosa: la víctima no es quien inyecta.
- **Multimodal**: texto oculto en imágenes, metadatos, o caracteres invisibles (Unicode tags, texto blanco).
- **Controles**: separación estructural de instrucciones y datos; mínimo privilegio en las herramientas;
  confirmación humana para acciones irreversibles; no confiar en instrucciones defensivas en el prompt.

### LLM02 — Sensitive Information Disclosure
El modelo revela datos que no debía: PII de otros usuarios, secretos, contenido de documentos internos.
- Vectores: contexto sobrecargado, RAG sin filtro de autorización por usuario, memoria compartida entre
  sesiones, logs con prompts completos, datos sensibles en fine-tuning.
- **Control central**: la autorización se aplica **en la recuperación**, no en el prompt. Filtra los
  documentos por permisos del usuario antes de que entren al contexto.
- En Chile esto es una brecha de datos personales bajo la Ley 21.719. Ver `marco-legal-chile.md`.

### LLM03 — Supply Chain
Riesgo heredado de modelos, datasets, adaptadores LoRA, librerías y plugins de terceros.
- Modelos descargados de repositorios públicos sin verificación de integridad.
- Formatos de serialización que ejecutan código al cargarse (pickle); preferir formatos seguros.
- Dependencia de un proveedor de API: cambios de modelo sin aviso alteran el comportamiento en producción.
- **Controles**: SBOM/AIBOM, fijar versiones y hashes, evaluar licencias y procedencia, plan de salida.

### LLM04 — Data and Model Poisoning
Manipulación de datos de entrenamiento, fine-tuning o embeddings para inducir comportamiento o backdoors.
- Aplica también al RAG: envenenar el índice es más barato que envenenar el entrenamiento.
- **Controles**: procedencia y versionado de datasets, revisión de fuentes que alimentan el índice,
  detección de anomalías en la distribución, pruebas de regresión de comportamiento en cada actualización.

### LLM05 — Improper Output Handling
La salida del modelo se usa sin validar en un sistema río abajo.
- Markdown/HTML renderizado → XSS; imagen remota con datos en la URL → exfiltración silenciosa.
- SQL generado y ejecutado → inyección; comandos de shell → RCE; JSON malformado → corrupción de estado.
- **Control**: validación y escape según el destino, exactamente como con cualquier entrada de usuario.
  Nunca `eval`, nunca query construida por concatenación, nunca renderizar HTML crudo del modelo.

### LLM06 — Excessive Agency
El sistema puede hacer más de lo necesario: demasiadas herramientas, demasiados permisos, demasiada
autonomía.
- Tres dimensiones a recortar: **funcionalidad** (menos tools), **permisos** (scope mínimo por tool),
  **autonomía** (aprobación humana en acciones con efecto externo o irreversible).
- Cada tool necesita su propia identidad y su propio registro de auditoría.

### LLM07 — System Prompt Leakage
Fuga del prompt de sistema. El daño real no es la fuga sino lo que el prompt contenía: credenciales,
endpoints internos, reglas de negocio, lógica de autorización.
- **Control**: asume que el prompt es público. Ningún secreto ni control de acceso vive ahí.

### LLM08 — Vector and Embedding Weaknesses
Debilidades específicas de RAG y bases vectoriales.
- Inversión de embeddings: recuperar texto original desde vectores almacenados.
- Cross-tenant leakage: un índice compartido sin partición por cliente o por usuario.
- Colisiones semánticas y envenenamiento del índice para forzar la recuperación de un documento hostil.
- **Controles**: partición por tenant, cifrado y control de acceso del almacén vectorial, filtrado de
  metadatos previo a la recuperación, auditoría de qué se indexó y quién lo subió.

### LLM09 — Misinformation
Salidas incorrectas presentadas con confianza — alucinaciones, citas inventadas, código inseguro sugerido.
- Riesgo operacional y reputacional; con impacto en derechos, puede constituir uso de alto riesgo bajo el
  proyecto de ley chileno de IA.
- **Controles**: grounding con fuentes citadas y verificables, indicación de incertidumbre, revisión humana
  en decisiones con efecto sobre personas, medición de tasa de error en el dominio real.

### LLM10 — Unbounded Consumption
Uso desmedido de recursos: costo, cómputo, cuota del proveedor.
- Denial of Wallet, bucles de agentes, prompts adversarios que maximizan tokens, extracción de modelo por
  consultas masivas.
- **Controles**: cuotas por usuario y por sesión, límites de tokens y de profundidad de bucle, timeouts,
  alertas de costo, degradación controlada.

---

## MITRE ATLAS

Base de conocimiento de tácticas y técnicas adversarias contra sistemas de IA, análoga a ATT&CK.
Úsala para dos cosas: nombrar los ataques con vocabulario compartido, y detectar **brechas de detección**.

**Tácticas** (secuencia típica de un adversario):

1. Reconnaissance — descubrir qué modelo y arquitectura se usa
2. Resource Development — preparar datos o modelos maliciosos
3. Initial Access — acceso al sistema o a su cadena de suministro
4. ML Model Access — acceso a inferencia, API o pesos
5. Execution — ejecutar en el entorno del sistema
6. Persistence — backdoors en modelo, datos o prompts
7. Privilege Escalation — abusar de tools y credenciales del agente
8. Defense Evasion — evadir guardrails y detección
9. Credential Access — extraer claves del contexto o de las tools
10. Discovery — enumerar capacidades, tools y fuentes
11. Collection — reunir datos del sistema
12. ML Attack Staging — preparar el ataque (proxy models, envenenamiento)
13. Exfiltration — sacar datos vía salidas, URLs, o tools
14. Impact — degradación, costo, erosión de integridad

**Uso práctico**: por cada táctica, responde "¿lo detectaríamos?". Las tácticas sin respuesta son la lista
de trabajo de detection engineering. Referencia: <https://atlas.mitre.org/>

---

## Riesgos específicos de agentes autónomos

Los agentes concentran los peores casos de LLM01 + LLM05 + LLM06.

| Riesgo | Descripción | Mitigación mínima |
|---|---|---|
| Confused deputy | El agente actúa con sus permisos por orden de un atacante | Propagar la identidad del usuario a cada tool, no usar cuenta de servicio omnipotente |
| Bucle de acciones | Reintentos infinitos con costo o efectos duplicados | Límite de pasos, idempotencia, presupuesto por tarea |
| Efectos irreversibles | Borrar, enviar, pagar, publicar | Lista explícita de acciones que requieren confirmación humana |
| Memoria envenenada | Instrucción hostil persiste entre sesiones | Memoria de solo lectura por defecto, expiración, revisión de escrituras |
| Encadenamiento de agentes | Permisos efectivos mayores que los de cada agente | Documentar el conjunto de permisos de la cadena y recortarlo al mínimo |
| Exfiltración por canal lateral | Datos en URLs de imágenes, webhooks, nombres de archivo | Allowlist de dominios de salida, bloquear renderizado remoto |

---

## Checklist rápido de threat modeling

Para cada sistema, responde en una sola sesión:

- [ ] ¿Qué contenido no controlado por nosotros llega al contexto del modelo?
- [ ] Si ese contenido contuviera instrucciones, ¿qué es lo peor que lograría?
- [ ] ¿Qué herramientas puede invocar el modelo y con qué identidad?
- [ ] ¿Alguna acción es irreversible o tiene efecto externo? ¿Hay confirmación humana?
- [ ] ¿La autorización del RAG se aplica en la recuperación o solo en el prompt?
- [ ] ¿Dónde termina la salida: HTML, SQL, shell, otro agente?
- [ ] ¿Qué datos personales pasan por el contexto y con qué base de licitud?
- [ ] ¿Se registran prompts, documentos recuperados, tool calls y salidas? ¿Por cuánto tiempo?
- [ ] Si esto se explotara hoy, ¿en cuánto tiempo nos enteraríamos?
- [ ] ¿Tenemos los datos para redactar una alerta temprana a ANCI en 3 horas?

---

## Fuentes

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [OWASP Agentic Security Initiative](https://genai.owasp.org/)
- [NIST AI 100-2: Adversarial Machine Learning Taxonomy](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
