#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Clasificador de nivel de riesgo para casos de uso de IA — marco CCHIA.

Aplica el esquema por riesgo del proyecto de ley chileno de IA (Boletin 16821-19,
en tramitacion a agosto 2026) y determina las obligaciones aplicables bajo la
Ley 21.663 (ciberseguridad) y la Ley 21.719 (datos personales, vigente 01-12-2026).

Uso:
    python clasificar_riesgo.py --interactivo
    python clasificar_riesgo.py --json caso.json
    python clasificar_riesgo.py --ejemplo > caso.json

Orientacion tecnica. No constituye asesoria legal.
"""

import argparse
import json
import sys
import textwrap

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# --- Criterios -------------------------------------------------------------
# clave, pregunta, nivel que gatilla

INACEPTABLE = [
    ("manipulacion_danina",
     "¿Usa tecnicas subliminales o manipuladoras para alterar la conducta de personas causandoles dano?"),
    ("explota_vulnerabilidad",
     "¿Explota vulnerabilidades por edad, discapacidad o situacion socioeconomica para alterar conducta?"),
    ("scoring_social",
     "¿Clasifica o puntua a personas por su comportamiento social para darles trato desfavorable en contextos ajenos al origen del dato?"),
    ("biometria_masiva",
     "¿Hace identificacion biometrica remota en tiempo real en espacios publicos, o categorizacion biometrica por atributos protegidos?"),
]

ALTO = [
    ("salud_seguridad",
     "¿Su falla puede afectar la salud, la seguridad fisica o la vida de personas?"),
    ("acceso_servicios",
     "¿Determina o condiciona el acceso a servicios esenciales, credito, seguros o beneficios sociales?"),
    ("empleo",
     "¿Interviene en seleccion, evaluacion, promocion o desvinculacion de trabajadores?"),
    ("educacion",
     "¿Interviene en admision, evaluacion o progresion educativa?"),
    ("justicia_orden",
     "¿Se usa en justicia, seguridad publica, migracion o aplicacion de la ley?"),
    ("infra_critica",
     "¿Opera o gestiona infraestructura critica (energia, agua, transporte, telecom, financiera)?"),
    ("decision_automatizada",
     "¿Toma decisiones con efecto juridico o significativo sobre personas sin revision humana efectiva?"),
    ("datos_sensibles",
     "¿Trata datos sensibles (salud, biometricos, origen, creencias, vida sexual) o datos de NNA?"),
]

LIMITADO = [
    ("interactua_personas",
     "¿Interactua directamente con personas (chatbot, asistente, voz)?"),
    ("genera_contenido",
     "¿Genera texto, imagen, audio o video que podria confundirse con contenido humano o real?"),
    ("reconoce_emociones",
     "¿Infiere emociones o estados de las personas?"),
]

CONTEXTO = [
    ("es_oiv",
     "¿La organizacion esta calificada como Operador de Importancia Vital por la ANCI?"),
    ("servicio_esencial",
     "¿La organizacion presta un servicio esencial segun el art. 4 de la Ley 21.663?"),
    ("datos_personales",
     "¿El sistema trata datos personales en cualquier etapa (entrada, contexto, entrenamiento, logs)?"),
    ("proveedor_externo",
     "¿Depende de un modelo o servicio de IA de un tercero?"),
    ("opera_en_ue",
     "¿El sistema o su salida se ofrecen en la Union Europea?"),
]

TODAS = INACEPTABLE + ALTO + LIMITADO + CONTEXTO

NIVELES = {
    "inaceptable": "RIESGO INACEPTABLE",
    "alto": "ALTO RIESGO",
    "limitado": "RIESGO LIMITADO",
    "minimo": "SIN RIESGO EVIDENTE",
}

CONTROLES_POR_NIVEL = {
    "inaceptable": "No desplegar. Rediseñar el caso de uso o descartarlo.",
    "alto": "Catalogo completo: todos los controles marcados ● y ○ en controles-y-mapeo.md.",
    "limitado": "Controles marcados ● en las columnas Min y Lim de controles-y-mapeo.md.",
    "minimo": "Controles marcados ● en la columna Min de controles-y-mapeo.md.",
}


def preguntar(clave, texto):
    while True:
        r = input("  " + textwrap.fill(texto, 96).replace("\n", "\n  ") + "\n  [s/n] > ").strip().lower()
        if r in ("s", "si", "sí", "y", "yes"):
            return True
        if r in ("n", "no"):
            return False
        print("  Responde s o n.")


def recolectar_interactivo():
    datos = {}
    bloques = [
        ("USOS POTENCIALMENTE PROHIBIDOS", INACEPTABLE),
        ("USOS DE ALTO RIESGO", ALTO),
        ("TRANSPARENCIA", LIMITADO),
        ("CONTEXTO ORGANIZACIONAL", CONTEXTO),
    ]
    print("\n=== Clasificacion de riesgo de caso de uso de IA — CCHIA ===\n")
    datos["nombre"] = input("Nombre del sistema: ").strip() or "(sin nombre)"
    for titulo, grupo in bloques:
        print("\n--- " + titulo + " ---")
        for clave, texto in grupo:
            datos[clave] = preguntar(clave, texto)
    return datos


def clasificar(d):
    razones = []
    nivel = "minimo"

    disparos = [t for k, t in INACEPTABLE if d.get(k)]
    if disparos:
        return "inaceptable", disparos

    disparos = [t for k, t in ALTO if d.get(k)]
    if disparos:
        nivel = "alto"
        razones = disparos
    else:
        disparos = [t for k, t in LIMITADO if d.get(k)]
        if disparos:
            nivel = "limitado"
            razones = disparos
        else:
            razones = ["Ningun criterio de riesgo inaceptable, alto ni limitado se activo."]
    return nivel, razones


def obligaciones(d, nivel):
    obl = []

    if d.get("es_oiv"):
        obl.append(("Ley 21.663 — OIV",
                    "SGSI, planes de continuidad y ciberseguridad certificados, auditorias periodicas, "
                    "Delegado de Ciberseguridad, y reporte de incidentes 3h / 24h (servicio afectado) / 15 dias. "
                    "El sistema de IA debe estar en el inventario de activos del SGSI."))
    elif d.get("servicio_esencial"):
        obl.append(("Ley 21.663 — Servicio esencial",
                    "Gestion continua de riesgos, capacidad de respuesta y reporte de incidentes "
                    "3h / 72h / 15 dias al CSIRT Nacional."))
    else:
        obl.append(("Ley 21.663",
                    "Sin obligaciones directas si no es OIV ni servicio esencial. Verificar la nomina "
                    "vigente de OIV en anci.gob.cl antes de descartarlo."))

    if d.get("datos_personales"):
        detalle = ("Base de licitud, finalidad, minimizacion, derechos ARCOP con procedimiento real de "
                   "borrado en indices y datasets, y notificacion de brechas. Vigente 01-12-2026.")
        if d.get("datos_sensibles"):
            detalle += " Datos sensibles: regimen reforzado y evaluacion de impacto."
        if d.get("decision_automatizada"):
            detalle += " Decisiones automatizadas: derecho de oposicion y explicacion; documentar supervision humana."
        obl.append(("Ley 21.719", detalle))

    if d.get("proveedor_externo"):
        obl.append(("Cadena de suministro",
                    "Contrato de encargado de tratamiento, plazo contractual de notificacion de incidentes "
                    "compatible con las 3 horas de la Ley 21.663, y logging propio independiente del proveedor. "
                    "Ver references/evaluacion-proveedores.md."))

    if nivel == "alto":
        obl.append(("Proyecto ley IA (Boletin 16821-19, en tramitacion)",
                    "Anticipar: gestion de riesgos documentada, calidad y procedencia de datos, documentacion "
                    "tecnica, supervision humana efectiva, robustez y ciberseguridad, y registro del sistema."))
    elif nivel == "limitado":
        obl.append(("Proyecto ley IA (Boletin 16821-19, en tramitacion)",
                    "Anticipar deberes de transparencia: informar que se interactua con un sistema de IA y "
                    "etiquetar el contenido generado."))
    elif nivel == "inaceptable":
        obl.append(("Proyecto ley IA (Boletin 16821-19, en tramitacion)",
                    "El uso quedaria prohibido. Detener el desarrollo y rediseñar el caso de uso."))

    if d.get("opera_en_ue"):
        obl.append(("EU AI Act",
                    "Aplica en paralelo a la normativa chilena. Evaluar categoria y obligaciones bajo el "
                    "reglamento europeo con asesoria especializada."))

    obl.append(("Ley 21.459 / Ley 21.595",
                "Cualquier prueba adversaria requiere autorizacion escrita, alcance y ventana temporal. "
                "Incluir los sistemas de IA en el modelo de prevencion de delitos."))

    return obl


def imprimir(d, nivel, razones, obls):
    ancho = 98
    print("\n" + "=" * ancho)
    print("  CLASIFICACION: " + NIVELES[nivel])
    print("  Sistema: " + str(d.get("nombre", "(sin nombre)")))
    print("=" * ancho)

    print("\nCRITERIOS ACTIVADOS")
    for r in razones:
        print("  - " + textwrap.fill(r, ancho - 4).replace("\n", "\n    "))

    print("\nPROFUNDIDAD DE ANALISIS REQUERIDA")
    print("  " + textwrap.fill(CONTROLES_POR_NIVEL[nivel], ancho - 2).replace("\n", "\n  "))

    print("\nOBLIGACIONES Y DEBERES APLICABLES")
    for titulo, detalle in obls:
        print("\n  [" + titulo + "]")
        print("  " + textwrap.fill(detalle, ancho - 4).replace("\n", "\n  "))

    print("\n" + "-" * ancho)
    print("Siguiente paso: registrar en assets/registro-sistemas-ia.csv y continuar con el paso 3 del")
    print("flujo (superficie de ataque). Referencia normativa con fecha de corte agosto 2026.")
    print("Orientacion tecnica, no asesoria legal.")
    print("-" * ancho + "\n")


def ejemplo():
    plantilla = {"nombre": "Asistente de atencion a clientes"}
    for clave, _ in TODAS:
        plantilla[clave] = False
    plantilla["interactua_personas"] = True
    plantilla["datos_personales"] = True
    plantilla["proveedor_externo"] = True
    return plantilla


def main():
    p = argparse.ArgumentParser(
        description="Clasificador de riesgo de casos de uso de IA — marco CCHIA")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--interactivo", action="store_true", help="Cuestionario paso a paso")
    g.add_argument("--json", metavar="ARCHIVO", help="Lee las respuestas desde un archivo JSON")
    g.add_argument("--ejemplo", action="store_true", help="Imprime un JSON de ejemplo")
    p.add_argument("--salida", metavar="ARCHIVO", help="Guarda el resultado en JSON")
    args = p.parse_args()

    if args.ejemplo:
        print(json.dumps(ejemplo(), indent=2, ensure_ascii=False))
        return 0

    if args.interactivo:
        datos = recolectar_interactivo()
    else:
        with open(args.json, encoding="utf-8") as fh:
            datos = json.load(fh)
        desconocidas = set(datos) - {k for k, _ in TODAS} - {"nombre"}
        if desconocidas:
            print("Aviso: claves ignoradas en el JSON: " + ", ".join(sorted(desconocidas)),
                  file=sys.stderr)

    nivel, razones = clasificar(datos)
    obls = obligaciones(datos, nivel)
    imprimir(datos, nivel, razones, obls)

    if args.salida:
        resultado = {
            "sistema": datos.get("nombre"),
            "nivel_riesgo": nivel,
            "etiqueta": NIVELES[nivel],
            "criterios_activados": razones,
            "profundidad_controles": CONTROLES_POR_NIVEL[nivel],
            "obligaciones": [{"marco": t, "detalle": dt} for t, dt in obls],
            "respuestas": datos,
            "fecha_corte_normativo": "2026-08",
        }
        with open(args.salida, "w", encoding="utf-8") as fh:
            json.dump(resultado, fh, indent=2, ensure_ascii=False)
        print("Resultado guardado en " + args.salida)

    return 0


if __name__ == "__main__":
    sys.exit(main())
