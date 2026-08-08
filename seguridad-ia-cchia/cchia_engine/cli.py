from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .catalog import load_catalog
from .collectors import available_collectors, collector_names
from .compiler import compile_assessment
from .scaffold import scaffold_check


SKILL_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CATALOG = SKILL_ROOT / "checks"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cchia", description="CCHIA Checks + Security Compiler")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG, help="Raíz del catálogo de checks")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="Validar contratos y perfil read-only de todos los checks")
    listing = sub.add_parser("list", help="Listar catálogo")
    listing.add_argument("--json", action="store_true")

    collectors_cmd = sub.add_parser("collectors", help="Listar collectors runtime opt-in (no ejecuta comandos)")
    collectors_cmd.add_argument("--json", action="store_true")

    compile_cmd = sub.add_parser("compile", help="Seleccionar controles, ejecutar y emitir evidencia/informes")
    compile_cmd.add_argument("--target", type=Path, help="Repositorio, directorio IaC o archivo individual")
    compile_cmd.add_argument("--system", type=Path, help="Descripción YAML/JSON/Markdown/texto de arquitectura o sistema")
    compile_cmd.add_argument("--output", type=Path, required=True)
    compile_cmd.add_argument("--control", action="append", default=[], help="Forzar un control; repetible")
    compile_cmd.add_argument("--plan-only", action="store_true")
    compile_cmd.add_argument("--fail-on-findings", action="store_true")
    compile_cmd.add_argument(
        "--collector",
        action="append",
        default=[],
        choices=collector_names(),
        help="Collector runtime read-only explícito; repetible y desactivado por defecto",
    )
    compile_cmd.add_argument("--gcp-project", help="ID de proyecto para gcloud-iam")
    compile_cmd.add_argument("--aws-profile", help="Perfil AWS CLI opcional para aws-iam")
    compile_cmd.add_argument("--azure-subscription", help="ID o nombre de suscripción para az-role-assignments")
    compile_cmd.add_argument("--github-repo", help="Repositorio owner/repo para gh-repo-security")
    compile_cmd.add_argument("--kube-context", help="Contexto kubeconfig explícito")
    compile_cmd.add_argument("--kube-namespace", help="Namespace; si se omite, usa --all-namespaces")
    compile_cmd.add_argument(
        "--collector-timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Timeout por comando collector (1-300; default: 30)",
    )

    new_check = sub.add_parser("new-check", help="Crear control.yaml + check.py + expected.json + mapping.yaml + README.md")
    new_check.add_argument("--id", required=True)
    new_check.add_argument("--domain", required=True)
    new_check.add_argument("--title", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            from .fixtures import validate_catalog_fixtures

            packages = load_catalog(args.catalog)
            fixtures = validate_catalog_fixtures(packages)
            print(
                f"OK: {len(packages)} CCHIA Checks y {len(fixtures)} fixtures válidos "
                f"en {args.catalog}"
            )
            return 0
        if args.command == "list":
            packages = load_catalog(args.catalog)
            rows = [
                {
                    "id": item.control_id,
                    "version": item.control_version,
                    "domain": item.domain,
                    "title": item.control["title"],
                }
                for item in packages
            ]
            if args.json:
                print(json.dumps(rows, ensure_ascii=False, indent=2))
            else:
                for row in rows:
                    print(f"{row['id']}\t{row['version']}\t{row['domain']}\t{row['title']}")
            return 0
        if args.command == "collectors":
            rows = available_collectors()
            if args.json:
                print(json.dumps(rows, ensure_ascii=False, indent=2))
            else:
                for row in rows:
                    print(f"{row['id']}\t{row['provider']}\t{row['mode']}\t{row['description']}")
            return 0
        if args.command == "new-check":
            path = scaffold_check(args.catalog, args.id, args.domain, args.title)
            print(path)
            return 0
        if args.command == "compile":
            compile_options = {
                "target": args.target,
                "catalog_root": args.catalog,
                "output": args.output,
                "system_path": args.system,
                "forced_controls": args.control,
                "plan_only": args.plan_only,
            }
            if args.collector:
                compile_options["collector_names"] = args.collector
                compile_options["collector_options"] = {
                    "aws_profile": args.aws_profile,
                    "azure_subscription": args.azure_subscription,
                    "gcp_project": args.gcp_project,
                    "github_repo": args.github_repo,
                    "kube_context": args.kube_context,
                    "kube_namespace": args.kube_namespace,
                    "timeout_seconds": args.collector_timeout,
                }
            result = compile_assessment(
                **compile_options,
            )
            print(json.dumps({key: value for key, value in result.items() if key != "assessment"}, ensure_ascii=False, indent=2))
            if args.fail_on_findings and not args.plan_only:
                statuses = result["assessment"]["summary"]["statuses"]
                if statuses.get("FAIL", 0) or statuses.get("ERROR", 0):
                    return 2
            return 0
    except Exception as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    return 1
