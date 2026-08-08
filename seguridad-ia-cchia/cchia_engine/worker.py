"""Worker aislado: ejecuta un check puro sin builtins de I/O, imports ni introspección."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path


SAFE_BUILTINS = {
    "all": all,
    "any": any,
    "bool": bool,
    "dict": dict,
    "enumerate": enumerate,
    "float": float,
    "int": int,
    "isinstance": isinstance,
    "len": len,
    "list": list,
    "max": max,
    "min": min,
    "range": range,
    "reversed": reversed,
    "set": set,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "zip": zip,
}

FORBIDDEN_NAMES = {
    "open",
    "exec",
    "eval",
    "compile",
    "__import__",
    "input",
    "breakpoint",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "dir",
    "help",
}


def _validate(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)):
            raise ValueError("El check contiene una construcción no permitida")
        if isinstance(node, ast.Name) and (node.id.startswith("__") or node.id in FORBIDDEN_NAMES):
            raise ValueError(f"El check intenta usar una capacidad no permitida: {node.id}")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            raise ValueError("El check intenta usar introspección")


def execute(check_path: Path, context_path: Path) -> dict:
    source = check_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(check_path))
    _validate(tree)
    namespace = {"__builtins__": SAFE_BUILTINS}
    exec(compile(tree, str(check_path), "exec"), namespace, namespace)
    evaluate = namespace.get("evaluate")
    if not callable(evaluate):
        raise ValueError("No existe evaluate(context)")
    context = json.loads(context_path.read_text(encoding="utf-8"))
    result = evaluate(context)
    if not isinstance(result, dict):
        raise ValueError("evaluate(context) debe retornar un objeto")
    return result


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"error": "uso: worker.py CHECK CONTEXT"}))
        return 2
    try:
        result = execute(Path(sys.argv[1]), Path(sys.argv[2]))
    except Exception as exc:  # El boundary serializa el error; no expone traceback al informe.
        print(json.dumps({"error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
