"""Validación runtime de artefactos contra los contratos JSON Schema versionados."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from .models import ContractError


SCHEMA_ROOT = Path(__file__).resolve().parent.parent / "schemas"


@lru_cache(maxsize=None)
def _validator(schema_name: str) -> Draft202012Validator:
    path = SCHEMA_ROOT / schema_name
    if not path.is_file():
        raise ContractError(f"Schema CCHIA inexistente: {path}")
    schema = json.loads(path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_contract(schema_name: str, value: Any) -> None:
    errors = sorted(_validator(schema_name).iter_errors(value), key=lambda item: list(item.path))
    if not errors:
        return
    details = []
    for error in errors[:10]:
        location = ".".join(str(part) for part in error.path) or "$"
        details.append(f"{location}: {error.message}")
    if len(errors) > 10:
        details.append(f"... y {len(errors) - 10} errores adicionales")
    raise ContractError(f"{schema_name} inválido: " + "; ".join(details))
