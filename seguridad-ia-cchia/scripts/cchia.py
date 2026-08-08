#!/usr/bin/env python3
"""Entrada sin instalación para el CCHIA Security Compiler."""

from pathlib import Path
import sys

SKILL_ROOT = Path(__file__).resolve().parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from cchia_engine.cli import main

raise SystemExit(main())
