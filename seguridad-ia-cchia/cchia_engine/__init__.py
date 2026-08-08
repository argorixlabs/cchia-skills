"""Motor compartido para CCHIA Checks y el CCHIA Security Compiler."""

from .compiler import compile_assessment
from .models import ENGINE_VERSION

__all__ = ["compile_assessment"]
__version__ = ENGINE_VERSION
