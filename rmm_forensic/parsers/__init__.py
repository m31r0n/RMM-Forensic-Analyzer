"""
Parsers de logs forenses para múltiples herramientas RMM.
Cada parser implementa BaseParser y se auto-registra en ParserRegistry.
"""

from .base import BaseParser
from .registry import ParserRegistry

__all__ = ["BaseParser", "ParserRegistry"]
