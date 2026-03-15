"""Parser forense para Splashtop."""

from .parser import SplashtopParser
from .splashtop_logs import parse_splashtop_logs

__all__ = ["SplashtopParser", "parse_splashtop_logs"]
