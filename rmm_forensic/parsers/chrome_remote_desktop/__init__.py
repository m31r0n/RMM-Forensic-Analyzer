"""Parser forense para Chrome Remote Desktop."""

from .parser import ChromeRDParser
from .crd_logs import parse_crd_logs

__all__ = ["ChromeRDParser", "parse_crd_logs"]
