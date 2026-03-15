"""Parser forense para RustDesk."""

from .parser import RustDeskParser
from .rustdesk_logs import parse_rustdesk_logs

__all__ = ["RustDeskParser", "parse_rustdesk_logs"]
