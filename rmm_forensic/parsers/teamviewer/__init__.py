"""Parser forense para TeamViewer (Connections_incoming.txt, Logfile.log)."""

from .parser import TeamViewerParser
from .connections import parse_connections
from .logfile import parse_logfile

__all__ = ["TeamViewerParser", "parse_connections", "parse_logfile"]
