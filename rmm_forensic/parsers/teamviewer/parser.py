"""
Main TeamViewer parser - BaseParser implementation.

Detects TeamViewer log file types and delegates to the appropriate
sub-parser (connections.py or logfile.py).
Auto-registers with ParserRegistry on import.
"""

from __future__ import annotations

import os
import re
from typing import ClassVar

from ...models.base import RMMType, ParseResult
from ..base import BaseParser
from ..registry import ParserRegistry
from .connections import parse_connections
from .logfile import parse_logfile

# Filename patterns for can_parse detection
_CONNECTIONS_PATTERNS = re.compile(
    r"^connections(?:_incoming)?\.txt$", re.I
)
_LOGFILE_PATTERNS = re.compile(
    r"^teamviewer\d*_logfile(?:_old)?\.log$", re.I
)


class TeamViewerParser(BaseParser):
    """Parser forense para TeamViewer."""

    rmm_type: ClassVar[RMMType] = RMMType.TEAMVIEWER

    def can_parse(self, filepath: str) -> bool:
        """
        Check if the file matches known TeamViewer filename patterns.

        Recognized files:
        - Connections_incoming.txt
        - Connections.txt
        - TeamViewer*_Logfile.log
        - TeamViewer*_Logfile_OLD.log
        """
        basename = os.path.basename(filepath)

        if _CONNECTIONS_PATTERNS.match(basename):
            return True
        if _LOGFILE_PATTERNS.match(basename):
            return True

        return False

    def parse(self, filepath: str, hostname: str = "") -> ParseResult:
        """
        Parse a TeamViewer log file.

        Detects the file type and delegates to the appropriate sub-parser:
        - Connection logs -> connections.py
        - Log files -> logfile.py
        """
        basename = os.path.basename(filepath)
        result = ParseResult(rmm_type=RMMType.TEAMVIEWER, hostname=hostname)

        if _CONNECTIONS_PATTERNS.match(basename):
            connections = parse_connections(filepath)
            result.connections = connections
            result.source_files.append(basename)
            result.total_events = len(connections)
        elif _LOGFILE_PATTERNS.match(basename):
            result = parse_logfile(filepath, hostname=hostname)
        else:
            # Fallback: try to detect from content
            result = self._parse_by_content(filepath, hostname)

        return result

    def _parse_by_content(self, filepath: str, hostname: str) -> ParseResult:
        """Attempt to parse by inspecting file content."""
        result = ParseResult(rmm_type=RMMType.TEAMVIEWER, hostname=hostname)

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(2048)
        except OSError:
            return result

        # If it looks like a connection log (tab-separated IDs and dates)
        if re.search(r"\d{6,15}\t", head):
            connections = parse_connections(filepath)
            result.connections = connections
            result.source_files.append(os.path.basename(filepath))
            result.total_events = len(connections)
        else:
            # Default to logfile parser
            result = parse_logfile(filepath, hostname=hostname)

        return result

    @classmethod
    def file_patterns(cls) -> list[str]:
        """Glob patterns for TeamViewer files."""
        return [
            "Connections_incoming.txt",
            "Connections.txt",
            "TeamViewer*_Logfile.log",
            "TeamViewer*_Logfile_OLD.log",
        ]

    @classmethod
    def known_paths_windows(cls) -> list[str]:
        """Known TeamViewer installation/log paths on Windows."""
        return [
            "%APPDATA%\\TeamViewer",
            "%PROGRAMDATA%\\TeamViewer",
            "C:\\Program Files\\TeamViewer",
            "C:\\Program Files (x86)\\TeamViewer",
        ]

    @classmethod
    def known_paths_linux(cls) -> list[str]:
        """Known TeamViewer paths on Linux."""
        return [
            "/opt/teamviewer/logfiles",
            "/var/log/teamviewer",
            "~/.local/share/teamviewer/logfiles",
        ]

    @classmethod
    def known_paths_macos(cls) -> list[str]:
        """Known TeamViewer paths on macOS."""
        return [
            "/Library/Preferences/com.teamviewer.teamviewer.preferences",
            "~/Library/Logs/TeamViewer",
            "/var/log/teamviewer",
        ]

    @classmethod
    def content_signatures(cls) -> list[str]:
        """Regex patterns that identify TeamViewer log content."""
        return [
            r"TeamViewer\s+\d+",                       # "TeamViewer 15" etc.
            r"TeamViewer\s+version\s+\d+",             # "TeamViewer version 15.x"
            r"Incoming\s+session\s+request\s+from",    # Session marker
            r"Start\s+session\s+to",                   # Outgoing session
            r"Participant\s+ID:",                      # Remote participant
            r"SessionTerminate",                       # Session end marker
            r"RemoteControl\s+\{",                     # Connection type in connections log
        ]


# ─── Auto-register ───────────────────────────────────────────────────────────

ParserRegistry.register(TeamViewerParser())
