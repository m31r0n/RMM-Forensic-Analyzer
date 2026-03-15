"""
Main Splashtop parser - BaseParser implementation.

Detects Splashtop log files and delegates to the
splashtop_logs sub-parser.
Auto-registers with ParserRegistry on import.
"""

from __future__ import annotations

import os
import re
from typing import ClassVar

from ...models.base import RMMType, ParseResult
from ..base import BaseParser
from ..registry import ParserRegistry
from .splashtop_logs import parse_splashtop_logs

# ─── Detection patterns ─────────────────────────────────────────────────────

_FILENAME_PATTERNS = re.compile(
    r"^(?:SplashtopStreamer.*\.log"
    r"|log_\d+\.log"
    r"|SPLog\.txt"
    r"|SRLog\.txt"
    r"|.*splashtop.*\.log)$",
    re.I,
)

_CONTENT_SIGNATURES = re.compile(
    r"[Ss]plashtop|SplashtopStreamer|Splashtop\s+Streamer",
    re.I,
)


class SplashtopParser(BaseParser):
    """
    Parser forense para Splashtop.

    Handles:
    - SplashtopStreamer*.log: Streamer service logs
    - log_*.log: Date-based log files
    - SPLog.txt, SRLog.txt: Legacy log formats
    - Any log containing Splashtop signatures
    """

    rmm_type: ClassVar[RMMType] = RMMType.SPLASHTOP

    def can_parse(self, filepath: str) -> bool:
        """
        Check if the file is a Splashtop artifact.

        Verifies by filename pattern first, then falls back to
        reading the first bytes for content signatures.
        """
        basename = os.path.basename(filepath).lower()

        # Filename pattern match
        if _FILENAME_PATTERNS.match(basename):
            return True

        # Path-based detection
        filepath_lower = filepath.lower().replace("\\", "/")
        if "splashtop" in filepath_lower:
            if basename.endswith(".log") or basename.endswith(".txt"):
                return True

        # Content-based detection for log/txt files
        if not (basename.endswith(".log") or basename.endswith(".txt")):
            return False

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                head = ""
                for _ in range(20):
                    line = f.readline()
                    if not line:
                        break
                    head += line
        except OSError:
            return False

        if _CONTENT_SIGNATURES.search(head):
            return True

        return False

    def parse(self, filepath: str, hostname: str = "") -> ParseResult:
        """
        Parse a Splashtop log file.

        Delegates to splashtop_logs.parse_splashtop_logs for all text log files.
        """
        result = ParseResult(
            rmm_type=RMMType.SPLASHTOP,
            hostname=hostname,
        )

        try:
            result = parse_splashtop_logs(filepath, hostname=hostname)
        except Exception:
            # Never crash - return empty result on unexpected errors
            result.error_count += 1

        return result

    @classmethod
    def file_patterns(cls) -> list[str]:
        """Glob patterns for Splashtop files."""
        return [
            "SplashtopStreamer*.log",
            "log_*.log",
            "*splashtop*.log",
            "SPLog.txt",
            "SRLog.txt",
        ]

    @classmethod
    def known_paths_windows(cls) -> list[str]:
        """Known Splashtop installation/log paths on Windows."""
        return [
            r"%PROGRAMDATA%\Splashtop\*",
            r"%APPDATA%\Splashtop\*",
        ]

    @classmethod
    def known_paths_linux(cls) -> list[str]:
        """Known Splashtop paths on Linux."""
        return [
            "/opt/splashtop*",
            "/var/log/splashtop*",
        ]

    @classmethod
    def known_paths_macos(cls) -> list[str]:
        """Known Splashtop paths on macOS."""
        return [
            "/Library/Application Support/Splashtop*",
            "~/Library/Logs/Splashtop*",
        ]

    @classmethod
    def content_signatures(cls) -> list[str]:
        """Regex patterns that identify Splashtop content."""
        return [
            r"[Ss]plashtop|SplashtopStreamer",
        ]


# ─── Auto-register ───────────────────────────────────────────────────────────

ParserRegistry.register(SplashtopParser())
