"""
Main ScreenConnect/ConnectWise Control parser - BaseParser implementation.

Detects ScreenConnect log file types (text logs, SQLite databases,
user.config) and delegates to the appropriate sub-parser.
Auto-registers with ParserRegistry on import.
"""

from __future__ import annotations

import os
import re
from typing import ClassVar

from ...models.base import RMMType, ParseResult
from ..base import BaseParser
from ..registry import ParserRegistry
from .session_logs import parse_session_logs
from .session_db import parse_session_db

# ─── Detection patterns ─────────────────────────────────────────────────────

_KNOWN_FILENAMES = {
    "sessionoutput.db",
    "user.config",
}

_FILENAME_PATTERNS = re.compile(
    r"^(?:sessionoutput\.db|user\.config|.*screenconnect.*\.log|.*connectwise.*\.log)$",
    re.I,
)

_CONTENT_SIGNATURES = re.compile(
    r"ScreenConnect|ConnectWise|SessionOutput",
    re.I,
)

_SQLITE_MAGIC = b"SQLite"


class ScreenConnectParser(BaseParser):
    """
    Parser forense para ScreenConnect/ConnectWise Control.

    Handles:
    - SessionOutput.db: SQLite database with session data
    - *.log: Text log files with session events
    - user.config: Configuration files (parsed as text logs)
    """

    rmm_type: ClassVar[RMMType] = RMMType.SCREENCONNECT

    def can_parse(self, filepath: str) -> bool:
        """
        Check if the file is a ScreenConnect artifact.

        Verifies by filename pattern first, then falls back to
        reading the first bytes for content signatures.
        """
        basename = os.path.basename(filepath).lower()

        # Known filenames
        if basename in _KNOWN_FILENAMES:
            return True

        # Filename pattern match
        if _FILENAME_PATTERNS.match(basename):
            return True

        # Content-based detection
        try:
            with open(filepath, "rb") as f:
                head = f.read(4096)
        except OSError:
            return False

        # Check if it's a SQLite DB that might be SessionOutput
        if head[:6] == _SQLITE_MAGIC:
            # Only claim SQLite files if they're in a ScreenConnect path
            # or named suggestively
            filepath_lower = filepath.lower()
            if "screenconnect" in filepath_lower or "connectwise" in filepath_lower:
                return True
            return False

        # Check text content for signatures
        try:
            text = head.decode("utf-8", errors="replace")
        except Exception:
            return False

        if _CONTENT_SIGNATURES.search(text):
            return True

        return False

    def parse(self, filepath: str, hostname: str = "") -> ParseResult:
        """
        Parse a ScreenConnect artifact.

        Detects the file type and delegates:
        - SQLite databases -> session_db.py
        - Text files (logs, config) -> session_logs.py
        """
        result = ParseResult(rmm_type=RMMType.SCREENCONNECT, hostname=hostname)

        try:
            if self._is_sqlite(filepath):
                result = parse_session_db(filepath, hostname=hostname)
            else:
                result = parse_session_logs(filepath, hostname=hostname)
        except Exception:
            # Never crash - return empty result on unexpected errors
            result.error_count += 1

        return result

    @staticmethod
    def _is_sqlite(filepath: str) -> bool:
        """Check if the file is a SQLite database."""
        try:
            with open(filepath, "rb") as f:
                return f.read(6) == _SQLITE_MAGIC
        except OSError:
            return False

    @classmethod
    def file_patterns(cls) -> list[str]:
        """Glob patterns for ScreenConnect files."""
        return ["*.db", "*.log", "user.config", "SessionOutput.db"]

    @classmethod
    def known_paths_windows(cls) -> list[str]:
        """Known ScreenConnect installation/log paths on Windows."""
        return [
            r"%PROGRAMDATA%\ScreenConnect Client*",
            r"%PROGRAMFILES%\ScreenConnect Client*",
        ]

    @classmethod
    def known_paths_linux(cls) -> list[str]:
        """Known ScreenConnect paths on Linux."""
        return [
            "/opt/screenconnect*",
            "/opt/connectwisecontrol*",
        ]

    @classmethod
    def known_paths_macos(cls) -> list[str]:
        """Known ScreenConnect paths on macOS."""
        return [
            "/Library/Application Support/connectwisecontrol*",
        ]

    @classmethod
    def content_signatures(cls) -> list[str]:
        """Regex patterns that identify ScreenConnect content."""
        return [
            r"ScreenConnect|ConnectWise|SessionOutput",
        ]


# ─── Auto-register ───────────────────────────────────────────────────────────

ParserRegistry.register(ScreenConnectParser())
