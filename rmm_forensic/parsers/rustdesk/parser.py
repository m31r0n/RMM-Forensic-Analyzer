"""
Main RustDesk parser - BaseParser implementation.

Detects RustDesk log files and delegates to the
rustdesk_logs sub-parser.
Auto-registers with ParserRegistry on import.
"""

from __future__ import annotations

import os
import re
from typing import ClassVar

from ...models.base import RMMType, ParseResult
from ..base import BaseParser
from ..registry import ParserRegistry
from .rustdesk_logs import parse_rustdesk_logs

# ─── Detection patterns ─────────────────────────────────────────────────────

_FILENAME_PATTERNS = re.compile(
    r"^(?:rustdesk.*\.log"
    r"|D\d+\.log"
    r"|.*rustdesk.*\.log)$",
    re.I,
)

_CONTENT_SIGNATURES = re.compile(
    r"rustdesk|RustDesk",
    re.I,
)


class RustDeskParser(BaseParser):
    """
    Parser forense para RustDesk.

    Handles:
    - rustdesk*.log: Main RustDesk log files
    - D*.log: Date-based log files
    - Any log containing RustDesk signatures
    """

    rmm_type: ClassVar[RMMType] = RMMType.RUSTDESK

    def can_parse(self, filepath: str) -> bool:
        """
        Check if the file is a RustDesk artifact.

        Verifies by filename pattern first, then falls back to
        reading the first bytes for content signatures.
        """
        basename = os.path.basename(filepath).lower()

        # Filename pattern match
        if _FILENAME_PATTERNS.match(basename):
            return True

        # Path-based detection
        filepath_lower = filepath.lower().replace("\\", "/")
        if "rustdesk" in filepath_lower:
            if basename.endswith(".log"):
                return True

        # Content-based detection for .log files
        if not basename.endswith(".log"):
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
        Parse a RustDesk log file.

        Delegates to rustdesk_logs.parse_rustdesk_logs for all text log files.
        """
        result = ParseResult(
            rmm_type=RMMType.RUSTDESK,
            hostname=hostname,
        )

        try:
            result = parse_rustdesk_logs(filepath, hostname=hostname)
        except Exception:
            # Never crash - return empty result on unexpected errors
            result.error_count += 1

        return result

    @classmethod
    def file_patterns(cls) -> list[str]:
        """Glob patterns for RustDesk files."""
        return [
            "rustdesk*.log",
            "D*.log",
        ]

    @classmethod
    def known_paths_windows(cls) -> list[str]:
        """Known RustDesk installation/log paths on Windows."""
        return [
            r"%APPDATA%\RustDesk\*",
            r"%PROGRAMDATA%\RustDesk\*",
        ]

    @classmethod
    def known_paths_linux(cls) -> list[str]:
        """Known RustDesk paths on Linux."""
        return [
            "/var/log/rustdesk*",
            "~/.config/rustdesk/",
            "/root/.config/rustdesk/",
        ]

    @classmethod
    def known_paths_macos(cls) -> list[str]:
        """Known RustDesk paths on macOS."""
        return [
            "~/Library/Logs/RustDesk*",
            "/Library/Application Support/RustDesk*",
        ]

    @classmethod
    def content_signatures(cls) -> list[str]:
        """Regex patterns that identify RustDesk content."""
        return [
            r"rustdesk|RustDesk",
        ]


# ─── Auto-register ───────────────────────────────────────────────────────────

ParserRegistry.register(RustDeskParser())
