"""
Main Chrome Remote Desktop parser - BaseParser implementation.

Detects Chrome Remote Desktop log files and delegates to the
crd_logs sub-parser.
Auto-registers with ParserRegistry on import.
"""

from __future__ import annotations

import os
import re
from typing import ClassVar

from ...models.base import RMMType, ParseResult
from ..base import BaseParser
from ..registry import ParserRegistry
from .crd_logs import parse_crd_logs

# ─── Detection patterns ─────────────────────────────────────────────────────

_FILENAME_PATTERNS = re.compile(
    r"^(?:chrome_remote_desktop.*\.log"
    r"|chromoting.*\.log"
    r"|remoting_host.*\.log"
    r"|crd.*\.log)$",
    re.I,
)

_CONTENT_SIGNATURES = re.compile(
    r"chromoting|chrome.?remote.?desktop|remoting_host",
    re.I,
)


class ChromeRDParser(BaseParser):
    """
    Parser forense para Chrome Remote Desktop.

    Handles:
    - chrome_remote_desktop*.log: Main CRD log files
    - chromoting*.log: Chromoting service logs
    - Any log containing chromoting/CRD signatures
    """

    rmm_type: ClassVar[RMMType] = RMMType.CHROME_REMOTE_DESKTOP

    def can_parse(self, filepath: str) -> bool:
        """
        Check if the file is a Chrome Remote Desktop artifact.

        Verifies by filename pattern first, then falls back to
        reading the first bytes for content signatures.
        """
        basename = os.path.basename(filepath).lower()

        # Filename pattern match
        if _FILENAME_PATTERNS.match(basename):
            return True

        # Path-based detection
        filepath_lower = filepath.lower().replace("\\", "/")
        if "chrome remote desktop" in filepath_lower or "chromoting" in filepath_lower:
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
        Parse a Chrome Remote Desktop log file.

        Delegates to crd_logs.parse_crd_logs for all text log files.
        """
        result = ParseResult(
            rmm_type=RMMType.CHROME_REMOTE_DESKTOP,
            hostname=hostname,
        )

        try:
            result = parse_crd_logs(filepath, hostname=hostname)
        except Exception:
            # Never crash - return empty result on unexpected errors
            result.error_count += 1

        return result

    @classmethod
    def file_patterns(cls) -> list[str]:
        """Glob patterns for Chrome Remote Desktop files."""
        return ["chrome_remote_desktop*.log", "*.log"]

    @classmethod
    def known_paths_windows(cls) -> list[str]:
        """Known CRD log paths on Windows."""
        return [
            r"%LOCALAPPDATA%\Google\Chrome Remote Desktop",
            r"%PROGRAMDATA%\Google\Chrome Remote Desktop",
        ]

    @classmethod
    def known_paths_linux(cls) -> list[str]:
        """Known CRD paths on Linux."""
        return [
            "/var/log/chrome-remote-desktop",
            "/tmp/chrome_remote_desktop_*",
            "~/.config/chrome-remote-desktop",
        ]

    @classmethod
    def known_paths_macos(cls) -> list[str]:
        """Known CRD paths on macOS."""
        return [
            "~/Library/Logs/Chrome Remote Desktop",
            "/var/log/chrome-remote-desktop",
        ]

    @classmethod
    def content_signatures(cls) -> list[str]:
        """Regex patterns that identify Chrome Remote Desktop content."""
        return [
            r"chromoting|chrome.?remote.?desktop|remoting_host",
        ]


# ─── Auto-register ───────────────────────────────────────────────────────────

ParserRegistry.register(ChromeRDParser())
