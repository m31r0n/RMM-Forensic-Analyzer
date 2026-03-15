"""
Content-based file identification for RMM log files.

When filename alone is ambiguous (e.g. ``*.log``), reading the first
few lines and matching against known patterns can positively identify
which RMM tool produced the file.
"""

from __future__ import annotations

import re
import logging
from typing import Optional

from ..utils import detect_encoding

logger = logging.getLogger(__name__)

# ── Content signatures ───────────────────────────────────────────────────────
# Each value is a list of regex patterns.  If *any* pattern matches *any* of
# the first N lines, the file is considered to belong to that RMM tool.

CONTENT_SIGNATURES: dict[str, list[str]] = {
    "AnyDesk": [
        # ad.trace format: level  YYYY-MM-DD HH:MM:SS.nnn  module  pid  tid ...
        r"^\w+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\w+\s+\d+\s+\d+",
        # connection_trace format: Incoming/Outgoing YYYY-MM-DD ...
        r"^(Incoming|Outgoing)\s+\d{4}-\d{2}-\d{2}",
    ],
    "TeamViewer": [
        r"TeamViewer",
        # Connections_incoming.txt tab-delimited: ID<TAB>DD-MM-YYYY ...
        r"^\d+\t\d{2}-\d{2}-\d{4}",
        r"Participant ID",
    ],
    "ScreenConnect": [
        r"ScreenConnect|ConnectWise",
        r"SessionOutput",
    ],
    "Chrome Remote Desktop": [
        r"chrome.remote.?desktop|chromoting",
    ],
    "Splashtop": [
        r"Splashtop|SPLog|SRLog",
    ],
    "RustDesk": [
        r"rustdesk|RustDesk",
    ],
}

# Pre-compile for performance.
_COMPILED_SIGNATURES: dict[str, list[re.Pattern[str]]] = {
    rmm: [re.compile(p, re.IGNORECASE) for p in patterns]
    for rmm, patterns in CONTENT_SIGNATURES.items()
}


def identify_rmm(filepath: str, max_lines: int = 50) -> Optional[str]:
    """
    Identify which RMM tool produced *filepath* by reading its first
    *max_lines* lines and matching against known content signatures.

    Returns the RMM name string (matching ``RMMType.value``) on success,
    or ``None`` if no signature matched.
    """
    try:
        encoding = detect_encoding(filepath)
        with open(filepath, "r", encoding=encoding, errors="replace") as fh:
            lines: list[str] = []
            for i, line in enumerate(fh):
                if i >= max_lines:
                    break
                lines.append(line.rstrip("\r\n"))
    except OSError as exc:
        logger.debug("Cannot read %s for signature check: %s", filepath, exc)
        return None

    for rmm_name, patterns in _COMPILED_SIGNATURES.items():
        for pat in patterns:
            for line in lines:
                if pat.search(line):
                    return rmm_name

    return None
