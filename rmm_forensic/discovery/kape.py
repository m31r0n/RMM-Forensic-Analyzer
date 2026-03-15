"""
KAPE triage output detection and metadata extraction.

KAPE (Kroll Artifact Parser and Extractor) produces a well-known
directory structure when collecting forensic artifacts.  This module
detects that structure and extracts useful metadata such as the
source hostname.

Typical KAPE layout::

    <output>/
    +-- C/
    |   +-- Users/
    |   |   +-- <username>/
    |   |       +-- AppData/Roaming/AnyDesk/
    |   +-- ProgramData/
    |   |   +-- AnyDesk/
    |   +-- Program Files/
    |       +-- TeamViewer/
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Directories that signal KAPE output when found as direct children
# of a candidate root.  We look for a single-letter drive folder
# (typically "C") containing Windows-like paths underneath.
_WINDOWS_SYSTEM_DIRS = {"Users", "ProgramData", "Program Files", "Program Files (x86)", "Windows"}


def detect_kape_output(path: str) -> bool:
    """
    Return *True* if *path* looks like a KAPE triage output root.

    Heuristic: the path contains a direct child that is a single
    upper-case letter (drive letter, e.g. ``C``), and that child
    contains at least one of the well-known Windows system directories.
    """
    try:
        root = Path(path)
        if not root.is_dir():
            return False

        for entry in os.scandir(root):
            if not entry.is_dir():
                continue
            # Single-letter directory name -> possible drive letter
            if len(entry.name) == 1 and entry.name.isalpha():
                drive_path = Path(entry.path)
                try:
                    children = {e.name for e in os.scandir(drive_path) if e.is_dir()}
                except OSError:
                    continue
                if children & _WINDOWS_SYSTEM_DIRS:
                    return True
    except OSError as exc:
        logger.debug("Cannot inspect %s for KAPE structure: %s", path, exc)

    return False


def extract_hostname_from_kape(path: str) -> str:
    """
    Try to infer the source hostname from a KAPE output directory.

    KAPE often names the top-level output folder after the host, e.g.
    ``WORKSTATION01/C/Users/...``.  We also check for a common
    pattern where the folder name or a parent looks like a hostname.

    Returns an empty string if no hostname can be determined.
    """
    root = Path(path)
    name = root.name

    # If the folder itself is a drive-letter, look one level up.
    if len(name) == 1 and name.isalpha():
        name = root.parent.name

    # Simple heuristic: a hostname-like string is alphanumeric (with
    # optional hyphens/underscores), at least 2 chars, and does NOT
    # look like a common generic directory name.
    _generic = {
        "output", "export", "triage", "kape", "collection",
        "evidence", "artifacts", "data", "case", "forensic",
        "results", "extracted", "tmp", "temp",
    }
    if name.lower() in _generic:
        return ""

    # Hostname pattern: starts with a letter, contains only
    # alphanumeric / hyphens / underscores, 2-63 chars.
    if re.match(r"^[A-Za-z][A-Za-z0-9_-]{1,62}$", name):
        return name

    return ""
