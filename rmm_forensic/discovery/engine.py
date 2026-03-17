"""
Main log discovery engine.

Orchestrates directory walking, filename matching, content-signature
verification, ZIP extraction, and KAPE detection to locate RMM log
files in an arbitrary input path.

The engine **never** attempts to extract nested archives found during
the walk.  Only the top-level path supplied by the caller is extracted
if it is a supported archive.  This prevents wasting time on false-
positive files (e.g. Windows ``$Recycle.Bin`` metadata) and keeps the
analysis scope under the analyst's control.
"""

from __future__ import annotations

import enum
import fnmatch
import hashlib
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from .archive import ArchiveHandler
from .kape import detect_kape_output, extract_hostname_from_kape
from .known_paths import FILE_PATTERNS, KNOWN_PATHS, DIR_HINTS
from .signatures import identify_rmm

logger = logging.getLogger(__name__)


# ── Target OS ────────────────────────────────────────────────────────────────

class TargetOS(enum.Enum):
    """Operating system of the evidence source."""
    WINDOWS = "windows"
    LINUX   = "linux"
    MACOS   = "macos"
    AUTO    = "auto"      # Detect from path structure


# Directories that never contain useful RMM logs and should be skipped
# (case-insensitive comparison).
_SKIP_DIRS_WINDOWS: set[str] = {
    "$recycle.bin",
    "system volume information",
    "$winreagent",
    "$windows.~bt",
    "$windows.~ws",
    "windows.old",
    "config.msi",
    "windows",
    "boot",
    "recovery",
    "$sysreset",
    "perflogs",
}

_SKIP_DIRS_LINUX: set[str] = {
    "proc", "sys", "dev", "run", "snap", "boot", "lost+found",
}

_SKIP_DIRS_MACOS: set[str] = {
    ".spotlight-v100", ".fseventsd", ".trashes",
}

_SKIP_DIRS_COMMON: set[str] = {
    "__pycache__", ".git", "node_modules", ".svn", ".hg",
}


def _skip_dirs_for_os(target_os: TargetOS) -> set[str]:
    """Return the set of directory names to skip for the given OS."""
    base = set(_SKIP_DIRS_COMMON)
    if target_os in (TargetOS.WINDOWS, TargetOS.AUTO):
        base |= _SKIP_DIRS_WINDOWS
    if target_os in (TargetOS.LINUX, TargetOS.AUTO):
        base |= _SKIP_DIRS_LINUX
    if target_os in (TargetOS.MACOS, TargetOS.AUTO):
        base |= _SKIP_DIRS_MACOS
    return base


def _detect_os_from_path(dirpath: str) -> TargetOS:
    """Heuristic: detect OS from directory structure."""
    norm = dirpath.replace("\\", "/").lower()
    # macOS indicators (check BEFORE Windows — both have /Users/)
    if "/library/application support/" in norm or "/library/logs/" in norm:
        return TargetOS.MACOS
    # Linux indicators
    if any(marker in norm for marker in (
        "/home/", "/etc/", "/var/log/", "/opt/",
    )):
        return TargetOS.LINUX
    # Windows indicators
    if any(marker in norm for marker in (
        "/users/", "/programdata/", "/program files/",
        "/windows/", "/appdata/",
    )):
        return TargetOS.WINDOWS
    return TargetOS.WINDOWS   # Default for KAPE/forensic images


# ── Discovered file model ────────────────────────────────────────────────────

@dataclass
class DiscoveredFile:
    """A single RMM-related file discovered during the scan."""

    filepath: str
    rmm_type: str           # RMM name (matches RMMType.value)
    filename: str
    hostname: str = ""      # Inferred hostname (from KAPE structure, etc.)
    user_account: str = ""  # OS user from path (Users/<user>/…, /home/<user>/…)
    confidence: str = ""    # "high" (filename match), "medium" (content), "low" (path)
    size_bytes: int = 0


# ── Discovery engine ─────────────────────────────────────────────────────────

class LogDiscoveryEngine:
    """
    Discover RMM log files in a given path.

    Handles plain directories, ZIP files, and individual files.
    Uses a two-pass strategy:

    1. **Filename matching** (fast) -- compares against ``FILE_PATTERNS``.
    2. **Content-signature verification** (slower) -- reads first N lines
       of ambiguous files to positively identify the producing RMM tool.

    Nested archives found during the walk are **ignored** — only the
    top-level input path is extracted if it is an archive.
    """

    def __init__(self, target_os: TargetOS = TargetOS.AUTO) -> None:
        self._archive_handler = ArchiveHandler()
        self._target_os = target_os
        self._skip_dirs: set[str] = set()      # populated in discover()
        self._resolved_os: TargetOS = target_os
        self.input_hash: str = ""               # SHA-256 of original archive

    # ── Public API ────────────────────────────────────────────────────────

    def discover(
        self,
        input_path: str,
        rmm_filter: list[str] | None = None,
    ) -> list[DiscoveredFile]:
        """
        Discover RMM log files in *input_path*.

        Parameters
        ----------
        input_path:
            A directory, ZIP file, or single file path.
        rmm_filter:
            Optional list of RMM names to restrict the search to
            (e.g. ``["AnyDesk", "TeamViewer"]``).

        Returns
        -------
        list[DiscoveredFile]
            All discovered files, sorted by RMM type then filepath.
        """
        results: list[DiscoveredFile] = []

        if os.path.isfile(input_path):
            if self._archive_handler.is_archive(input_path):
                # Hash the original evidence file for chain-of-custody.
                self.input_hash = _sha256_file(input_path)
                logger.info(
                    "Evidence hash (SHA-256): %s  file: %s",
                    self.input_hash, input_path,
                )
                try:
                    tmp_dir = self._archive_handler.extract(input_path)
                    results.extend(self._discover_in_directory(tmp_dir, rmm_filter))
                except Exception as exc:
                    logger.error("Failed to extract archive %s: %s", input_path, exc)
            else:
                match = self._match_file(input_path, rmm_filter)
                if match:
                    results.append(match)
        elif os.path.isdir(input_path):
            results.extend(self._discover_in_directory(input_path, rmm_filter))
        else:
            logger.warning("Input path does not exist: %s", input_path)

        results.sort(key=lambda d: (d.rmm_type, d.hostname, d.user_account, d.filepath))
        return results

    def summary(self, discovered: list[DiscoveredFile]) -> str:
        """Generate a human-readable summary of discovered files."""
        if not discovered:
            return "No RMM log files discovered."

        by_rmm: dict[str, list[DiscoveredFile]] = {}
        for d in discovered:
            by_rmm.setdefault(d.rmm_type, []).append(d)

        total_size = sum(d.size_bytes for d in discovered)
        lines: list[str] = [
            f"Discovered {len(discovered)} RMM log file(s) "
            f"({_human_size(total_size)}) across {len(by_rmm)} tool(s):",
            "",
        ]

        for rmm_name in sorted(by_rmm):
            files = by_rmm[rmm_name]
            rmm_size = sum(f.size_bytes for f in files)
            lines.append(f"  {rmm_name}: {len(files)} file(s) ({_human_size(rmm_size)})")
            for f in files:
                conf = f"[{f.confidence}]" if f.confidence else ""
                host = f" (host: {f.hostname})" if f.hostname else ""
                user = f" (user: {f.user_account})" if f.user_account else ""
                lines.append(
                    f"    - {f.filename} ({_human_size(f.size_bytes)}) "
                    f"{conf}{host}{user}"
                )
            lines.append("")

        return "\n".join(lines)

    def cleanup(self) -> None:
        """Release all temporary resources (extracted archives)."""
        self._archive_handler.cleanup()

    # ── Private helpers ──────────────────────────────────────────────────

    def _discover_in_directory(
        self,
        dirpath: str,
        rmm_filter: list[str] | None,
    ) -> list[DiscoveredFile]:
        """Recursively search *dirpath* for RMM logs using os.scandir."""
        results: list[DiscoveredFile] = []

        # Resolve OS if AUTO.
        if self._target_os == TargetOS.AUTO:
            self._resolved_os = _detect_os_from_path(dirpath)
            logger.info("Auto-detected target OS: %s", self._resolved_os.value)
        else:
            self._resolved_os = self._target_os

        self._skip_dirs = _skip_dirs_for_os(self._resolved_os)

        # Detect KAPE structure once at the top level.
        is_kape = detect_kape_output(dirpath)
        kape_hostname = ""
        if is_kape:
            kape_hostname = extract_hostname_from_kape(dirpath)
            logger.info(
                "Detected KAPE output structure at %s (hostname=%s)",
                dirpath,
                kape_hostname or "<unknown>",
            )

        self._walk_scandir(dirpath, rmm_filter, results, kape_hostname)
        return results

    def _walk_scandir(
        self,
        dirpath: str,
        rmm_filter: list[str] | None,
        results: list[DiscoveredFile],
        kape_hostname: str,
    ) -> None:
        """Recursive walk — matches files only, never extracts nested archives."""
        try:
            with os.scandir(dirpath) as it:
                entries = list(it)
        except (OSError, PermissionError) as exc:
            logger.debug("Cannot scan %s: %s", dirpath, exc)
            return

        dirs: list[str] = []
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.lower() in self._skip_dirs:
                        logger.debug("Skipping system directory: %s", entry.path)
                        continue
                    dirs.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    match = self._match_file(entry.path, rmm_filter)
                    if match:
                        if kape_hostname and not match.hostname:
                            match.hostname = kape_hostname
                        results.append(match)
            except OSError as exc:
                logger.debug("Error inspecting %s: %s", entry.path, exc)

        for d in dirs:
            self._walk_scandir(d, rmm_filter, results, kape_hostname)

    def _match_file(
        self,
        filepath: str,
        rmm_filter: list[str] | None,
    ) -> Optional[DiscoveredFile]:
        """
        Check if a file matches any RMM pattern.

        Strategy:
        1. Try exact / glob filename match against FILE_PATTERNS  -> high confidence.
        2. If the filename matches a generic pattern shared by
           multiple RMMs (e.g. ``*.log``), verify with content
           signatures -> medium confidence.
        3. Check path components for RMM-related directory names -> low confidence.
        """
        filename = os.path.basename(filepath)

        try:
            size_bytes = os.path.getsize(filepath)
        except OSError:
            size_bytes = 0

        # Skip empty files and very large non-log files (>500 MB).
        if size_bytes == 0:
            return None
        if size_bytes > 500 * 1024 * 1024:
            logger.debug("Skipping oversized file: %s (%s)", filepath, _human_size(size_bytes))
            return None

        # ── Pass 1: filename match ───────────────────────────────────────
        exact_matches: list[str] = []
        generic_matches: list[str] = []

        for rmm_name, patterns in FILE_PATTERNS.items():
            if rmm_filter and rmm_name not in rmm_filter:
                continue
            for pattern in patterns:
                if fnmatch.fnmatch(filename, pattern):
                    if pattern in ("*.log",):
                        generic_matches.append(rmm_name)
                    else:
                        exact_matches.append(rmm_name)

        hostname, user_account = _infer_host_and_user(
            filepath, self._resolved_os,
        )

        # Unique exact match -> high confidence.
        if len(exact_matches) == 1:
            return DiscoveredFile(
                filepath=filepath,
                rmm_type=exact_matches[0],
                filename=filename,
                hostname=hostname,
                user_account=user_account,
                confidence="high",
                size_bytes=size_bytes,
            )

        # Multiple exact matches or only generic matches -> verify content.
        candidates = exact_matches or generic_matches
        if candidates:
            identified = identify_rmm(filepath)
            if identified and (not rmm_filter or identified in rmm_filter):
                conf = "high" if identified in exact_matches else "medium"
                return DiscoveredFile(
                    filepath=filepath,
                    rmm_type=identified,
                    filename=filename,
                    hostname=hostname,
                    user_account=user_account,
                    confidence=conf,
                    size_bytes=size_bytes,
                )

        # ── Pass 2: path-based heuristic (directory name hints) ──────────
        path_lower = filepath.lower().replace("\\", "/")
        os_key = self._resolved_os.value
        for rmm_name, os_hints in DIR_HINTS.items():
            if rmm_filter and rmm_name not in rmm_filter:
                continue
            # Use OS-specific hints + common hints.
            hints = os_hints.get(os_key, []) + os_hints.get("common", [])
            for hint in hints:
                if hint in path_lower:
                    _, ext = os.path.splitext(filename)
                    if ext.lower() in (
                        ".log", ".txt", ".trace", ".db", ".sqlite",
                        ".config", ".conf", ".json", ".xml", "",
                    ):
                        return DiscoveredFile(
                            filepath=filepath,
                            rmm_type=rmm_name,
                            filename=filename,
                            hostname=hostname,
                            user_account=user_account,
                            confidence="low",
                            size_bytes=size_bytes,
                        )

        return None


# ── Path analysis utilities ──────────────────────────────────────────────────

def _infer_host_and_user(
    filepath: str, target_os: TargetOS = TargetOS.WINDOWS,
) -> tuple[str, str]:
    """
    Infer hostname and user account from the path.

    Handles KAPE-like layouts (Windows)::

        <hostname>/C/Users/<user>/AppData/…
        D:/CASOS/<case>/<hostname>/C/Users/<user>/…

    And Linux/macOS layouts::

        <hostname>/home/<user>/…
        <hostname>/Users/<user>/…   (macOS)

    Returns ``(hostname, user_account)`` — either may be empty.
    """
    parts = filepath.replace("\\", "/").split("/")

    hostname = ""
    user_account = ""

    _generic = {
        "output", "export", "triage", "kape", "collection",
        "evidence", "artifacts", "data", "case", "forensic",
        "results", "extracted", "tmp", "temp", "casos", "",
    }

    _skip_users = {
        "public", "default", "default user", "all users",
        "defaultapppool", "nobody", "daemon", "root",
        "shared",
    }

    for i, part in enumerate(parts):
        # ── Windows: <hostname>/C/Users/… ─────────────────────────────
        if (
            len(part) == 1
            and part.isalpha()
            and i + 1 < len(parts)
            and parts[i + 1] in (
                "Users", "ProgramData", "Program Files",
                "Program Files (x86)", "Windows",
            )
        ):
            if i > 0 and not hostname:
                candidate = parts[i - 1]
                if candidate.lower() not in _generic and len(candidate) > 1:
                    hostname = candidate

        # ── Extract username: Users/<user>/ or home/<user>/ ───────────
        if part in ("Users", "home") and i + 1 < len(parts):
            candidate_user = parts[i + 1]
            if (
                candidate_user.lower() not in _skip_users
                and not candidate_user.startswith(".")
                and len(candidate_user) > 1
            ):
                user_account = candidate_user

    return hostname, user_account


# ── Evidence integrity ───────────────────────────────────────────────────────

def _sha256_file(filepath: str, chunk_size: int = 1 << 20) -> str:
    """Compute SHA-256 hash of a file (streaming, memory-safe)."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
    except OSError as exc:
        logger.warning("Cannot hash %s: %s", filepath, exc)
        return ""
    return h.hexdigest()


# ── Utility ──────────────────────────────────────────────────────────────────

def _human_size(nbytes: int) -> str:
    """Format byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}" if unit != "B" else f"{nbytes} {unit}"
        nbytes /= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} TB"
