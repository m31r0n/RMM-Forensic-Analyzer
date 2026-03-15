"""
Main log discovery engine.

Orchestrates directory walking, filename matching, content-signature
verification, ZIP extraction, and KAPE detection to locate RMM log
files in an arbitrary input path.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from .archive import ArchiveHandler
from .kape import detect_kape_output, extract_hostname_from_kape
from .known_paths import FILE_PATTERNS
from .signatures import identify_rmm

logger = logging.getLogger(__name__)


# ── Discovered file model ────────────────────────────────────────────────────

@dataclass
class DiscoveredFile:
    """A single RMM-related file discovered during the scan."""

    filepath: str
    rmm_type: str           # RMM name (matches RMMType.value)
    filename: str
    hostname: str = ""      # Inferred hostname (from KAPE structure, etc.)
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
    """

    def __init__(self) -> None:
        self._archive_handler = ArchiveHandler()

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

        results.sort(key=lambda d: (d.rmm_type, d.filepath))
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
                lines.append(
                    f"    - {f.filename} ({_human_size(f.size_bytes)}) "
                    f"{conf}{host}"
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
        """Lazy recursive walk using os.scandir for performance."""
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
                    dirs.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    match = self._match_file(entry.path, rmm_filter)
                    if match:
                        if kape_hostname and not match.hostname:
                            match.hostname = kape_hostname
                        results.append(match)
            except OSError as exc:
                logger.debug("Error inspecting %s: %s", entry.path, exc)

        # Recurse into subdirectories.
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
                    # Distinguish "specific" patterns (no wildcard or very
                    # specific like "ad.trace") from generic ("*.log").
                    if pattern in ("*.log",):
                        generic_matches.append(rmm_name)
                    else:
                        exact_matches.append(rmm_name)

        hostname = self._infer_hostname(filepath)

        # Unique exact match -> high confidence.
        if len(exact_matches) == 1:
            return DiscoveredFile(
                filepath=filepath,
                rmm_type=exact_matches[0],
                filename=filename,
                hostname=hostname,
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
                    confidence=conf,
                    size_bytes=size_bytes,
                )

        # ── Pass 2: path-based heuristic ────────────────────────────────
        path_lower = filepath.lower().replace("\\", "/")
        _rmm_dir_hints: dict[str, list[str]] = {
            "AnyDesk": ["anydesk"],
            "TeamViewer": ["teamviewer"],
            "ScreenConnect": ["screenconnect", "connectwise control"],
            "Chrome Remote Desktop": ["chrome remote desktop", "chromoting"],
            "Splashtop": ["splashtop"],
            "RustDesk": ["rustdesk"],
        }
        for rmm_name, hints in _rmm_dir_hints.items():
            if rmm_filter and rmm_name not in rmm_filter:
                continue
            for hint in hints:
                if hint in path_lower:
                    # Only accept if the file has a plausible extension.
                    _, ext = os.path.splitext(filename)
                    if ext.lower() in (".log", ".txt", ".trace", ".db", ".config", ""):
                        return DiscoveredFile(
                            filepath=filepath,
                            rmm_type=rmm_name,
                            filename=filename,
                            hostname=hostname,
                            confidence="low",
                            size_bytes=size_bytes,
                        )

        return None

    def _infer_hostname(self, filepath: str) -> str:
        """
        Try to infer a hostname from the path structure.

        Handles KAPE-like layouts where the path contains
        ``<hostname>/C/Users/...`` or similar patterns.
        Also looks for ``Users/<username>`` to extract
        the username as a fallback.
        """
        # Normalise separators.
        parts = filepath.replace("\\", "/").split("/")

        # Look for a KAPE-like pattern: <something>/C/Users/...
        for i, part in enumerate(parts):
            if (
                len(part) == 1
                and part.isalpha()
                and i + 1 < len(parts)
                and parts[i + 1] in ("Users", "ProgramData", "Program Files", "Windows")
            ):
                if i > 0:
                    candidate = parts[i - 1]
                    _generic = {
                        "output", "export", "triage", "kape", "collection",
                        "evidence", "artifacts", "data", "case", "forensic",
                        "results", "extracted", "tmp", "temp", "",
                    }
                    if candidate.lower() not in _generic and len(candidate) > 1:
                        return candidate
                break

        return ""


# ── Utility ──────────────────────────────────────────────────────────────────

def _human_size(nbytes: int) -> str:
    """Format byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if abs(nbytes) < 1024:
            return f"{nbytes:.1f} {unit}" if unit != "B" else f"{nbytes} {unit}"
        nbytes /= 1024  # type: ignore[assignment]
    return f"{nbytes:.1f} TB"
