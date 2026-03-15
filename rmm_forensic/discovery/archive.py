"""
ZIP and archive handling for the log discovery engine.

Provides a context-manager that extracts archives to temporary
directories and cleans them up on exit.

Supports standard ZIP (via zipfile), and falls back to 7-Zip CLI
or PowerShell Expand-Archive when the built-in module cannot handle
the compression method (e.g. DEFLATE64, PPMd).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Extensions we recognise as archives (case-insensitive).
_ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar"}


def _find_7z() -> str | None:
    """Return the path to the 7z executable, or *None*."""
    # Check common Windows install locations first.
    candidates = [
        shutil.which("7z"),
        shutil.which("7za"),
        r"C:\Program Files\7-Zip\7z.exe",
        r"C:\Program Files (x86)\7-Zip\7z.exe",
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return c
    return None


class ArchiveHandler:
    """Extract ZIP / 7z / RAR archives to temporary directories for analysis."""

    def __init__(self) -> None:
        self._temp_dirs: list[str] = []

    # ── Public API ────────────────────────────────────────────────────────

    @staticmethod
    def is_archive(filepath: str) -> bool:
        """Return *True* if *filepath* is a valid, supported archive.

        Validates using magic bytes — never trusts extension alone.
        This avoids false positives from Windows ``$Recycle.Bin``
        metadata files (``$I*.zip``) and other non-archive files
        that happen to have an archive extension.
        """
        try:
            size = os.path.getsize(filepath)
        except OSError:
            return False
        # Skip tiny files (< 22 bytes is the minimum ZIP size).
        if size < 22:
            return False

        ext = os.path.splitext(filepath)[1].lower()

        # ZIP: rely on zipfile.is_zipfile which checks magic bytes.
        if ext == ".zip" or ext == "":
            try:
                return zipfile.is_zipfile(filepath)
            except OSError:
                return False

        # 7z: magic bytes 37 7A BC AF 27 1C
        if ext == ".7z":
            try:
                with open(filepath, "rb") as f:
                    return f.read(6) == b"7z\xbc\xaf\x27\x1c"
            except OSError:
                return False

        # RAR: magic bytes "Rar!"
        if ext == ".rar":
            try:
                with open(filepath, "rb") as f:
                    return f.read(4) == b"Rar!"
            except OSError:
                return False

        # Unknown extension — try ZIP magic as last resort.
        try:
            return zipfile.is_zipfile(filepath)
        except OSError:
            return False

    def extract(self, filepath: str) -> str:
        """
        Extract an archive to a fresh temporary directory.

        Returns the path to the temporary directory containing the
        extracted files.  The directory is tracked and will be removed
        when :meth:`cleanup` is called (or when the context manager
        exits).

        Tries (in order):
        1. Python ``zipfile`` (standard ZIP compression methods).
        2. External ``7z`` CLI (DEFLATE64, PPMd, 7z, RAR, …).
        3. PowerShell ``Expand-Archive`` (last resort, ZIP only).

        Raises
        ------
        RuntimeError
            If none of the extraction methods succeed.
        """
        tmp_dir = tempfile.mkdtemp(prefix="rmm_forensic_")
        self._temp_dirs.append(tmp_dir)

        logger.info("Extracting %s -> %s", filepath, tmp_dir)

        ext = os.path.splitext(filepath)[1].lower()

        # ── Attempt 1: Python zipfile (fast, but limited methods) ─────
        if ext in (".zip", "") or zipfile.is_zipfile(filepath):
            try:
                self._extract_zipfile(filepath, tmp_dir)
                return tmp_dir
            except NotImplementedError as exc:
                logger.warning(
                    "zipfile cannot handle %s (%s), trying fallbacks…",
                    filepath, exc,
                )
            except (zipfile.BadZipFile, OSError) as exc:
                logger.warning(
                    "zipfile failed for %s (%s), trying fallbacks…",
                    filepath, exc,
                )

        # ── Attempt 2: 7-Zip CLI ─────────────────────────────────────
        sevenz = _find_7z()
        if sevenz:
            try:
                self._extract_7z(sevenz, filepath, tmp_dir)
                return tmp_dir
            except Exception as exc:
                logger.warning("7z extraction failed for %s: %s", filepath, exc)
        else:
            logger.debug("7-Zip not found on this system")

        # ── Attempt 3: PowerShell Expand-Archive (ZIP only) ───────────
        if ext == ".zip" or zipfile.is_zipfile(filepath):
            try:
                self._extract_powershell(filepath, tmp_dir)
                return tmp_dir
            except Exception as exc:
                logger.warning(
                    "PowerShell Expand-Archive failed for %s: %s",
                    filepath, exc,
                )

        raise RuntimeError(
            f"No se pudo extraer el archivo {filepath}. "
            "Instale 7-Zip (https://7-zip.org) para soportar "
            "métodos de compresión avanzados."
        )

    def cleanup(self) -> None:
        """Remove all temporary directories created by :meth:`extract`."""
        for tmp_dir in self._temp_dirs:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                logger.debug("Cleaned up temp dir: %s", tmp_dir)
            except OSError as exc:
                logger.warning("Failed to remove temp dir %s: %s", tmp_dir, exc)
        self._temp_dirs.clear()

    # ── Context manager ──────────────────────────────────────────────────

    def __enter__(self) -> ArchiveHandler:
        return self

    def __exit__(self, *args: object) -> None:
        self.cleanup()

    # ── Private extraction strategies ────────────────────────────────────

    @staticmethod
    def _extract_zipfile(filepath: str, tmp_dir: str) -> None:
        """Extract using Python's built-in ``zipfile`` module."""
        with zipfile.ZipFile(filepath, "r") as zf:
            for member in zf.infolist():
                # Guard against path-traversal (zip-slip) attacks.
                target = Path(tmp_dir) / member.filename
                resolved = target.resolve()
                if not str(resolved).startswith(str(Path(tmp_dir).resolve())):
                    logger.warning(
                        "Skipping suspicious zip member: %s", member.filename
                    )
                    continue
                zf.extract(member, tmp_dir)

    @staticmethod
    def _extract_7z(sevenz: str, filepath: str, tmp_dir: str) -> None:
        """Extract using the 7-Zip CLI."""
        result = subprocess.run(
            [sevenz, "x", filepath, f"-o{tmp_dir}", "-y", "-bso0", "-bsp0"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"7z exit code {result.returncode}: {result.stderr.strip()}"
            )

    @staticmethod
    def _extract_powershell(filepath: str, tmp_dir: str) -> None:
        """Extract a ZIP using PowerShell ``Expand-Archive``."""
        # Use .NET's System.IO.Compression for better method support.
        ps_script = (
            "Add-Type -AssemblyName System.IO.Compression.FileSystem; "
            "[System.IO.Compression.ZipFile]::ExtractToDirectory("
            f"'{filepath}', '{tmp_dir}')"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"PowerShell exit code {result.returncode}: "
                f"{result.stderr.strip()}"
            )
