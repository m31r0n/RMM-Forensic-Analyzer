"""
ZIP and archive handling for the log discovery engine.

Provides a context-manager that extracts archives to temporary
directories and cleans them up on exit.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import zipfile
from pathlib import Path

logger = logging.getLogger(__name__)


class ArchiveHandler:
    """Extract ZIP archives to temporary directories for analysis."""

    def __init__(self) -> None:
        self._temp_dirs: list[str] = []

    # ── Public API ────────────────────────────────────────────────────────

    @staticmethod
    def is_archive(filepath: str) -> bool:
        """Return *True* if *filepath* is a supported archive (ZIP)."""
        try:
            return zipfile.is_zipfile(filepath)
        except OSError:
            return False

    def extract(self, filepath: str) -> str:
        """
        Extract a ZIP archive to a fresh temporary directory.

        Returns the path to the temporary directory containing the
        extracted files.  The directory is tracked and will be removed
        when :meth:`cleanup` is called (or when the context manager
        exits).

        Raises
        ------
        zipfile.BadZipFile
            If the file is not a valid ZIP archive.
        OSError
            If extraction fails for filesystem reasons.
        """
        tmp_dir = tempfile.mkdtemp(prefix="rmm_forensic_")
        self._temp_dirs.append(tmp_dir)

        logger.info("Extracting %s -> %s", filepath, tmp_dir)

        with zipfile.ZipFile(filepath, "r") as zf:
            # Guard against path-traversal (zip-slip) attacks.
            for member in zf.infolist():
                target = Path(tmp_dir) / member.filename
                resolved = target.resolve()
                if not str(resolved).startswith(str(Path(tmp_dir).resolve())):
                    logger.warning(
                        "Skipping suspicious zip member: %s", member.filename
                    )
                    continue
                zf.extract(member, tmp_dir)

        return tmp_dir

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
