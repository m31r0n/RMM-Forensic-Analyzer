"""
Verificador de nodos de salida TOR.
Descarga y cachea la lista oficial de exit nodes de TOR Project.
No requiere API key.
"""

from __future__ import annotations
import os
import time
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

_TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_CACHE_MAX_AGE = 86400  # 24 horas


class TorExitNodeChecker:
    """
    Descarga y cachea la lista de nodos de salida TOR.
    Recarga automáticamente si el cache tiene más de 24 horas.
    """

    def __init__(self, cache_file: str = "tor_exit_nodes.txt"):
        self._cache_path = Path(cache_file)
        self._nodes: set[str] = set()
        self._loaded = False

    def _load(self) -> None:
        """Carga la lista de nodos, descargando si es necesario."""
        if self._loaded:
            return

        # Verificar si el caché local es reciente
        if self._cache_path.exists():
            age = time.time() - self._cache_path.stat().st_mtime
            if age < _CACHE_MAX_AGE:
                self._nodes = self._read_cache()
                self._loaded = True
                return

        # Descargar lista actualizada
        self._nodes = self._download()
        self._loaded = True

    def _read_cache(self) -> set[str]:
        """Lee nodos desde el archivo de caché."""
        try:
            text = self._cache_path.read_text(encoding="utf-8")
            return {
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.startswith("#")
            }
        except OSError:
            return set()

    def _download(self) -> set[str]:
        """Descarga la lista actualizada de exit nodes."""
        if not HAS_REQUESTS:
            return set()

        try:
            r = requests.get(_TOR_LIST_URL, timeout=15)
            r.raise_for_status()
            nodes = {
                line.strip()
                for line in r.text.splitlines()
                if line.strip() and not line.startswith("#")
            }
            # Guardar caché
            try:
                self._cache_path.parent.mkdir(parents=True, exist_ok=True)
                self._cache_path.write_text(r.text, encoding="utf-8")
            except OSError:
                pass

            return nodes
        except Exception:
            # Si falla la descarga, intentar usar caché viejo
            if self._cache_path.exists():
                return self._read_cache()
            return set()

    def is_exit_node(self, ip: str) -> bool:
        """Verifica si una IP es un nodo de salida TOR."""
        self._load()
        return ip in self._nodes

    def check_ips(self, ips: list[str]) -> dict[str, bool]:
        """Verifica múltiples IPs contra la lista TOR."""
        self._load()
        return {ip: ip in self._nodes for ip in ips}

    @property
    def node_count(self) -> int:
        """Número de nodos de salida conocidos."""
        self._load()
        return len(self._nodes)

    def refresh(self) -> int:
        """Fuerza recarga de la lista. Retorna número de nodos."""
        self._loaded = False
        self._load()
        return len(self._nodes)
