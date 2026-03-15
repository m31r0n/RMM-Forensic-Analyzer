"""
Caché persistente de consultas de IP con TTL configurable.
Guarda en ip_cache.json para evitar llamadas duplicadas a las APIs.
"""

from __future__ import annotations
import json
import time
from pathlib import Path
from typing import Any


class IPCache:
    """
    Caché key-value persistida en JSON con TTL opcional (segundos).
    Estructura interna: {"key": {"data": {...}, "ts": 1234567890.0}}
    """

    def __init__(self, path: str = "ip_cache.json", ttl: int = 86_400 * 7) -> None:
        """
        Args:
            path: Ruta al archivo de caché.
            ttl:  Tiempo de vida en segundos (default: 7 días).
        """
        self._path = Path(path)
        self._ttl  = ttl
        self._data: dict[str, dict] = {}
        self._load()

    # ── I/O ──────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                # Compatibilidad con formato antiguo (valor plano sin ts)
                for k, v in raw.items():
                    if isinstance(v, dict) and "ts" in v:
                        self._data[k] = v
                    else:
                        self._data[k] = {"data": v, "ts": 0.0}
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def save(self) -> None:
        """Persiste la caché en disco."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass

    # ── Operaciones ──────────────────────────────────────────────────────────

    def get(self, key: str) -> Any | None:
        """Devuelve el valor si está en caché y no ha expirado. Si no, None."""
        entry = self._data.get(key)
        if entry is None:
            return None
        if self._ttl > 0 and (time.time() - entry.get("ts", 0)) > self._ttl:
            del self._data[key]
            return None
        return entry.get("data")

    def set(self, key: str, value: Any) -> None:
        """Almacena un valor con timestamp actual."""
        self._data[key] = {"data": value, "ts": time.time()}

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def clear(self) -> int:
        """Elimina toda la caché. Devuelve número de entradas eliminadas."""
        n = len(self._data)
        self._data.clear()
        self.save()
        return n

    def purge_expired(self) -> int:
        """Elimina entradas expiradas. Devuelve número eliminado."""
        if self._ttl <= 0:
            return 0
        now   = time.time()
        keys  = [k for k, v in self._data.items() if (now - v.get("ts", 0)) > self._ttl]
        for k in keys:
            del self._data[k]
        if keys:
            self.save()
        return len(keys)

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, key: str) -> bool:
        return self.get(key) is not None

    def stats(self) -> str:
        n     = len(self._data)
        valid = sum(
            1 for v in self._data.values()
            if self._ttl <= 0 or (time.time() - v.get("ts", 0)) <= self._ttl
        )
        return f"{n} entradas ({valid} válidas, {n - valid} expiradas) — {self._path}"
