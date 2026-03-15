"""
Gestión de configuración: carga desde config.json (local) y/o variables de entorno.
Prioridad: Variables de entorno > config.json > valores por defecto.
"""

from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Any

# Ubicación del config.json: junto al directorio del proyecto,
# o en ~/.rmm_forensic/config.json (con fallback a ~/.anydesk_forensic/)
_LOCAL_CONFIG  = Path(__file__).parent.parent / "config.json"
_GLOBAL_CONFIG = Path.home() / ".rmm_forensic" / "config.json"
_LEGACY_CONFIG = Path.home() / ".anydesk_forensic" / "config.json"

_DEFAULTS: dict[str, Any] = {
    "virustotal_api_key":     "",
    "abuseipdb_api_key":      "",
    "criminalip_api_key":     "",
    "default_output_dir":     "output_forense",
    "ip_cache_file":          "ip_cache.json",
    "max_age_days_abuseipdb": 90,
    "vt_rate_limit_sleep":    0.5,
    "theme_color":            "#1A8080",
    "tor_exit_node_cache":    "tor_exit_nodes.txt",
}

_ENV_MAP = {
    "virustotal_api_key":  "VT_API_KEY",
    "abuseipdb_api_key":   "ABUSEIPDB_API_KEY",
    "criminalip_api_key":  "CRIMINALIP_API_KEY",
}


class Config:
    """Configuración centralizada con persistencia en JSON."""

    def __init__(self) -> None:
        self._data: dict[str, Any] = dict(_DEFAULTS)
        self._path: Path = _LOCAL_CONFIG
        self._load()

    # ── Carga ─────────────────────────────────────────────────────

    def _load(self) -> None:
        """Carga en orden: defaults → config.json → variables de entorno."""
        if _LOCAL_CONFIG.exists():
            self._path = _LOCAL_CONFIG
            self._merge_file(_LOCAL_CONFIG)
        elif _GLOBAL_CONFIG.exists():
            self._path = _GLOBAL_CONFIG
            self._merge_file(_GLOBAL_CONFIG)
        elif _LEGACY_CONFIG.exists():
            self._path = _LEGACY_CONFIG
            self._merge_file(_LEGACY_CONFIG)

        for key, env_var in _ENV_MAP.items():
            val = os.environ.get(env_var, "")
            if val:
                self._data[key] = val

    def _merge_file(self, path: Path) -> None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            for k, v in raw.items():
                if not k.startswith("_"):
                    self._data[k] = v
        except (json.JSONDecodeError, OSError):
            pass

    # ── Acceso ─────────────────────────────────────────────────────

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def set(self, key: str, value: Any) -> None:
        self._data[key] = value

    @property
    def vt_key(self) -> str:
        return self._data.get("virustotal_api_key", "")

    @vt_key.setter
    def vt_key(self, v: str) -> None:
        self._data["virustotal_api_key"] = v

    @property
    def abuse_key(self) -> str:
        return self._data.get("abuseipdb_api_key", "")

    @abuse_key.setter
    def abuse_key(self, v: str) -> None:
        self._data["abuseipdb_api_key"] = v

    @property
    def criminalip_key(self) -> str:
        return self._data.get("criminalip_api_key", "")

    @criminalip_key.setter
    def criminalip_key(self, v: str) -> None:
        self._data["criminalip_api_key"] = v

    @property
    def output_dir(self) -> str:
        return self._data.get("default_output_dir", "output_forense")

    # ── Persistencia ───────────────────────────────────────────────

    def save(self, path: Path | None = None) -> Path:
        """Guarda la configuración actual en disco."""
        target = path or self._path
        target.parent.mkdir(parents=True, exist_ok=True)
        to_save = {k: v for k, v in self._data.items()}
        target.write_text(json.dumps(to_save, indent=2, ensure_ascii=False), encoding="utf-8")
        self._path = target
        return target

    def save_global(self) -> Path:
        """Guarda en ~/.rmm_forensic/config.json (persiste entre proyectos)."""
        return self.save(_GLOBAL_CONFIG)

    def save_local(self) -> Path:
        """Guarda en config.json junto al proyecto."""
        return self.save(_LOCAL_CONFIG)

    # ── Representación ─────────────────────────────────────────────

    def summary(self) -> str:
        vt  = f"{'*'*6+self.vt_key[-4:]   if len(self.vt_key)   > 6 else ('Configurada' if self.vt_key   else '— No configurada')}"
        ab  = f"{'*'*6+self.abuse_key[-4:] if len(self.abuse_key) > 6 else ('Configurada' if self.abuse_key else '— No configurada')}"
        cip = f"{'*'*6+self.criminalip_key[-4:] if len(self.criminalip_key) > 6 else ('Configurada' if self.criminalip_key else '— No configurada')}"
        return (
            f"  VT API Key:        {vt}\n"
            f"  AbuseIPDB Key:     {ab}\n"
            f"  CriminalIP Key:    {cip}\n"
            f"  Directorio sal.:   {self.output_dir}\n"
            f"  Cache IP:          {self._data.get('ip_cache_file','ip_cache.json')}\n"
            f"  Config en:         {self._path}"
        )

    def all_keys_present(self) -> bool:
        return bool(self.vt_key and self.abuse_key)


# Instancia global (importable)
cfg = Config()
