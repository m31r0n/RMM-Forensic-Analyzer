"""
Modelos base unificados para análisis forense multi-RMM.
Todos los parsers producen estos modelos normalizados.
Datos RMM-específicos van en el dict 'extras'.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any


class RMMType(Enum):
    """Tipos de herramientas RMM soportadas."""
    ANYDESK             = "AnyDesk"
    TEAMVIEWER          = "TeamViewer"
    SCREENCONNECT       = "ScreenConnect"
    CHROME_REMOTE_DESKTOP = "Chrome Remote Desktop"
    SPLASHTOP           = "Splashtop"
    RUSTDESK            = "RustDesk"


class ConnectionDirection(Enum):
    """Dirección de la conexión RMM."""
    INCOMING = "Incoming"
    OUTGOING = "Outgoing"
    UNKNOWN  = "Unknown"


# ─── Conexión normalizada ──────────────────────────────────────────────────

@dataclass
class RMMConnection:
    """Registro de conexión normalizado de cualquier herramienta RMM."""
    rmm_type:     RMMType
    direction:    ConnectionDirection
    datetime:     Optional[datetime]
    dt_str:       str
    user:         str         = ""
    remote_id:    str         = ""
    alias:        str         = ""
    source_file:  str         = ""
    hostname:     str         = ""
    duration_str: str         = ""
    extras:       dict[str, Any] = field(default_factory=dict)


# ─── Sesión normalizada ───────────────────────────────────────────────────

@dataclass
class RMMSession:
    """
    Sesión normalizada de cualquier herramienta RMM.
    Campos comunes que aplican a todos los RMMs + extras para datos específicos.
    """
    idx:            int
    rmm_type:       RMMType
    remote_id:      str
    alias:          str         = ""
    start_dt:       Optional[datetime] = None
    end_dt:         Optional[datetime] = None
    duration_sec:   Optional[int]      = None
    hostname:       str         = ""
    source_file:    str         = ""

    # Info remota
    remote_ip:      str         = ""
    remote_version: str         = ""
    remote_os:      str         = ""

    # Indicadores de actividad normalizados (comunes a todos los RMMs)
    file_transfers:     int     = 0
    clipboard_events:   int     = 0
    clipboard_max_files: int    = 0
    text_transfers:     int     = 0
    elevated:           bool    = False
    authenticated:      bool    = False

    # IPs públicas detectadas
    public_ips:     list[str]   = field(default_factory=list)

    # Riesgo (calculado post-parsing)
    risk:           str         = "BAJO"
    risk_score:     int         = 0
    risk_reasons:   list[str]   = field(default_factory=list)

    # Proximidad al incidente (calculado si hay fecha de incidente)
    incident_proximity_hours: Optional[float] = None
    incident_proximity_label: str = ""      # "24h", "3d", "7d", "fuera"
    country_classification:   str = ""      # "Informativa", "Sospechosa", ""

    # Correlación con conexión
    conn_record:    Optional[RMMConnection] = None

    # Datos RMM-específicos (permisos AnyDesk, caps remotas, etc.)
    extras:         dict[str, Any] = field(default_factory=dict)

    # ── Propiedades calculadas ────────────────────────────────────

    @property
    def all_ips(self) -> list[str]:
        return sorted(set(self.public_ips))

    def to_dict(self) -> dict:
        """Exporta la sesión como dict plano (para CSV/XLSX)."""
        return {
            "idx":                self.idx,
            "rmm_type":           self.rmm_type.value,
            "remote_id":          self.remote_id,
            "alias":              self.alias,
            "start_dt":           self.start_dt,
            "end_dt":             self.end_dt,
            "duration_sec":       self.duration_sec,
            "hostname":           self.hostname,
            "user_account":       self.extras.get("user_account", ""),
            "remote_ip":          self.remote_ip,
            "remote_version":     self.remote_version,
            "remote_os":          self.remote_os,
            "file_transfers":     self.file_transfers,
            "clipboard_events":   self.clipboard_events,
            "clipboard_max_files": self.clipboard_max_files,
            "text_transfers":     self.text_transfers,
            "elevated":           self.elevated,
            "public_ips":         " | ".join(self.public_ips),
            "risk":               self.risk,
            "risk_score":         self.risk_score,
            "risk_reasons":       " | ".join(self.risk_reasons),
            "incident_proximity": self.incident_proximity_label,
            "country_class":      self.country_classification,
        }


# ─── Resultado de parsing ─────────────────────────────────────────────────

@dataclass
class ParseResult:
    """Resultado del parsing de logs de un RMM desde una o más fuentes."""
    rmm_type:       RMMType
    sessions:       list[RMMSession]      = field(default_factory=list)
    connections:    list[RMMConnection]    = field(default_factory=list)
    public_ips:     set[str]              = field(default_factory=set)
    source_files:   list[str]             = field(default_factory=list)
    hostname:       str                   = ""

    # Metadatos
    tool_versions:  list[str]             = field(default_factory=list)
    os_versions:    list[str]             = field(default_factory=list)
    client_ids:     set[str]              = field(default_factory=set)
    error_count:    int                   = 0
    warning_count:  int                   = 0
    total_events:   int                   = 0

    # Datos RMM-específicos globales
    extras:         dict[str, Any]        = field(default_factory=dict)

    def merge(self, other: ParseResult) -> None:
        """Combina otro ParseResult del mismo RMM type."""
        self.sessions.extend(other.sessions)
        self.connections.extend(other.connections)
        self.public_ips |= other.public_ips
        self.source_files.extend(other.source_files)
        for v in other.tool_versions:
            if v not in self.tool_versions:
                self.tool_versions.append(v)
        for v in other.os_versions:
            if v not in self.os_versions:
                self.os_versions.append(v)
        self.client_ids |= other.client_ids
        self.error_count += other.error_count
        self.warning_count += other.warning_count
        self.total_events += other.total_events
