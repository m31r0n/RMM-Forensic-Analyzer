"""
Modelos de datos legacy específicos de AnyDesk.

Estos dataclasses son usados internamente por ad_trace.py y connection_trace.py.
El wrapper parser.py convierte estos objetos a los modelos unificados
(RMMSession, RMMConnection, ParseResult) definidos en rmm_forensic.models.base.

Copiados desde el legacy rmm_forensic/models.py para desacoplar los parsers
internos del archivo monolítico original.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ─── Conexión (connection_trace.txt) ────────────────────────────────────────

@dataclass
class Connection:
    direction:    str
    datetime:     Optional[datetime]
    dt_str:       str
    user:         str
    remote_id:    str
    alias:        str = ""
    source_file:  str = ""


# ─── Permisos de sesión ──────────────────────────────────────────────────────

@dataclass
class Permission:
    name:      str
    enabled:   bool = False
    allowed:   bool = False
    forbidden: bool = False
    disabled:  bool = False
    supported: bool = False
    raw:       str  = ""


# ─── Evento clipboard ────────────────────────────────────────────────────────

@dataclass
class ClipboardEvent:
    dt:    Optional[datetime]
    files: int
    bulk:  bool = False          # True si files > 20


# ─── Evento de escritorio (Winlogon) ─────────────────────────────────────────

@dataclass
class DesktopSwitch:
    dt:        Optional[datetime]
    from_desk: str
    to_desk:   str

    @property
    def to_winlogon(self) -> bool:
        return self.to_desk.lower() == "winlogon"


# ─── Sesión (ad.trace) ───────────────────────────────────────────────────────

@dataclass
class Session:
    idx:          int
    remote_id:    str
    alias:        str        = ""
    fpr:          str        = ""
    start_dt:     Optional[datetime] = None
    end_dt:       Optional[datetime] = None
    duration_sec: Optional[int]      = None

    # Metadatos de conexión
    features:     list[str]  = field(default_factory=list)
    route_type:   str        = ""
    conn_flags:   str        = ""
    remote_os:    str        = ""
    remote_version: str      = ""
    remote_caps:  list[str]  = field(default_factory=list)
    perm_profile: str        = ""
    no_password:  bool       = False
    unpaid:       bool       = False
    close_reason: str        = ""
    minimized:    bool       = False
    tcp_tunnel_active: bool  = False
    authenticated: bool      = False
    elevated:     bool       = False

    # Permisos
    perms:        dict[str, Permission] = field(default_factory=dict)

    # Eventos de archivo/portapapeles
    file_offers_accepted: int = 0
    paste_events:         int = 0
    text_relays:          int = 0
    relay_file_events:    int = 0
    clipboard_relays:     list[ClipboardEvent] = field(default_factory=list)
    ft_src_sessions:      list[str] = field(default_factory=list)
    ft_sink_sessions:     list[str] = field(default_factory=list)

    # Eventos Winlogon
    desktop_switches: list[DesktopSwitch] = field(default_factory=list)

    # IPs de sesión
    relay_ips:     list[str] = field(default_factory=list)
    external_ips:  list[str] = field(default_factory=list)
    candidate_ips: list[str] = field(default_factory=list)

    # Riesgo (calculado post-parsing)
    risk:         str       = "BAJO"
    risk_score:   int       = 0
    risk_reasons: list[str] = field(default_factory=list)

    # Referencia a registro de connection_trace correlacionado
    conn_record:  Optional[Connection] = None
    pid:          int = 0

    # ── Propiedades calculadas ────────────────────────────────────

    @property
    def clipboard_bulk(self) -> int:
        """Máximo de archivos en un único evento de clipboard."""
        return max((e.files for e in self.clipboard_relays), default=0)

    @property
    def winlogon_switches(self) -> int:
        """Número de cambios hacia Winlogon."""
        return sum(1 for e in self.desktop_switches if e.to_winlogon)

    @property
    def all_ips(self) -> list[str]:
        return sorted(set(self.relay_ips + self.external_ips + self.candidate_ips))

    def to_dict(self) -> dict:
        """Exporta la sesión como dict plano (para CSV/XLSX)."""
        return {
            "idx":            self.idx,
            "remote_id":      self.remote_id,
            "alias":          self.alias,
            "fpr":            self.fpr,
            "start_dt":       self.start_dt,
            "end_dt":         self.end_dt,
            "duration_sec":   self.duration_sec,
            "features":       ", ".join(self.features),
            "route_type":     self.route_type,
            "conn_flags":     self.conn_flags,
            "remote_os":      self.remote_os,
            "remote_version": self.remote_version,
            "perm_profile":   self.perm_profile,
            "no_password":    self.no_password,
            "file_offers":    self.file_offers_accepted,
            "pastes":         self.paste_events,
            "clipboard_bulk": self.clipboard_bulk,
            "text_relays":    self.text_relays,
            "winlogon":       self.winlogon_switches,
            "elevated":       self.elevated,
            "minimized":      self.minimized,
            "tcp_tunnel":     self.tcp_tunnel_active,
            "close_reason":   self.close_reason,
            "relay_ips":      " | ".join(self.relay_ips),
            "external_ips":   " | ".join(self.external_ips),
            "risk":           self.risk,
            "risk_score":     self.risk_score,
            "risk_reasons":   " | ".join(self.risk_reasons),
        }


# ─── Resultado del trace ─────────────────────────────────────────────────────

@dataclass
class TraceResult:
    sessions:      list[Session]   = field(default_factory=list)
    relay_ips:     set[str]        = field(default_factory=set)
    external_ips:  set[str]        = field(default_factory=set)
    candidate_ips: set[str]        = field(default_factory=set)
    client_ids:    set[str]        = field(default_factory=set)
    ad_versions:   list[str]       = field(default_factory=list)
    os_versions:   list[str]       = field(default_factory=list)
    error_count:   int             = 0
    warning_count: int             = 0
    total_events:  int             = 0
    source_files:  list[str]       = field(default_factory=list)

    @property
    def all_public_ips(self) -> set[str]:
        return self.relay_ips | self.external_ips | self.candidate_ips
