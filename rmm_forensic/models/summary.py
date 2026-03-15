"""Resumen forense agregado multi-RMM."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any

from .base import RMMType, RMMSession, RMMConnection, ParseResult


@dataclass
class ForensicSummary:
    """
    Resumen forense que agrega datos de múltiples RMMs y hosts.
    Incluye estadísticas globales, por RMM, por host, y correlación cruzada.
    """
    # Resultados por fuente
    results_by_rmm:       dict[str, ParseResult]        = field(default_factory=dict)
    results_by_hostname:  dict[str, list[ParseResult]]   = field(default_factory=dict)

    # Agregados globales
    total_connections:    int = 0
    total_sessions:       int = 0
    incoming:             int = 0
    outgoing:             int = 0
    unique_ids:           list[str]  = field(default_factory=list)
    date_range_conn:      Optional[tuple[datetime, datetime]] = None
    date_range_sessions:  Optional[tuple[datetime, datetime]] = None

    # Indicadores de actividad
    total_file_transfers: int = 0
    total_clipboard:      int = 0
    total_text_transfers: int = 0
    elevated_sessions:    int = 0
    max_clipboard_files:  int = 0

    # Distribuciones temporales
    monthly:              dict[str, int] = field(default_factory=dict)
    hourly:               dict[int, int] = field(default_factory=dict)
    risk_dist:            dict[str, int] = field(default_factory=dict)
    conn_per_id:          dict[str, int] = field(default_factory=dict)

    # Distribución por RMM
    sessions_per_rmm:     dict[str, int] = field(default_factory=dict)
    connections_per_rmm:  dict[str, int] = field(default_factory=dict)

    # Correlación cross-RMM
    cross_rmm_ips:        dict[str, list[str]] = field(default_factory=dict)  # IP → [RMM names]
    cross_rmm_sessions:   list[dict[str, Any]] = field(default_factory=list)

    # Análisis de incidente
    sessions_within_24h:  list[RMMSession] = field(default_factory=list)
    sessions_within_3d:   list[RMMSession] = field(default_factory=list)
    sessions_within_7d:   list[RMMSession] = field(default_factory=list)
    anomalous_patterns:   list[str]        = field(default_factory=list)

    # Clasificación por país
    informative_sessions: int = 0
    suspicious_sessions:  int = 0

    # ── Helpers ───────────────────────────────────────────────────

    @property
    def all_sessions(self) -> list[RMMSession]:
        """Todas las sesiones de todos los RMMs, ordenadas por fecha."""
        sessions = []
        for pr in self.results_by_rmm.values():
            sessions.extend(pr.sessions)
        return sorted(sessions, key=lambda s: s.start_dt or datetime.min)

    @property
    def all_connections(self) -> list[RMMConnection]:
        """Todas las conexiones de todos los RMMs, ordenadas por fecha."""
        conns = []
        for pr in self.results_by_rmm.values():
            conns.extend(pr.connections)
        return sorted(conns, key=lambda c: c.datetime or datetime.min)

    @property
    def all_public_ips(self) -> set[str]:
        """Todas las IPs públicas de todos los RMMs."""
        ips: set[str] = set()
        for pr in self.results_by_rmm.values():
            ips |= pr.public_ips
        return ips

    @property
    def rmm_types_found(self) -> list[str]:
        """Lista de RMMs encontrados."""
        return sorted(self.results_by_rmm.keys())

    @property
    def hostnames_found(self) -> list[str]:
        """Lista de hostnames encontrados."""
        return sorted(self.results_by_hostname.keys())
