"""
Parser wrapper para AnyDesk que convierte los resultados legacy
(TraceResult, Session, Connection) al modelo unificado multi-RMM
(ParseResult, RMMSession, RMMConnection).
"""

from __future__ import annotations
import os
import re
from dataclasses import asdict
from typing import Any, ClassVar

from ..base import BaseParser
from ...models.base import (
    RMMType,
    ParseResult,
    RMMSession,
    RMMConnection,
    ConnectionDirection,
)
from ..registry import ParserRegistry

# Internal parsers (producen objetos legacy)
from .ad_trace import parse_ad_trace
from .connection_trace import parse_connection_trace

# Legacy models para type hints
from .legacy_models import (
    Session as LegacySession,
    Connection as LegacyConnection,
    TraceResult,
    Permission as LegacyPermission,
    ClipboardEvent as LegacyClipboardEvent,
    DesktopSwitch as LegacyDesktopSwitch,
)


# ─── Patrones de identificación ──────────────────────────────────────────────

_ANYDESK_FILENAMES = {"ad.trace", "ad_svc.trace", "connection_trace.txt"}

_ANYDESK_LOG_PATTERN = re.compile(
    r"^\w+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\w+\s+\d+\s+\d+",
)

_CONN_TRACE_PATTERN = re.compile(
    r"^(Incoming|Outgoing)\s+\d{4}-\d{2}-\d{2}",
)


# ─── Serialización de objetos legacy para extras ─────────────────────────────

def _serialize_permissions(perms: dict[str, LegacyPermission]) -> list[dict[str, Any]]:
    """Serializa el dict de permisos legacy a lista de dicts."""
    result = []
    for name, perm in perms.items():
        result.append({
            "name":      perm.name,
            "enabled":   perm.enabled,
            "allowed":   perm.allowed,
            "forbidden": perm.forbidden,
            "disabled":  perm.disabled,
            "supported": perm.supported,
            "raw":       perm.raw,
        })
    return result


def _serialize_clipboard_relays(relays: list[LegacyClipboardEvent]) -> list[dict[str, Any]]:
    """Serializa eventos de clipboard legacy a lista de dicts."""
    return [
        {
            "dt":    e.dt.isoformat() if e.dt else None,
            "files": e.files,
            "bulk":  e.bulk,
        }
        for e in relays
    ]


def _serialize_desktop_switches(switches: list[LegacyDesktopSwitch]) -> list[dict[str, Any]]:
    """Serializa eventos de escritorio legacy a lista de dicts."""
    return [
        {
            "dt":        s.dt.isoformat() if s.dt else None,
            "from_desk": s.from_desk,
            "to_desk":   s.to_desk,
        }
        for s in switches
    ]


# ─── Conversión legacy → unificado ───────────────────────────────────────────

def _convert_session(
    session: LegacySession,
    hostname: str = "",
    source_file: str = "",
) -> RMMSession:
    """Convierte un Session legacy a RMMSession unificado."""
    return RMMSession(
        idx=session.idx,
        rmm_type=RMMType.ANYDESK,
        remote_id=session.remote_id,
        alias=session.alias,
        start_dt=session.start_dt,
        end_dt=session.end_dt,
        duration_sec=session.duration_sec,
        hostname=hostname,
        source_file=source_file,
        remote_version=session.remote_version,
        remote_os=session.remote_os,
        # Indicadores de actividad normalizados
        file_transfers=session.file_offers_accepted,
        clipboard_events=len(session.clipboard_relays),
        clipboard_max_files=session.clipboard_bulk,
        text_transfers=session.text_relays,
        elevated=session.elevated,
        authenticated=session.authenticated,
        # IPs públicas
        public_ips=session.all_ips,
        # Riesgo
        risk=session.risk,
        risk_score=session.risk_score,
        risk_reasons=session.risk_reasons,
        # Datos AnyDesk-específicos
        extras={
            "fpr":                session.fpr,
            "features":           session.features,
            "route_type":         session.route_type,
            "conn_flags":         session.conn_flags,
            "perm_profile":       session.perm_profile,
            "no_password":        session.no_password,
            "perms":              _serialize_permissions(session.perms),
            "remote_caps":        session.remote_caps,
            "desktop_switches":   _serialize_desktop_switches(session.desktop_switches),
            "clipboard_relays":   _serialize_clipboard_relays(session.clipboard_relays),
            "winlogon_switches":  session.winlogon_switches,
            "minimized":          session.minimized,
            "tcp_tunnel_active":  session.tcp_tunnel_active,
            "unpaid":             session.unpaid,
            "close_reason":       session.close_reason,
            "paste_events":       session.paste_events,
            "relay_file_events":  session.relay_file_events,
            "ft_src_sessions":    session.ft_src_sessions,
            "ft_sink_sessions":   session.ft_sink_sessions,
            "relay_ips":          session.relay_ips,
            "external_ips":       session.external_ips,
            "candidate_ips":      session.candidate_ips,
            "pid":                session.pid,
        },
    )


def _convert_connection(
    conn: LegacyConnection,
    hostname: str = "",
) -> RMMConnection:
    """Convierte un Connection legacy a RMMConnection unificado."""
    if conn.direction == "Incoming":
        direction = ConnectionDirection.INCOMING
    elif conn.direction == "Outgoing":
        direction = ConnectionDirection.OUTGOING
    else:
        direction = ConnectionDirection.UNKNOWN

    return RMMConnection(
        rmm_type=RMMType.ANYDESK,
        direction=direction,
        datetime=conn.datetime,
        dt_str=conn.dt_str,
        user=conn.user,
        remote_id=conn.remote_id,
        alias=conn.alias,
        source_file=conn.source_file,
        hostname=hostname,
    )


# ─── Parser principal ────────────────────────────────────────────────────────

class AnyDeskParser(BaseParser):
    """
    Parser AnyDesk que implementa la interfaz BaseParser.

    Maneja tres tipos de archivos:
    - ad.trace: Log principal del cliente AnyDesk
    - ad_svc.trace: Log del servicio AnyDesk
    - connection_trace.txt: Historial de conexiones
    """

    rmm_type: ClassVar[RMMType] = RMMType.ANYDESK

    def can_parse(self, filepath: str) -> bool:
        """
        Verifica si el archivo es un log de AnyDesk.

        Comprueba el nombre del archivo (case-insensitive) y, si no coincide,
        lee los primeros bytes para buscar patrones de log AnyDesk.
        """
        basename = os.path.basename(filepath).lower()

        # Verificación por nombre de archivo
        if basename in _ANYDESK_FILENAMES:
            return True

        # Verificación por contenido (primeras líneas)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                head = ""
                for _ in range(10):
                    line = f.readline()
                    if not line:
                        break
                    head += line

            # Patrón de log AnyDesk (ad.trace / ad_svc.trace)
            if _ANYDESK_LOG_PATTERN.search(head):
                return True

            # Patrón de connection_trace.txt
            if _CONN_TRACE_PATTERN.search(head):
                return True

        except OSError:
            pass

        return False

    def parse(self, filepath: str, hostname: str = "") -> ParseResult:
        """
        Parsea un archivo AnyDesk y devuelve un ParseResult unificado.

        Detecta automáticamente si es un connection_trace o un ad.trace/ad_svc.trace
        y delega al parser interno correspondiente, convirtiendo después los
        resultados legacy a modelos unificados.
        """
        basename = os.path.basename(filepath).lower()
        source_file = os.path.basename(filepath)

        result = ParseResult(
            rmm_type=RMMType.ANYDESK,
            hostname=hostname,
        )

        if self._is_connection_trace(filepath, basename):
            # Parsear connection_trace.txt
            legacy_connections = parse_connection_trace(filepath)
            result.connections = [
                _convert_connection(conn, hostname=hostname)
                for conn in legacy_connections
            ]
            result.source_files.append(source_file)
        else:
            # Parsear ad.trace / ad_svc.trace
            legacy_result = parse_ad_trace(filepath)

            # Convertir sesiones
            result.sessions = [
                _convert_session(session, hostname=hostname, source_file=source_file)
                for session in legacy_result.sessions
            ]

            # Metadatos globales
            result.public_ips = legacy_result.all_public_ips
            result.tool_versions = list(legacy_result.ad_versions)
            result.os_versions = list(legacy_result.os_versions)
            result.client_ids = set(legacy_result.client_ids)
            result.error_count = legacy_result.error_count
            result.warning_count = legacy_result.warning_count
            result.total_events = legacy_result.total_events
            result.source_files = list(legacy_result.source_files)

            # Datos AnyDesk-específicos globales
            result.extras = {
                "relay_ips":     sorted(legacy_result.relay_ips),
                "external_ips":  sorted(legacy_result.external_ips),
                "candidate_ips": sorted(legacy_result.candidate_ips),
            }

        return result

    @classmethod
    def file_patterns(cls) -> list[str]:
        """Patrones glob de archivos AnyDesk."""
        return ["ad.trace", "ad_svc.trace", "connection_trace.txt"]

    @classmethod
    def known_paths_windows(cls) -> list[str]:
        """Rutas conocidas de AnyDesk en Windows."""
        return [
            r"%APPDATA%\AnyDesk",
            r"%PROGRAMDATA%\AnyDesk",
            r"%USERPROFILE%\AppData\Roaming\AnyDesk",
            r"C:\ProgramData\AnyDesk",
        ]

    @classmethod
    def known_paths_linux(cls) -> list[str]:
        """Rutas conocidas de AnyDesk en Linux."""
        return [
            "/home/*/.anydesk",
            "/root/.anydesk",
            "/etc/anydesk",
        ]

    @classmethod
    def known_paths_macos(cls) -> list[str]:
        """Rutas conocidas de AnyDesk en macOS."""
        return [
            "~/Library/Application Support/AnyDesk",
            "/Library/Application Support/AnyDesk",
        ]

    @classmethod
    def content_signatures(cls) -> list[str]:
        """Patrones regex que identifican logs de AnyDesk."""
        return [
            # Formato de log ad.trace
            r"^\w+\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\w+\s+\d+\s+\d+",
            # Líneas de sesión
            r"Incoming session request:",
            # Conexiones
            r"^(Incoming|Outgoing)\s+\d{4}-\d{2}-\d{2}",
            # Versión AnyDesk
            r"\* Version\s+[\d.]+",
        ]

    # ── Helpers privados ─────────────────────────────────────────────

    @staticmethod
    def _is_connection_trace(filepath: str, basename: str) -> bool:
        """Determina si el archivo es un connection_trace.txt."""
        if basename == "connection_trace.txt":
            return True

        # Inspeccionar contenido si el nombre no es definitivo
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for _ in range(5):
                    line = f.readline()
                    if not line:
                        break
                    if _CONN_TRACE_PATTERN.search(line.strip()):
                        return True
        except OSError:
            pass

        return False


# ─── Auto-registro ───────────────────────────────────────────────────────────

ParserRegistry.register(AnyDeskParser())
