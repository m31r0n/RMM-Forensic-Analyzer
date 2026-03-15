"""
Parser forense profundo para ad.trace y ad_svc.trace.

Extrae todas las entidades forenses conocidas:
    - Metadatos de sesión (inicio, fin, duración, features, ruta)
    - Permisos por sesión y perfil (con indicador hasPw)
    - Transferencias de archivo y eventos de portapapeles
    - Cambios de escritorio (Default ↔ Winlogon)
    - Elevación de privilegios (Elevated backend)
    - IPs (relay, externas, candidatas)
    - Capacidades remotas declaradas
    - Versión AnyDesk y OS local/remoto
    - Tipo de conexión (direct/tunnel/relay, paid/unpaid)
"""

from __future__ import annotations
import os
import re
from datetime import datetime
from collections import defaultdict

from .legacy_models import (
    Session, TraceResult, Permission, ClipboardEvent, DesktopSwitch
)
from ...utils import detect_encoding, is_private, cprint

try:
    from colorama import Fore
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = ""

# ─── Patrones regex ──────────────────────────────────────────────────────────

_RE_LOG = re.compile(
    r"^(?P<level>\w+)\s+(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)"
    r"\s+(?P<comp>\w+)\s+(?P<pid>\d+)\s+(?P<tid>\d+)\s*(?:\d+)?\s+"
    r"(?P<mod>[^\s-]+)\s+-\s+(?P<msg>.+)$"
)

# Sesión / identidad
_RE_SESS_REQ = re.compile(r"Incoming session request:\s+(.+?)\s+\((\d+)\)")
_RE_CID      = re.compile(r"Client-ID:\s+(\d+)")
_RE_FPR      = re.compile(r"FPR:\s+([a-f0-9]+)")

# Metadatos
_RE_FEAT    = re.compile(r"Session features:\s+(.+)")
_RE_ROS     = re.compile(r"Remote OS:\s+(\w+),?\s*Connection flags:\s+(.+)")
_RE_RVER    = re.compile(r"Remote version:\s+([\d.]+)")
_RE_ROUTE   = re.compile(r"Route type:\s+(.+)")
_RE_AD_VER  = re.compile(r"\* Version\s+([\d.]+)")
_RE_OS_INFO = re.compile(r"OS is (Windows[^\r\n.]+)")
_RE_CLOSE   = re.compile(r"Session closed (?:by remote side|locally):\s+(\w+)")
_RE_UNPAID  = re.compile(r"Unpaid session")
_RE_MINIMIZE= re.compile(r"Starting session with minimized window")
_RE_TCP_TUN = re.compile(r"tcp_tunnel.*enabled|tcp.*tunnel.*active", re.I)

# Permisos
_RE_PERM    = re.compile(r"Sending ([\w][\w\s]+?)\s+\(\d+\) permissions\s+\(([^)]+)\)")
_RE_PROFILE = re.compile(r"Selecting Profile:\s+([^,]+),\s*hasPw:\s*([YN])")

# Autenticación
_RE_AUTH    = re.compile(r"Authenticated by local user")
_RE_ELEV    = re.compile(r"Elevated backend requested")
_RE_RCAPS   = re.compile(r"Remote caps:\s+(.+)")

# Portapapeles y archivos
_RE_FILE_OFF  = re.compile(r"File offer accepted")
_RE_PASTE     = re.compile(r"Pasting the object")
_RE_TXT_RELAY = re.compile(r"Relaying text offers")
_RE_REL_FILE  = re.compile(r"Relaying file offers")
_RE_CLIP_N    = re.compile(r"Found (\d+) files?")
_RE_FT_SRC    = re.compile(r"app\.ft_src_session - New session \(([a-f0-9]+)\)")
_RE_FT_SINK   = re.compile(r"app\.ft_sink_session - New session \(([a-f0-9]+)\)")

# Escritorio / Winlogon
_RE_DESK_SW  = re.compile(r"Desktop change:\s+(\w+)\s*-->\s*(\w+)")

# Red
_RE_RELAY_IP = re.compile(r"Using IPv4:\s+([\d.]+)")
_RE_EXT_ADDR = re.compile(r"External address:\s+([\d.]+):\d+")
_RE_CAND     = re.compile(r"Candidate \d+\s+\[([^\]]+)\]")


# ─── Parser principal ────────────────────────────────────────────────────────

def parse_ad_trace(filepath: str) -> TraceResult:
    """
    Parsea ad.trace o ad_svc.trace y devuelve TraceResult completo.
    Soporta UTF-8 y UTF-16 LE/BE.
    """
    result = TraceResult()

    if not os.path.exists(filepath):
        cprint(f"  [!] No encontrado: {filepath}", Fore.RED)
        return result

    enc = detect_encoding(filepath)
    try:
        with open(filepath, "r", encoding=enc, errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        cprint(f"  [!] Error leyendo {filepath}: {e}", Fore.RED)
        return result

    result.source_files.append(os.path.basename(filepath))

    cur: Session | None = None
    sidx = 0
    recent_events: list[str] = []   # ventana para buscar FPR retroactivo

    for raw in lines:
        line = raw.strip().replace("\r", "")
        if not line:
            continue

        m = _RE_LOG.match(line)
        if not m:
            continue

        level  = m.group("level")
        dt_str = m.group("dt")
        pid    = int(m.group("pid"))
        mod    = m.group("mod")
        msg    = m.group("msg").strip()

        try:
            dt: datetime | None = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            dt = None

        result.total_events += 1
        if level == "error":
            result.error_count += 1
        elif level == "warning":
            result.warning_count += 1

        # Ventana de búsqueda retroactiva (FPR)
        recent_events.append(msg)
        if len(recent_events) > 80:
            recent_events.pop(0)

        # ── Metadatos globales ──────────────────────────────────────
        mv = _RE_AD_VER.search(msg)
        if mv and mv.group(1) not in result.ad_versions:
            result.ad_versions.append(mv.group(1))

        mos = _RE_OS_INFO.search(msg)
        if mos:
            v = mos.group(1).strip()
            if v not in result.os_versions:
                result.os_versions.append(v)

        mci = _RE_CID.search(msg)
        if mci:
            result.client_ids.add(mci.group(1))

        # ── IPs globales ────────────────────────────────────────────
        _extract_ips(msg, result.relay_ips, result.external_ips, result.candidate_ips)

        # ── Nueva sesión ────────────────────────────────────────────
        ms = _RE_SESS_REQ.search(msg)
        if ms:
            sidx += 1
            fpr = _find_fpr(recent_events)
            cur = Session(
                idx       = sidx,
                remote_id = ms.group(2),
                alias     = ms.group(1).strip(),
                fpr       = fpr,
                start_dt  = dt,
                pid       = pid,
            )
            result.sessions.append(cur)
            continue

        if cur is None:
            continue

        # ── Features ───────────────────────────────────────────────
        mf = _RE_FEAT.search(msg)
        if mf and not cur.features:
            cur.features = [x.strip() for x in mf.group(1).split(",")]

        # ── Permisos ───────────────────────────────────────────────
        mp = _RE_PERM.search(msg)
        if mp:
            pn    = mp.group(1).strip().replace(" ", "_").lower()
            flags = mp.group(2)
            cur.perms[pn] = Permission(
                name      = pn,
                enabled   = "enabled"   in flags,
                allowed   = "allowed"   in flags,
                forbidden = "forbidden" in flags,
                disabled  = "disabled"  in flags,
                supported = "supported" in flags and "unsupported" not in flags,
                raw       = flags,
            )

        mpr = _RE_PROFILE.search(msg)
        if mpr:
            if not cur.perm_profile:
                cur.perm_profile = mpr.group(1)
            if mpr.group(2) == "N":
                cur.no_password = True

        # ── Capacidades remotas ─────────────────────────────────────
        mrc = _RE_RCAPS.search(msg)
        if mrc and not cur.remote_caps:
            cur.remote_caps = [c.strip() for c in mrc.group(1).split(",")]

        # ── Info remota ─────────────────────────────────────────────
        mros = _RE_ROS.search(msg)
        if mros:
            cur.remote_os   = mros.group(1)
            cur.conn_flags  = mros.group(2).strip()

        mrv = _RE_RVER.search(msg)
        if mrv and not cur.remote_version:
            cur.remote_version = mrv.group(1)

        mrt = _RE_ROUTE.search(msg)
        if mrt and not cur.route_type:
            cur.route_type = mrt.group(1).strip()

        # ── Autenticación / elevación ───────────────────────────────
        if _RE_AUTH.search(msg):  cur.authenticated = True
        if _RE_ELEV.search(msg):  cur.elevated       = True
        if _RE_UNPAID.search(msg):cur.unpaid          = True
        if _RE_MINIMIZE.search(msg): cur.minimized    = True
        if _RE_TCP_TUN.search(msg):  cur.tcp_tunnel_active = True

        # ── Archivos / portapapeles ─────────────────────────────────
        if _RE_FILE_OFF.search(msg):  cur.file_offers_accepted += 1
        if _RE_PASTE.search(msg):     cur.paste_events          += 1
        if _RE_TXT_RELAY.search(msg): cur.text_relays           += 1
        if _RE_REL_FILE.search(msg):  cur.relay_file_events     += 1

        mclip = _RE_CLIP_N.search(msg)
        if mclip:
            n = int(mclip.group(1))
            cur.clipboard_relays.append(ClipboardEvent(dt=dt, files=n, bulk=n > 20))

        mfs = _RE_FT_SRC.search(msg)
        if mfs:
            cur.ft_src_sessions.append(mfs.group(1))

        mfk = _RE_FT_SINK.search(msg)
        if mfk:
            cur.ft_sink_sessions.append(mfk.group(1))

        # ── Desktop / Winlogon ──────────────────────────────────────
        mdw = _RE_DESK_SW.search(msg)
        if mdw:
            cur.desktop_switches.append(DesktopSwitch(
                dt        = dt,
                from_desk = mdw.group(1),
                to_desk   = mdw.group(2),
            ))

        # ── IPs de sesión ───────────────────────────────────────────
        _extract_ips_session(msg, cur)

        # ── Cierre de sesión ────────────────────────────────────────
        mcl = _RE_CLOSE.search(msg)
        if mcl:
            cur.end_dt       = dt
            cur.close_reason = mcl.group(1)
            if cur.start_dt and dt:
                cur.duration_sec = int((dt - cur.start_dt).total_seconds())

    # Dedup IPs
    result.relay_ips    = set(result.relay_ips)
    result.external_ips = set(result.external_ips)
    result.candidate_ips= set(result.candidate_ips)

    return result


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _find_fpr(recent: list[str]) -> str:
    for msg in reversed(recent):
        m = re.search(r"FPR:\s+([a-f0-9]+)", msg)
        if m:
            return m.group(1)
    return ""


def _extract_ips(msg: str, relay: set, external: set, candidate: set) -> None:
    mi = _RE_RELAY_IP.search(msg)
    if mi:
        ip = mi.group(1)
        if not is_private(ip): relay.add(ip)

    me = _RE_EXT_ADDR.search(msg)
    if me:
        ip = me.group(1)
        if not is_private(ip): external.add(ip)

    mc = _RE_CAND.search(msg)
    if mc:
        ip = mc.group(1).split(":")[0]
        if not is_private(ip): candidate.add(ip)


def _extract_ips_session(msg: str, session: Session) -> None:
    mi = _RE_RELAY_IP.search(msg)
    if mi:
        ip = mi.group(1)
        if not is_private(ip) and ip not in session.relay_ips:
            session.relay_ips.append(ip)

    me = _RE_EXT_ADDR.search(msg)
    if me:
        ip = me.group(1)
        if not is_private(ip) and ip not in session.external_ips:
            session.external_ips.append(ip)

    mc = _RE_CAND.search(msg)
    if mc:
        ip = mc.group(1).split(":")[0]
        if not is_private(ip) and ip not in session.candidate_ips:
            session.candidate_ips.append(ip)
