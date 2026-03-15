"""
Parser for ScreenConnect/ConnectWise Control text log files.

Extracts sessions, authentication events, file transfers, commands,
and IP addresses from ScreenConnect log entries and user.config files.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Optional

from ...models.base import (
    RMMType,
    ParseResult,
    RMMSession,
    RMMConnection,
    ConnectionDirection,
)
from ...utils import detect_encoding, is_private

# ─── Timestamp patterns ─────────────────────────────────────────────────────

# Standard log: 2024-01-10 09:40:15 - Message
_RE_LOG_STANDARD = re.compile(
    r"^(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"\s*-\s*(?P<msg>.+)$"
)

# Timestamped with milliseconds: 2024-01-10 09:40:15.123 Message
_RE_LOG_MILLIS = re.compile(
    r"^(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?\s+(?P<msg>.+)$"
)

_DT_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M",
]

# ─── Event patterns ─────────────────────────────────────────────────────────

_RE_SESSION_CONNECT = re.compile(
    r"(?:[Cc]onnected\s+to\s+session|[Ss]ession\s+started|[Ss]ession\s+created"
    r"|[Cc]onnection\s+established|[Jj]oined\s+session)",
    re.I,
)

_RE_SESSION_DISCONNECT = re.compile(
    r"(?:[Ss]ession\s+disconnected|[Dd]isconnected|[Ss]ession\s+ended"
    r"|[Ss]ession\s+closed|[Cc]onnection\s+closed|[Ss]ession\s+terminated)",
    re.I,
)

_RE_AUTH = re.compile(
    r"(?:[Uu]ser\s+authenticated|[Aa]uthenticat(?:ed|ion)|[Ll]ogin\s+success"
    r"|[Ll]ogged\s+in)",
    re.I,
)

_RE_FILE_TRANSFER = re.compile(
    r"(?:[Ff]ile\s+transferred|[Uu]pload|[Dd]ownload|[Ff]ile\s+transfer"
    r"|[Ss]end\s+file|[Rr]eceive\s+file|[Ff]iles?\s+sent|[Ff]iles?\s+received)",
    re.I,
)

_RE_COMMAND = re.compile(
    r"(?:[Ee]xecuted\s+command|[Rr]un[Cc]ommand|[Cc]ommand\s+executed"
    r"|[Rr]emote\s+command|[Cc]ommand\s+sent|[Bb]ackstage\s+command)",
    re.I,
)

_RE_ELEVATION = re.compile(
    r"(?:[Ee]levat(?:ed|ion)|[Uu]AC|[Rr]un\s*[Aa]s\s*[Aa]dmin)",
    re.I,
)

# Session/connection ID: abc-123, {guid}, or numeric
_RE_SESSION_ID = re.compile(
    r"(?:session|Session|SESSION)\s+([a-fA-F0-9\-]{5,}|\{[a-fA-F0-9\-]+\})"
)

# User extraction from auth lines
_RE_USER_EXTRACT = re.compile(
    r"(?:[Uu]ser\s+authenticated:\s*(.+?)$"
    r"|[Ll]ogin\s+(?:for|by|as)\s+(.+?)$"
    r"|[Uu]ser[:\s]+(.+?)\s+(?:logged|authenticated|connected))",
)

# ─── IP address ──────────────────────────────────────────────────────────────

_RE_IP = re.compile(
    r"(?:(?:^|[\s(,;=:]))"
    r"((?:\d{1,3}\.){3}\d{1,3})"
    r"(?::\d+)?"
)

# ─── Version ─────────────────────────────────────────────────────────────────

_RE_VERSION = re.compile(
    r"(?:ScreenConnect|ConnectWise\s+Control)\s+(?:version\s+)?(\d+(?:\.\d+)+)",
    re.I,
)


def _parse_dt(raw: str) -> tuple[Optional[datetime], str]:
    """Try multiple datetime formats."""
    raw = raw.strip()
    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(raw, fmt), raw
        except ValueError:
            pass
    return None, raw


def _extract_public_ips(text: str) -> list[str]:
    """Extract public IPv4 addresses from text."""
    ips = []
    for m in _RE_IP.finditer(text):
        ip = m.group(1)
        try:
            if not is_private(ip):
                ips.append(ip)
        except Exception:
            pass
    return ips


def parse_session_logs(filepath: str, hostname: str = "") -> ParseResult:
    """
    Parse ScreenConnect text log files.

    Scans for session start/end markers, authentication, file transfers,
    commands, IP addresses, and version info.

    Returns a ParseResult with sessions and metadata.
    """
    result = ParseResult(rmm_type=RMMType.SCREENCONNECT, hostname=hostname)

    if not os.path.exists(filepath):
        return result

    enc = detect_encoding(filepath)
    try:
        with open(filepath, "r", encoding=enc, errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return result

    basename = os.path.basename(filepath)
    result.source_files.append(basename)

    cur: Optional[RMMSession] = None
    sidx = 0
    all_public_ips: set[str] = set()

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        result.total_events += 1

        # ── Parse timestamp and message ──────────────────────────────
        dt: Optional[datetime] = None
        msg = line

        m_std = _RE_LOG_STANDARD.match(line)
        m_ms = _RE_LOG_MILLIS.match(line)

        if m_std:
            dt, _ = _parse_dt(m_std.group("dt"))
            msg = m_std.group("msg")
        elif m_ms:
            dt, _ = _parse_dt(m_ms.group("dt"))
            msg = m_ms.group("msg")

        # ── Version detection ─────────────────────────────────────────
        mv = _RE_VERSION.search(msg)
        if mv:
            ver = mv.group(1)
            if ver not in result.tool_versions:
                result.tool_versions.append(ver)

        # ── Extract IPs from every line ───────────────────────────────
        line_ips = _extract_public_ips(msg)
        all_public_ips.update(line_ips)

        # ── Session connect / start ───────────────────────────────────
        if _RE_SESSION_CONNECT.search(msg):
            # Finalize previous session if still open
            if cur is not None and cur.end_dt is None and dt:
                cur.end_dt = dt
                if cur.start_dt:
                    cur.duration_sec = int(
                        (cur.end_dt - cur.start_dt).total_seconds()
                    )

            sidx += 1
            session_id = ""
            m_sid = _RE_SESSION_ID.search(msg)
            if m_sid:
                session_id = m_sid.group(1)

            cur = RMMSession(
                idx=sidx,
                rmm_type=RMMType.SCREENCONNECT,
                remote_id=session_id,
                start_dt=dt,
                hostname=hostname,
                source_file=basename,
            )
            cur.extras["direction"] = ConnectionDirection.INCOMING.value
            for ip in line_ips:
                if ip not in cur.public_ips:
                    cur.public_ips.append(ip)
            result.sessions.append(cur)
            continue

        # ── Everything below requires an active session ───────────────
        if cur is None:
            continue

        # ── Authentication ────────────────────────────────────────────
        if _RE_AUTH.search(msg):
            cur.authenticated = True
            m_user = _RE_USER_EXTRACT.search(msg)
            if m_user:
                user = m_user.group(1) or m_user.group(2) or m_user.group(3)
                if user:
                    cur.extras["user"] = user.strip()

        # ── File transfer ─────────────────────────────────────────────
        if _RE_FILE_TRANSFER.search(msg):
            cur.file_transfers += 1

        # ── Command execution ─────────────────────────────────────────
        if _RE_COMMAND.search(msg):
            cur.extras.setdefault("commands_executed", 0)
            cur.extras["commands_executed"] += 1

        # ── Elevation / UAC ───────────────────────────────────────────
        if _RE_ELEVATION.search(msg):
            cur.elevated = True

        # ── IPs within session ────────────────────────────────────────
        for ip in line_ips:
            if ip not in cur.public_ips:
                cur.public_ips.append(ip)

        # ── Session disconnect / end ──────────────────────────────────
        if _RE_SESSION_DISCONNECT.search(msg):
            cur.end_dt = dt
            if cur.start_dt and dt:
                cur.duration_sec = int(
                    (dt - cur.start_dt).total_seconds()
                )
            cur = None

    result.public_ips = all_public_ips
    return result
