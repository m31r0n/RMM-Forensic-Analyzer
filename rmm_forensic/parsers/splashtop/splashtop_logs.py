"""
Parser for Splashtop log files.

Extracts sessions, connection events, IP addresses, and file transfers
from Splashtop text log files (SPLog.txt, SRLog.txt, log_YYYYMMDD.log).
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
    ConnectionDirection,
)
from ...utils import detect_encoding, is_private

# ─── Timestamp patterns ─────────────────────────────────────────────────────

# Format: [2024-01-10 09:40:15.123] [INFO] Message
_RE_LOG_BRACKETED = re.compile(
    r"^\[(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?\]\s+"
    r"(?:\[(?:INFO|WARNING|ERROR|DEBUG|WARN)\]\s*)?"
    r"(?P<msg>.*)$"
)

# Format: 2024-01-10 09:40:15 - Message
_RE_LOG_STANDARD = re.compile(
    r"^(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?"
    r"\s*-\s*(?P<msg>.+)$"
)

# Format: 2024-01-10 09:40:15.123 Message (no separator)
_RE_LOG_PLAIN = re.compile(
    r"^(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?\s+(?P<msg>.+)$"
)

# Format: 01/10/2024 09:40:15 Message (US date)
_RE_LOG_US = re.compile(
    r"^(?P<dt>\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?\s+(?P<msg>.+)$"
)

_DT_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y-%m-%d %H:%M",
]

# ─── Event patterns ─────────────────────────────────────────────────────────

_RE_CONNECTION = re.compile(
    r"(?:[Cc]onnection\s+(?:from|established|accepted|started)"
    r"|[Ii]ncoming\s+connection|[Cc]lient\s+connect(?:ed|ing)"
    r"|[Nn]ew\s+connection|[Rr]emote\s+session\s+(?:started|request))",
    re.I,
)

_RE_SESSION_START = re.compile(
    r"(?:[Ss]ession\s+started|[Ss]ession\s+created|[Ss]treaming\s+started"
    r"|[Ss]ession\s+established|[Ss]ession\s+begin)",
    re.I,
)

_RE_SESSION_END = re.compile(
    r"(?:[Ss]ession\s+ended|[Ss]ession\s+closed|[Ss]ession\s+terminated"
    r"|[Dd]isconnected|[Ss]treaming\s+stopped|[Ss]ession\s+stopped"
    r"|[Cc]onnection\s+(?:closed|lost|terminated|ended))",
    re.I,
)

_RE_AUTH = re.compile(
    r"(?:[Aa]uthenticat(?:ed|ion)|[Ll]ogin\s+success|[Pp]assword\s+(?:verified|accepted)"
    r"|[Aa]ccess\s+(?:granted|approved)|[Uu]ser\s+verified)",
    re.I,
)

_RE_FILE_TRANSFER = re.compile(
    r"(?:[Ff]ile\s+transfer|[Ff]ile\s+(?:sent|received|upload|download)"
    r"|[Tt]ransfer\s+(?:started|completed|file)|[Dd]rag\s+and\s+drop)",
    re.I,
)

_RE_CLIPBOARD = re.compile(
    r"(?:[Cc]lipboard|[Cc]opy|[Pp]aste)",
    re.I,
)

_RE_ELEVATION = re.compile(
    r"(?:[Ee]levat(?:ed|ion)|[Uu]AC|[Rr]un\s*[Aa]s\s*[Aa]dmin)",
    re.I,
)

# Session ID: ID: 12345, Session ID: abc-def
_RE_SESSION_ID = re.compile(
    r"(?:ID|Session\s*ID|session_id)[:\s]+(\S+)",
    re.I,
)

# User extraction
_RE_USER_EXTRACT = re.compile(
    r"(?:[Uu]ser[:\s]+(\S+)|(?:from|by)\s+(\S+?)@)",
)

# ─── IP address ──────────────────────────────────────────────────────────────

_RE_IP = re.compile(
    r"(?:(?:^|[\s(,;=:]))"
    r"((?:\d{1,3}\.){3}\d{1,3})"
    r"(?::\d+)?"
)

_RE_IP_FROM = re.compile(
    r"(?:from|address|ip)[:\s]+(?:user@)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.I,
)

# ─── Version ─────────────────────────────────────────────────────────────────

_RE_VERSION = re.compile(
    r"[Ss]plashtop\s+(?:version\s+)?(\d+(?:\.\d+)+)",
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


def parse_splashtop_logs(filepath: str, hostname: str = "") -> ParseResult:
    """
    Parse Splashtop log files.

    Scans for session start/end markers, connections, authentication,
    file transfers, clipboard events, elevation, and IP addresses.

    Returns a ParseResult with sessions and metadata.
    """
    result = ParseResult(rmm_type=RMMType.SPLASHTOP, hostname=hostname)

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

        m_bracket = _RE_LOG_BRACKETED.match(line)
        m_std = _RE_LOG_STANDARD.match(line)
        m_plain = _RE_LOG_PLAIN.match(line)
        m_us = _RE_LOG_US.match(line)

        if m_bracket:
            dt, _ = _parse_dt(m_bracket.group("dt"))
            msg = m_bracket.group("msg")
        elif m_std:
            dt, _ = _parse_dt(m_std.group("dt"))
            msg = m_std.group("msg")
        elif m_us:
            dt, _ = _parse_dt(m_us.group("dt"))
            msg = m_us.group("msg")
        elif m_plain:
            dt, _ = _parse_dt(m_plain.group("dt"))
            msg = m_plain.group("msg")

        # ── Version detection ─────────────────────────────────────────
        mv = _RE_VERSION.search(msg)
        if mv:
            ver = mv.group(1)
            if ver not in result.tool_versions:
                result.tool_versions.append(ver)

        # ── Extract IPs from every line ───────────────────────────────
        line_ips = _extract_public_ips(msg)
        all_public_ips.update(line_ips)

        # ── Connection / Session start ────────────────────────────────
        is_connection = _RE_CONNECTION.search(msg)
        is_start = _RE_SESSION_START.search(msg)

        if is_connection or is_start:
            # Finalize previous session if still open
            if cur is not None and cur.end_dt is None and dt:
                cur.end_dt = dt
                if cur.start_dt:
                    cur.duration_sec = int(
                        (cur.end_dt - cur.start_dt).total_seconds()
                    )

            sidx += 1

            # Extract session ID if present
            session_id = ""
            m_sid = _RE_SESSION_ID.search(msg)
            if m_sid:
                session_id = m_sid.group(1)

            # Extract remote IP
            remote_ip = ""
            m_ip_from = _RE_IP_FROM.search(msg)
            if m_ip_from:
                ip_candidate = m_ip_from.group(1)
                try:
                    if not is_private(ip_candidate):
                        remote_ip = ip_candidate
                except Exception:
                    pass

            # Extract user
            user_alias = ""
            m_user = _RE_USER_EXTRACT.search(msg)
            if m_user:
                user_alias = (m_user.group(1) or m_user.group(2) or "").strip()

            cur = RMMSession(
                idx=sidx,
                rmm_type=RMMType.SPLASHTOP,
                remote_id=session_id,
                alias=user_alias,
                start_dt=dt,
                hostname=hostname,
                source_file=basename,
                remote_ip=remote_ip,
            )
            cur.extras["direction"] = ConnectionDirection.INCOMING.value
            for ip in line_ips:
                if ip not in cur.public_ips:
                    cur.public_ips.append(ip)
            if remote_ip and remote_ip not in cur.public_ips:
                cur.public_ips.append(remote_ip)
            result.sessions.append(cur)
            continue

        # ── Everything below requires an active session ───────────────
        if cur is None:
            continue

        # ── Authentication ────────────────────────────────────────────
        if _RE_AUTH.search(msg):
            cur.authenticated = True

        # ── File transfer ─────────────────────────────────────────────
        if _RE_FILE_TRANSFER.search(msg):
            cur.file_transfers += 1

        # ── Clipboard ─────────────────────────────────────────────────
        if _RE_CLIPBOARD.search(msg):
            cur.clipboard_events += 1

        # ── Elevation ─────────────────────────────────────────────────
        if _RE_ELEVATION.search(msg):
            cur.elevated = True

        # ── IPs within session ────────────────────────────────────────
        for ip in line_ips:
            if ip not in cur.public_ips:
                cur.public_ips.append(ip)
            if not cur.remote_ip:
                cur.remote_ip = ip

        # ── Session end ───────────────────────────────────────────────
        if _RE_SESSION_END.search(msg):
            cur.end_dt = dt
            if cur.start_dt and dt:
                cur.duration_sec = int(
                    (dt - cur.start_dt).total_seconds()
                )
            cur = None

    result.public_ips = all_public_ips
    return result
