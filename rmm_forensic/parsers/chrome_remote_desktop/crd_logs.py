"""
Parser for Chrome Remote Desktop log files.

Extracts sessions, connection events, IP addresses, and file transfers
from Chrome Remote Desktop (chromoting) text log files.
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

# Format: [2024-01-10 09:40:15] INFO module.py:123 - Message
_RE_LOG_BRACKETED = re.compile(
    r"^\[(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]"
    r"\s+(?:INFO|WARNING|ERROR|DEBUG|CRITICAL)?\s*"
    r"(?:\S+:\d+\s*-?\s*)?"
    r"(?P<msg>.*)$"
)

# Format: 2024-01-10 09:40:15 - Message
_RE_LOG_STANDARD = re.compile(
    r"^(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?"
    r"\s*-\s*(?P<msg>.+)$"
)

# Format: 2024-01-10T09:40:15.123Z message (ISO with T separator)
_RE_LOG_ISO = re.compile(
    r"^(?P<dt>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?Z?\s+(?P<msg>.+)$"
)

# Format: 2024-01-10 09:40:15.123 Message (no dash separator)
_RE_LOG_PLAIN = re.compile(
    r"^(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?\s+(?P<msg>.+)$"
)

_DT_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
]

# ─── Event patterns ─────────────────────────────────────────────────────────

_RE_CLIENT_CONNECTED = re.compile(
    r"(?:[Cc]lient\s+connected|[Cc]onnection\s+(?:from|established|accepted)"
    r"|[Pp]eer\s+connected|[Ii]ncoming\s+connection"
    r"|[Rr]emote\s+client\s+connected)",
    re.I,
)

_RE_SESSION_START = re.compile(
    r"(?:[Ss]ession\s+started|[Ss]ession\s+created|[Ss]ession\s+established"
    r"|[Hh]ost\s+started|[Rr]emoting\s+session\s+(?:started|begun))",
    re.I,
)

_RE_SESSION_END = re.compile(
    r"(?:[Ss]ession\s+ended|[Ss]ession\s+closed|[Ss]ession\s+terminated"
    r"|[Dd]isconnected|[Cc]lient\s+disconnected|[Ss]ession\s+stopped"
    r"|[Cc]onnection\s+closed|[Cc]onnection\s+lost)",
    re.I,
)

_RE_AUTH = re.compile(
    r"(?:[Aa]uthenticat(?:ed|ion)|[Ll]ogin|[Pp]IN\s+(?:verified|accepted)"
    r"|[Aa]ccess\s+(?:granted|approved))",
    re.I,
)

_RE_FILE_TRANSFER = re.compile(
    r"(?:[Ff]ile\s+transfer|[Ff]ile\s+(?:sent|received|upload|download)"
    r"|[Tt]ransfer\s+(?:started|completed|file))",
    re.I,
)

_RE_CLIPBOARD = re.compile(
    r"(?:[Cc]lipboard|[Cc]opy|[Pp]aste)",
    re.I,
)

# ─── IP address ──────────────────────────────────────────────────────────────

_RE_IP = re.compile(
    r"(?:(?:^|[\s(,;=:]))"
    r"((?:\d{1,3}\.){3}\d{1,3})"
    r"(?::\d+)?"
)

# IP extraction from connection messages
_RE_IP_FROM = re.compile(
    r"(?:from|address|ip)[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.I,
)

# ─── Version ─────────────────────────────────────────────────────────────────

_RE_VERSION = re.compile(
    r"(?:chrome\s*remote\s*desktop|chromoting|CRD)\s+(?:version\s+)?(\d+(?:\.\d+)+)",
    re.I,
)

# ─── Chromoting identifiers ──────────────────────────────────────────────────

_RE_CHROMOTING = re.compile(
    r"(?:chromoting|chrome.?remote.?desktop|remoting_host|CRD)",
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


def parse_crd_logs(filepath: str, hostname: str = "") -> ParseResult:
    """
    Parse Chrome Remote Desktop log files.

    Scans for session start/end markers, client connections,
    authentication, file transfers, clipboard events, and IP addresses.

    Returns a ParseResult with sessions and metadata.
    """
    result = ParseResult(rmm_type=RMMType.CHROME_REMOTE_DESKTOP, hostname=hostname)

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
        m_iso = _RE_LOG_ISO.match(line)
        m_plain = _RE_LOG_PLAIN.match(line)

        if m_bracket:
            dt, _ = _parse_dt(m_bracket.group("dt"))
            msg = m_bracket.group("msg")
        elif m_std:
            dt, _ = _parse_dt(m_std.group("dt"))
            msg = m_std.group("msg")
        elif m_iso:
            dt, _ = _parse_dt(m_iso.group("dt"))
            msg = m_iso.group("msg")
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

        # ── Client connected / Session start ──────────────────────────
        is_connect = _RE_CLIENT_CONNECTED.search(msg)
        is_start = _RE_SESSION_START.search(msg)

        if is_connect or is_start:
            # Finalize previous session if still open
            if cur is not None and cur.end_dt is None and dt:
                cur.end_dt = dt
                if cur.start_dt:
                    cur.duration_sec = int(
                        (cur.end_dt - cur.start_dt).total_seconds()
                    )

            sidx += 1

            # Try to extract remote IP from connection message
            remote_ip = ""
            m_ip_from = _RE_IP_FROM.search(msg)
            if m_ip_from:
                ip_candidate = m_ip_from.group(1)
                try:
                    if not is_private(ip_candidate):
                        remote_ip = ip_candidate
                except Exception:
                    pass

            cur = RMMSession(
                idx=sidx,
                rmm_type=RMMType.CHROME_REMOTE_DESKTOP,
                remote_id="",
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
