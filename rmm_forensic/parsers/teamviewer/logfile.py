"""
Parser for TeamViewer log files (TeamViewer*_Logfile.log).

Extracts sessions, file transfers, authentication events,
IP addresses, version info, and elevation/UAC indicators
from timestamped TeamViewer log entries.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Optional

from ...models.base import (
    RMMType, ParseResult, RMMSession, ConnectionDirection,
)
from ...utils import detect_encoding, is_private

# ─── Log line patterns ───────────────────────────────────────────────────────

# Primary format: 2024-01-10 09:40:15.123  1234  5678 S0   ThreadName!Function: Message
_RE_LOG_PRIMARY = re.compile(
    r"^(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?"                     # optional milliseconds
    r"\s+(?P<rest>.+)$"
)

# Alternative format: 2024/01/10 09:40:15.123 - Message content
_RE_LOG_ALT = re.compile(
    r"^(?P<dt>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?"
    r"\s+-\s+(?P<msg>.+)$"
)

# Datetime parse formats
_DT_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M",
]

# ─── Session patterns ────────────────────────────────────────────────────────

_RE_INCOMING_SESSION = re.compile(
    r"[Ii]ncoming\s+session\s+request\s+from\s+(.+?)(?:\s*\((\d+)\))?",
)
_RE_START_SESSION = re.compile(
    r"[Ss]tart\s+session\s+to\s+(.+?)(?:\s*\((\d+)\))?",
)
_RE_SESSION_END = re.compile(
    r"(?:[Ss]ession\s+terminated|CloseSession|SessionTerminate"
    r"|[Ss]ession\s+(?:closed|ended|stopped))",
)

# ─── Authentication ──────────────────────────────────────────────────────────

_RE_AUTH = re.compile(r"[Aa]uthenticat(?:ed|ion\s+successful)", re.I)
_RE_LOGIN = re.compile(r"\b[Ll]ogin\b.*(?:success|accept|ok)", re.I)

# ─── Remote ID ────────────────────────────────────────────────────────────────

_RE_PARTICIPANT_ID = re.compile(r"[Pp]articipant\s+ID:\s*(\d+)")
_RE_TEAMVIEWER_ID = re.compile(r"TeamViewer\s+ID:\s*(\d+)")
_RE_PARTNER_ID = re.compile(r"[Pp]artner\s+ID[:\s]+(\d+)")

# ─── File transfer ────────────────────────────────────────────────────────────

_RE_FILE_TRANSFER = re.compile(
    r"(?:[Ff]ile[Tt]ransfer|[Ff]ile\s+transfer\s+started"
    r"|SendFile|ReceiveFile|FileTransferStart"
    r"|[Ff]ile\s+(?:sent|received|upload|download))",
    re.I,
)

# ─── IP addresses ─────────────────────────────────────────────────────────────

_RE_IP = re.compile(
    r"(?:(?:^|[\s(,;=:]))"            # boundary before IP
    r"((?:\d{1,3}\.){3}\d{1,3})"      # IPv4
    r"(?::\d+)?"                       # optional port
)

# ─── Version ──────────────────────────────────────────────────────────────────

_RE_VERSION = re.compile(
    r"TeamViewer\s+(?:version\s+)?(\d+(?:\.\d+)+)", re.I
)

# ─── Elevation / UAC ─────────────────────────────────────────────────────────

_RE_ELEVATION = re.compile(
    r"(?:RequestElevation|[Ee]levated|UAC|RunAsAdmin"
    r"|[Ee]levation\s+requested|[Ee]levate\s+session)",
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
    """Extract public IPv4 addresses from a text string."""
    ips = []
    for m in _RE_IP.finditer(text):
        ip = m.group(1)
        try:
            if not is_private(ip):
                ips.append(ip)
        except Exception:
            pass
    return ips


def parse_logfile(filepath: str, hostname: str = "") -> ParseResult:
    """
    Parse a TeamViewer log file and return a ParseResult with sessions.

    Scans for session start/end markers, file transfers, authentication,
    IP addresses, version info, and elevation indicators.
    """
    result = ParseResult(rmm_type=RMMType.TEAMVIEWER, hostname=hostname)

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

        m_primary = _RE_LOG_PRIMARY.match(line)
        m_alt = _RE_LOG_ALT.match(line)

        if m_primary:
            dt, _ = _parse_dt(m_primary.group("dt"))
            msg = m_primary.group("rest")
        elif m_alt:
            dt, _ = _parse_dt(m_alt.group("dt"))
            msg = m_alt.group("msg")

        # ── Version detection ─────────────────────────────────────────
        mv = _RE_VERSION.search(msg)
        if mv:
            ver = mv.group(1)
            if ver not in result.tool_versions:
                result.tool_versions.append(ver)

        # ── Extract IPs from every line ───────────────────────────────
        line_ips = _extract_public_ips(msg)
        all_public_ips.update(line_ips)

        # ── Incoming session request ──────────────────────────────────
        ms_in = _RE_INCOMING_SESSION.search(msg)
        if ms_in:
            # Finalize previous session if still open
            if cur is not None and cur.end_dt is None and dt:
                cur.end_dt = dt
                if cur.start_dt:
                    cur.duration_sec = int(
                        (cur.end_dt - cur.start_dt).total_seconds()
                    )

            sidx += 1
            remote_id = ms_in.group(2) or ""
            alias = ms_in.group(1).strip() if ms_in.group(1) else ""
            cur = RMMSession(
                idx=sidx,
                rmm_type=RMMType.TEAMVIEWER,
                remote_id=remote_id,
                alias=alias,
                start_dt=dt,
                hostname=hostname,
                source_file=basename,
            )
            # Assign IPs found on this line
            for ip in line_ips:
                if ip not in cur.public_ips:
                    cur.public_ips.append(ip)
            cur.extras["direction"] = ConnectionDirection.INCOMING.value
            result.sessions.append(cur)
            continue

        # ── Outgoing session start ────────────────────────────────────
        ms_out = _RE_START_SESSION.search(msg)
        if ms_out:
            if cur is not None and cur.end_dt is None and dt:
                cur.end_dt = dt
                if cur.start_dt:
                    cur.duration_sec = int(
                        (cur.end_dt - cur.start_dt).total_seconds()
                    )

            sidx += 1
            remote_id = ms_out.group(2) or ""
            alias = ms_out.group(1).strip() if ms_out.group(1) else ""
            cur = RMMSession(
                idx=sidx,
                rmm_type=RMMType.TEAMVIEWER,
                remote_id=remote_id,
                alias=alias,
                start_dt=dt,
                hostname=hostname,
                source_file=basename,
            )
            for ip in line_ips:
                if ip not in cur.public_ips:
                    cur.public_ips.append(ip)
            cur.extras["direction"] = ConnectionDirection.OUTGOING.value
            result.sessions.append(cur)
            continue

        # ── Everything below requires an active session ───────────────
        if cur is None:
            # Still collect TeamViewer IDs from outside sessions
            m_tvid = _RE_TEAMVIEWER_ID.search(msg)
            if m_tvid:
                result.client_ids.add(m_tvid.group(1))
            continue

        # ── Remote / Participant ID ───────────────────────────────────
        m_pid = _RE_PARTICIPANT_ID.search(msg)
        if m_pid and not cur.remote_id:
            cur.remote_id = m_pid.group(1)

        m_tvid = _RE_TEAMVIEWER_ID.search(msg)
        if m_tvid:
            result.client_ids.add(m_tvid.group(1))
            if not cur.remote_id:
                cur.remote_id = m_tvid.group(1)

        m_partner = _RE_PARTNER_ID.search(msg)
        if m_partner and not cur.remote_id:
            cur.remote_id = m_partner.group(1)

        # ── Authentication ────────────────────────────────────────────
        if _RE_AUTH.search(msg) or _RE_LOGIN.search(msg):
            cur.authenticated = True

        # ── File transfer ─────────────────────────────────────────────
        if _RE_FILE_TRANSFER.search(msg):
            cur.file_transfers += 1

        # ── Elevation / UAC ───────────────────────────────────────────
        if _RE_ELEVATION.search(msg):
            cur.elevated = True

        # ── IPs within session ────────────────────────────────────────
        for ip in line_ips:
            if ip not in cur.public_ips:
                cur.public_ips.append(ip)

        # ── Session end ───────────────────────────────────────────────
        if _RE_SESSION_END.search(msg):
            cur.end_dt = dt
            if cur.start_dt and dt:
                cur.duration_sec = int(
                    (dt - cur.start_dt).total_seconds()
                )
            cur = None  # Session is closed; next events are outside sessions

    # Finalize last session if still open
    if cur is not None and cur.end_dt is None:
        # Leave end_dt as None to signal an unclosed session
        pass

    result.public_ips = all_public_ips
    return result
