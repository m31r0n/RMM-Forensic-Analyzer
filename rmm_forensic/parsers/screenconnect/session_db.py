"""
Parser for ScreenConnect SessionOutput.db (SQLite database).

Reads session metadata, events, and connection details from
the ScreenConnect database files.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from typing import Optional

from ...models.base import (
    RMMType,
    ParseResult,
    RMMSession,
    ConnectionDirection,
)
from ...utils import is_private

# ─── Datetime helpers ────────────────────────────────────────────────────────

_DT_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]


def _try_parse_dt(raw) -> Optional[datetime]:
    """Try to parse a datetime from various string or numeric formats."""
    if raw is None:
        return None

    # If it's already a datetime
    if isinstance(raw, datetime):
        return raw

    # If it's a numeric timestamp (Unix epoch)
    if isinstance(raw, (int, float)):
        try:
            return datetime.utcfromtimestamp(raw)
        except (OSError, ValueError, OverflowError):
            return None

    raw_str = str(raw).strip()
    if not raw_str:
        return None

    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(raw_str, fmt)
        except ValueError:
            pass

    return None


def _is_sqlite_db(filepath: str) -> bool:
    """Check if a file is a SQLite database by reading the magic bytes."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(16)
        return header[:6] == b"SQLite"
    except OSError:
        return False


def _extract_public_ip(ip_str: str) -> str:
    """Return the IP if it is public, else empty string."""
    if not ip_str:
        return ""
    ip = ip_str.strip()
    # Strip port if present
    if ":" in ip and not ip.startswith("["):
        parts = ip.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            ip = parts[0]
    try:
        if not is_private(ip):
            return ip
    except Exception:
        pass
    return ""


def parse_session_db(filepath: str, hostname: str = "") -> ParseResult:
    """
    Parse a ScreenConnect SessionOutput.db SQLite database.

    Attempts to read from tables:
    - Session: session metadata (ID, name, host, timestamps)
    - SessionEvent: timestamped events per session
    - SessionConnection: connection details (IP, user)

    Returns an empty ParseResult if the database cannot be read or
    tables do not exist.
    """
    result = ParseResult(rmm_type=RMMType.SCREENCONNECT, hostname=hostname)

    if not os.path.exists(filepath):
        return result

    if not _is_sqlite_db(filepath):
        return result

    basename = os.path.basename(filepath)
    result.source_files.append(basename)

    try:
        conn = sqlite3.connect(f"file:{filepath}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except (sqlite3.Error, OSError):
        return result

    try:
        _parse_sessions_table(conn, result, hostname, basename)
        _parse_session_events(conn, result)
        _parse_session_connections(conn, result)
    except sqlite3.Error:
        result.error_count += 1
    finally:
        try:
            conn.close()
        except sqlite3.Error:
            pass

    return result


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    """Check if a table exists in the SQLite database."""
    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        return cur.fetchone() is not None
    except sqlite3.Error:
        return False


def _get_columns(conn: sqlite3.Connection, table_name: str) -> list[str]:
    """Get the column names of a table."""
    try:
        cur = conn.execute(f"PRAGMA table_info({table_name})")
        return [row[1] for row in cur.fetchall()]
    except sqlite3.Error:
        return []


def _parse_sessions_table(
    conn: sqlite3.Connection,
    result: ParseResult,
    hostname: str,
    source_file: str,
) -> None:
    """Parse the Session table for session metadata."""
    if not _table_exists(conn, "Session"):
        return

    columns = _get_columns(conn, "Session")
    col_lower = [c.lower() for c in columns]

    try:
        cur = conn.execute("SELECT * FROM Session")
        rows = cur.fetchall()
    except sqlite3.Error:
        return

    for idx, row in enumerate(rows, start=1):
        row_dict = dict(row)

        # Extract session ID - try common column names
        session_id = ""
        for key in ("SessionID", "sessionid", "session_id", "Id", "id", "ID"):
            if key in row_dict and row_dict[key]:
                session_id = str(row_dict[key])
                break

        # Extract name/alias
        alias = ""
        for key in ("Name", "name", "SessionName", "sessionname", "HostName", "hostname"):
            if key in row_dict and row_dict[key]:
                alias = str(row_dict[key])
                break

        # Extract timestamps
        start_dt = None
        end_dt = None
        for key in ("CreatedDate", "createddate", "StartDate", "startdate",
                     "created_date", "start_date", "ConnectedDate"):
            if key in row_dict and row_dict[key]:
                start_dt = _try_parse_dt(row_dict[key])
                if start_dt:
                    break

        for key in ("EndedDate", "endeddate", "EndDate", "enddate",
                     "ended_date", "end_date", "DisconnectedDate"):
            if key in row_dict and row_dict[key]:
                end_dt = _try_parse_dt(row_dict[key])
                if end_dt:
                    break

        # Calculate duration
        duration_sec = None
        if start_dt and end_dt:
            duration_sec = int((end_dt - start_dt).total_seconds())

        # Extract IP
        remote_ip = ""
        public_ips: list[str] = []
        for key in ("GuestMachineIp", "guestmachineip", "RemoteIP",
                     "remoteip", "remote_ip", "IpAddress", "ipaddress"):
            if key in row_dict and row_dict[key]:
                ip = _extract_public_ip(str(row_dict[key]))
                if ip:
                    remote_ip = ip
                    public_ips.append(ip)
                break

        # Extract OS info
        remote_os = ""
        for key in ("GuestOperatingSystemName", "guestoperatingsystemname",
                     "OS", "os", "OperatingSystem"):
            if key in row_dict and row_dict[key]:
                remote_os = str(row_dict[key])
                break

        # Build extras from remaining interesting fields
        extras: dict = {}
        skip_keys = {k.lower() for k in (
            "SessionID", "Id", "Name", "SessionName", "HostName",
            "CreatedDate", "StartDate", "EndedDate", "EndDate",
            "GuestMachineIp", "RemoteIP", "IpAddress",
            "GuestOperatingSystemName", "OS", "OperatingSystem",
        )}
        for key, val in row_dict.items():
            if key.lower() not in skip_keys and val is not None:
                extras[key] = val

        session = RMMSession(
            idx=idx,
            rmm_type=RMMType.SCREENCONNECT,
            remote_id=session_id,
            alias=alias,
            start_dt=start_dt,
            end_dt=end_dt,
            duration_sec=duration_sec,
            hostname=hostname,
            source_file=source_file,
            remote_ip=remote_ip,
            remote_os=remote_os,
            public_ips=public_ips,
            extras=extras,
        )

        result.sessions.append(session)
        result.total_events += 1

        # Add public IPs to global set
        for ip in public_ips:
            result.public_ips.add(ip)


def _parse_session_events(
    conn: sqlite3.Connection,
    result: ParseResult,
) -> None:
    """Parse the SessionEvent table for event counts (file transfers, etc.)."""
    if not _table_exists(conn, "SessionEvent"):
        return

    try:
        cur = conn.execute("SELECT * FROM SessionEvent")
        rows = cur.fetchall()
    except sqlite3.Error:
        return

    # Build a mapping from session ID to session object for enrichment
    session_map: dict[str, RMMSession] = {}
    for session in result.sessions:
        if session.remote_id:
            session_map[session.remote_id] = session

    for row in rows:
        row_dict = dict(row)
        result.total_events += 1

        # Find associated session
        session_id = ""
        for key in ("SessionID", "sessionid", "session_id"):
            if key in row_dict and row_dict[key]:
                session_id = str(row_dict[key])
                break

        session = session_map.get(session_id)

        # Check event type
        event_type = ""
        for key in ("EventType", "eventtype", "event_type", "Type", "type"):
            if key in row_dict and row_dict[key]:
                event_type = str(row_dict[key]).lower()
                break

        # Check event data/message
        event_data = ""
        for key in ("Data", "data", "Message", "message", "EventData"):
            if key in row_dict and row_dict[key]:
                event_data = str(row_dict[key])
                break

        if session is None:
            continue

        # Classify events
        combined = f"{event_type} {event_data}".lower()
        if "file" in combined and ("transfer" in combined or "sent" in combined
                                   or "received" in combined):
            session.file_transfers += 1
        elif "command" in combined or "execute" in combined:
            session.extras.setdefault("commands_executed", 0)
            session.extras["commands_executed"] += 1
        elif "elevat" in combined or "uac" in combined:
            session.elevated = True
        elif "auth" in combined or "login" in combined:
            session.authenticated = True


def _parse_session_connections(
    conn: sqlite3.Connection,
    result: ParseResult,
) -> None:
    """Parse the SessionConnection table for IP/connection details."""
    if not _table_exists(conn, "SessionConnection"):
        return

    try:
        cur = conn.execute("SELECT * FROM SessionConnection")
        rows = cur.fetchall()
    except sqlite3.Error:
        return

    session_map: dict[str, RMMSession] = {}
    for session in result.sessions:
        if session.remote_id:
            session_map[session.remote_id] = session

    for row in rows:
        row_dict = dict(row)
        result.total_events += 1

        session_id = ""
        for key in ("SessionID", "sessionid", "session_id"):
            if key in row_dict and row_dict[key]:
                session_id = str(row_dict[key])
                break

        session = session_map.get(session_id)
        if session is None:
            continue

        # Extract IP from connection record
        for key in ("IpAddress", "ipaddress", "ip_address", "RemoteIP",
                     "remoteip", "remote_ip"):
            if key in row_dict and row_dict[key]:
                ip = _extract_public_ip(str(row_dict[key]))
                if ip:
                    if not session.remote_ip:
                        session.remote_ip = ip
                    if ip not in session.public_ips:
                        session.public_ips.append(ip)
                    result.public_ips.add(ip)
                break
