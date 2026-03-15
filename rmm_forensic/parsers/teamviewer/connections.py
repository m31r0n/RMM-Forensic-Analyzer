"""
Parser for TeamViewer connection logs (Connections_incoming.txt, Connections.txt).

Handles multiple date formats, tab/space-separated columns,
and UTF-8/UTF-16 encodings.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Optional

from ...models.base import RMMType, RMMConnection, ConnectionDirection
from ...utils import detect_encoding

# ─── Date formats ────────────────────────────────────────────────────────────

_DT_FORMATS = [
    "%d-%m-%Y %H:%M:%S",    # 10-01-2024 09:40:15
    "%d-%m-%Y %H:%M",       # 10-01-2024 09:40
    "%m/%d/%Y %H:%M:%S",    # 01/10/2024 09:40:15
    "%m/%d/%Y %H:%M",       # 01/10/2024 09:40
    "%Y-%m-%d %H:%M:%S",    # 2024-01-10 09:40:15
    "%Y-%m-%d %H:%M",       # 2024-01-10 09:40
    "%d.%m.%Y %H:%M:%S",    # 10.01.2024 09:40:15
    "%d.%m.%Y %H:%M",       # 10.01.2024 09:40
    "%Y/%m/%d %H:%M:%S",    # 2024/01/10 09:40:15
    "%Y/%m/%d %H:%M",       # 2024/01/10 09:40
]

# Regex to detect duration fields like HH:MM:SS
_RE_DURATION = re.compile(r"^\d{1,3}:\d{2}:\d{2}$")

# Regex to detect date-like fields
_RE_DATE = re.compile(
    r"^\d{2,4}[-/\.]\d{2}[-/\.]\d{2,4}\s+\d{2}:\d{2}"
)

# Regex for UUID fields like {abc12345-def6-7890-abcd-ef1234567890}
_RE_UUID = re.compile(r"^\{?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}?$", re.I)

# Regex for TeamViewer numeric ID (typically 9-10 digits, but can vary)
_RE_TV_ID = re.compile(r"^\d{6,15}$")


def _parse_dt(raw: str) -> tuple[Optional[datetime], str]:
    """Try to parse a datetime string against known formats."""
    raw = raw.strip()
    if not raw:
        return None, raw
    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(raw, fmt), raw
        except ValueError:
            pass
    return None, raw


def _parse_duration(raw: str) -> str:
    """Return duration string if it looks like HH:MM:SS, else empty."""
    raw = raw.strip()
    if _RE_DURATION.match(raw):
        return raw
    return ""


def _detect_direction(filepath: str) -> ConnectionDirection:
    """Determine direction based on filename."""
    basename = os.path.basename(filepath).lower()
    if "incoming" in basename:
        return ConnectionDirection.INCOMING
    elif "outgoing" in basename:
        return ConnectionDirection.OUTGOING
    # Connections.txt (without incoming) is typically outgoing
    if basename == "connections.txt":
        return ConnectionDirection.OUTGOING
    return ConnectionDirection.UNKNOWN


def _split_line(line: str) -> list[str]:
    """
    Split a connection log line by tabs first; if that yields too few
    fields, fall back to 2+ space splitting.
    """
    parts = line.split("\t")
    parts = [p.strip() for p in parts if p.strip()]
    if len(parts) >= 3:
        return parts
    # Fallback: split by 2+ spaces
    parts = re.split(r"\s{2,}", line.strip())
    parts = [p.strip() for p in parts if p.strip()]
    return parts


def parse_connections(filepath: str) -> list[RMMConnection]:
    """
    Parse TeamViewer Connections_incoming.txt or Connections.txt.

    Known column layouts (varies by TeamViewer version):
    - Full:  ID  StartDate  EndDate  Duration  User  ConnectionType  UniqueID
    - Short: ID  Date  User  ConnectionType  UniqueID
    - Minimal: ID  Date  User  ConnectionType

    Returns a list of RMMConnection objects.
    """
    records: list[RMMConnection] = []

    if not os.path.exists(filepath):
        return records

    enc = detect_encoding(filepath)
    try:
        with open(filepath, "r", encoding=enc, errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return records

    direction = _detect_direction(filepath)
    basename = os.path.basename(filepath)

    for line in lines:
        line = line.strip()
        if not line:
            continue

        parts = _split_line(line)
        if len(parts) < 3:
            continue

        # Skip header lines
        first_lower = parts[0].lower()
        if first_lower in ("id", "teamviewer id", "partner id", "#"):
            continue

        try:
            conn = _parse_connection_line(parts, direction, basename)
            if conn is not None:
                records.append(conn)
        except Exception:
            # Skip malformed lines gracefully
            continue

    return records


def _parse_connection_line(
    parts: list[str],
    direction: ConnectionDirection,
    source_file: str,
) -> Optional[RMMConnection]:
    """
    Parse a single connection line split into parts.

    Strategies:
    1. Identify the remote ID (first numeric field)
    2. Identify date fields
    3. Identify duration field (HH:MM:SS)
    4. Remaining text fields are user/connection type/UUID
    """
    remote_id = ""
    dt_parsed: Optional[datetime] = None
    dt_str = ""
    end_dt_str = ""
    duration_str = ""
    user = ""
    conn_type = ""
    unique_id = ""

    # Classify each part
    classified: list[tuple[str, str]] = []  # (type, value)

    i = 0
    while i < len(parts):
        part = parts[i].strip()
        if not part:
            i += 1
            continue

        # Check if this is a date (possibly combined with next part for time)
        if _RE_DATE.match(part):
            classified.append(("date", part))
            i += 1
            continue

        # Check if a date could be formed by combining this and next part
        if i + 1 < len(parts):
            combined = part + " " + parts[i + 1].strip()
            if _RE_DATE.match(combined):
                classified.append(("date", combined))
                i += 2
                continue

        # Check for TeamViewer ID
        if _RE_TV_ID.match(part) and not remote_id:
            classified.append(("id", part))
            i += 1
            continue

        # Check for duration (HH:MM:SS)
        if _RE_DURATION.match(part):
            classified.append(("duration", part))
            i += 1
            continue

        # Check for UUID
        if _RE_UUID.match(part):
            classified.append(("uuid", part))
            i += 1
            continue

        # Otherwise treat as text (user or connection type)
        classified.append(("text", part))
        i += 1

    # Extract values from classified parts
    dates_found: list[str] = []
    texts_found: list[str] = []

    for ctype, cval in classified:
        if ctype == "id" and not remote_id:
            remote_id = cval
        elif ctype == "date":
            dates_found.append(cval)
        elif ctype == "duration" and not duration_str:
            duration_str = cval
        elif ctype == "uuid":
            unique_id = cval
        elif ctype == "text":
            texts_found.append(cval)

    # Parse the first date as the main datetime
    if dates_found:
        dt_parsed, dt_str = _parse_dt(dates_found[0])
        if len(dates_found) > 1:
            end_dt_str = dates_found[1]

    # Assign text fields: first is user, second is connection type
    if len(texts_found) >= 2:
        user = texts_found[0]
        conn_type = texts_found[1]
    elif len(texts_found) == 1:
        # Could be user or connection type; treat as user
        user = texts_found[0]

    # Need at least an ID or a date to consider this a valid record
    if not remote_id and not dt_parsed:
        return None

    extras: dict = {}
    if conn_type:
        extras["connection_type"] = conn_type
    if unique_id:
        extras["unique_id"] = unique_id
    if end_dt_str:
        end_dt, _ = _parse_dt(end_dt_str)
        if end_dt:
            extras["end_datetime"] = end_dt

    return RMMConnection(
        rmm_type=RMMType.TEAMVIEWER,
        direction=direction,
        datetime=dt_parsed,
        dt_str=dt_str,
        user=user,
        remote_id=remote_id,
        source_file=source_file,
        duration_str=duration_str,
        extras=extras,
    )
