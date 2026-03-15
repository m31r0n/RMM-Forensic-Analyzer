"""Parser para connection_trace.txt (UTF-16 LE, tabulaciones)."""

from __future__ import annotations
import os
import re
from datetime import datetime

from .legacy_models import Connection
from ...utils import detect_encoding, cprint
try:
    from colorama import Fore
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = ""


_DT_FORMATS = ["%Y-%m-%d, %H:%M", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M", "%Y-%m-%d"]


def _parse_dt(raw: str) -> tuple[datetime | None, str]:
    raw = raw.strip()
    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(raw, fmt), raw
        except ValueError:
            pass
    return None, raw


def parse_connection_trace(filepath: str) -> list[Connection]:
    """
    Parsea connection_trace.txt y devuelve lista de Connection.

    Formato típico (UTF-16 LE, separado por 2+ espacios):
        Incoming    2024-01-10, 09:40    Quino Arias    988319357    988319357
    """
    records: list[Connection] = []

    if not os.path.exists(filepath):
        cprint(f"  [!] No encontrado: {filepath}", Fore.RED)
        return records

    enc = detect_encoding(filepath)
    try:
        with open(filepath, "r", encoding=enc, errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        cprint(f"  [!] Error leyendo {filepath}: {e}", Fore.RED)
        return records

    basename = os.path.basename(filepath)
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Separar por 2+ espacios (tabulaciones AnyDesk)
        parts = re.split(r"\s{2,}", line)
        if len(parts) < 4:
            parts = line.split()
        if len(parts) < 4:
            continue

        direction = parts[0].strip()
        if direction not in ("Incoming", "Outgoing"):
            continue

        dt, dt_str = _parse_dt(parts[1])
        user      = parts[2].strip()
        remote_id = parts[3].strip()
        alias     = parts[4].strip() if len(parts) > 4 else ""
        if alias == remote_id:
            alias = ""

        records.append(Connection(
            direction   = direction,
            datetime    = dt,
            dt_str      = dt_str,
            user        = user,
            remote_id   = remote_id,
            alias       = alias,
            source_file = basename,
        ))

    return records
