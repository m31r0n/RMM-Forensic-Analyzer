"""Utilidades compartidas: formato, IPs, encoding, colores."""

from __future__ import annotations
import ipaddress
import os
import re
import sys
from datetime import datetime

# Ensure UTF-8 stdout on Windows (avoids cp1252 UnicodeEncodeError)
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class _F:
        def __getattr__(self, _): return ""
    Fore = Style = _F()

# ─── IPs privadas ────────────────────────────────────────────────────────────

PRIVATE_NETS = [
    ipaddress.ip_network(n) for n in
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
     "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7"]
]


def is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in PRIVATE_NETS)
    except ValueError:
        return True


# ─── Encoding ────────────────────────────────────────────────────────────────

def detect_encoding(filepath: str) -> str:
    """Detecta UTF-16 LE/BE (frecuente en connection_trace.txt de AnyDesk)."""
    try:
        with open(filepath, "rb") as f:
            raw = f.read(4)
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return "utf-16"
        # Sin BOM pero nulos intercalados → UTF-16 LE
        if len(raw) >= 2 and raw[1:2] == b"\x00":
            return "utf-16-le"
    except OSError:
        pass
    return "utf-8"


# ─── Formato ─────────────────────────────────────────────────────────────────

def fmt_dt(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(dt, datetime) else (str(dt) if dt else "—")


def fmt_dur(sec: int | None) -> str:
    if sec is None:
        return "—"
    h, r = divmod(int(sec), 3600)
    m, s = divmod(r, 60)
    if h:   return f"{h}h {m}m {s}s"
    if m:   return f"{m}m {s}s"
    return f"{s}s"


def clean(v) -> str:
    """Elimina caracteres de control ilegales (xlsx no los acepta)."""
    if isinstance(v, str):
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", v)
    return v


# ─── Consola ─────────────────────────────────────────────────────────────────

def cprint(msg: str, color: str = "", bold: bool = False) -> None:
    prefix = (Style.BRIGHT if bold and HAS_COLOR else "") + (color if HAS_COLOR else "")
    text = prefix + msg + (Style.RESET_ALL if HAS_COLOR else "")
    try:
        print(text)
    except UnicodeEncodeError:
        # Fallback: strip non-ASCII so it always prints
        safe = text.encode("ascii", errors="replace").decode("ascii")
        print(safe)


def banner() -> None:
    cprint(r"""
  ╔══════════════════════════════════════════════════════════════╗
  ║   RMM Forensic Analyzer v3.0  —  DFIR Edition              ║
  ║   Multi-RMM · Discovery · Enrichment · Reports             ║
  ╚══════════════════════════════════════════════════════════════╝
""", Fore.CYAN, True)


def sep(char: str = "─", n: int = 62, color: str = "") -> None:
    cprint(char * n, color or Fore.CYAN)
