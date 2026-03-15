"""
Punto de entrada principal del analizador forense multi-RMM.
    python -m rmm_forensic          -> Menu interactivo
    python -m rmm_forensic --help   -> CLI con flags
    rmm-forensic --help             -> Igual (si instalado con pip)
"""

from __future__ import annotations

import argparse
import os
import sys
import warnings
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import cfg
from .utils import banner, cprint, sep, fmt_dt, fmt_dur
from .models.base import RMMType, RMMSession, RMMConnection, ParseResult
from .models.enrichment import IPEnrichment
from .models.incident import IncidentContext
from .models.summary import ForensicSummary
from .parsers import ParserRegistry
from .discovery import LogDiscoveryEngine, DiscoveredFile
from .analyzer import (
    score_all,
    correlate,
    apply_incident_context,
    classify_sessions_by_country,
)
from .apis import IPCache
from .apis.enrichment import enrich_ips
from .reports import generate_html, generate_xlsx, generate_csvs

# ── Rich (optional, falls back to colorama) ──────────────────────────────────

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

try:
    from colorama import Fore, Style
except ImportError:
    class Fore:                                     # type: ignore[no-redef]
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = ""
    class Style:                                    # type: ignore[no-redef]
        BRIGHT = RESET_ALL = ""


# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS & HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

_VERSION = "3.0"

_INCIDENT_DATE_FORMATS = [
    "%Y-%m-%d",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M",
    "%d/%m/%Y",
    "%d-%m-%Y",
    "%m/%d/%Y",
    "%Y%m%d",
]


def _parse_incident_date(raw: str) -> Optional[datetime]:
    """Try multiple datetime formats; return None on failure."""
    raw = raw.strip()
    for fmt in _INCIDENT_DATE_FORMATS:
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def _parse_rmm_filter(raw: str) -> list[str]:
    """Parse comma-separated RMM names into canonical names for the filter."""
    mapping = {
        "anydesk":       "AnyDesk",
        "teamviewer":    "TeamViewer",
        "screenconnect": "ScreenConnect",
        "chrome":        "Chrome Remote Desktop",
        "chromerd":      "Chrome Remote Desktop",
        "chrome_remote_desktop": "Chrome Remote Desktop",
        "splashtop":     "Splashtop",
        "rustdesk":      "RustDesk",
    }
    names: list[str] = []
    for part in raw.split(","):
        key = part.strip().lower().replace(" ", "").replace("-", "").replace("_", "")
        if key in mapping:
            names.append(mapping[key])
        else:
            for mk, mv in mapping.items():
                if mk.startswith(key) and mv not in names:
                    names.append(mv)
                    break
            else:
                names.append(part.strip())
    return names


def _mask(key: str) -> str:
    """Mask an API key for display."""
    if not key:
        return "No configurada"
    if len(key) > 8:
        return key[:4] + "****" + key[-4:]
    return "****"


def _banner():
    """Display the application banner."""
    if HAS_RICH:
        console = Console()
        console.print(Panel(
            f"[bold cyan]RMM Forensic Analyzer v{_VERSION}[/bold cyan] -- DFIR Edition\n"
            "[dim]AnyDesk . TeamViewer . ScreenConnect . Chrome RD . Splashtop . RustDesk[/dim]",
            border_style="cyan",
        ))
    else:
        banner()


def _status_line(label: str, value: str, ok: bool | None = None) -> str:
    """Build a status line with indicator."""
    if ok is True:
        ico = f"{Fore.GREEN}v{Style.RESET_ALL}"
    elif ok is False:
        ico = f"{Fore.RED}x{Style.RESET_ALL}"
    else:
        ico = f"{Fore.YELLOW}.{Style.RESET_ALL}"
    return f"  {ico} {label}: {value}"


# ═══════════════════════════════════════════════════════════════════════════════
#  DISCOVERY & PARSING ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def _discover_and_parse(
    input_path: str,
    rmm_filter: list[str] | None = None,
    hostname_filter: str = "",
) -> tuple[list[ParseResult], list[DiscoveredFile]]:
    """
    Discover RMM log files in *input_path*, parse each with the
    appropriate parser, and return merged ParseResults grouped by RMM
    together with the list of discovered files.
    """
    engine = LogDiscoveryEngine()
    try:
        discovered = engine.discover(input_path, rmm_filter=rmm_filter)

        if not discovered:
            cprint("  [!] No se encontraron archivos de log RMM", Fore.YELLOW)
            return [], []

        # Print discovery summary
        cprint(f"\n  Archivos descubiertos: {len(discovered)}", Fore.CYAN)
        for d in discovered:
            extra = ""
            if d.hostname:
                extra += f"  host: {d.hostname}"
            if d.user_account:
                extra += f"  user: {d.user_account}"
            cprint(
                f"    [{d.rmm_type}] {d.filename} "
                f"(confianza: {d.confidence}){extra}",
            )
        print()

        # Parse each discovered file
        results_by_rmm: dict[str, ParseResult] = {}

        if HAS_RICH:
            console = Console()
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.completed}/{task.total}"),
                console=console,
            ) as progress:
                task = progress.add_task("Parseando archivos...", total=len(discovered))
                for d in discovered:
                    progress.update(
                        task,
                        description=f"[cyan][{d.rmm_type}][/cyan] {d.filename}",
                    )
                    _parse_single_file(d, results_by_rmm, hostname_filter)
                    progress.advance(task)
        else:
            for i, d in enumerate(discovered, 1):
                cprint(
                    f"  [{i}/{len(discovered)}] [{d.rmm_type}] "
                    f"Parseando: {d.filename}",
                    Fore.CYAN,
                )
                _parse_single_file(d, results_by_rmm, hostname_filter)

    finally:
        engine.cleanup()

    return list(results_by_rmm.values()), discovered


def _parse_single_file(
    d: DiscoveredFile,
    results_by_rmm: dict[str, ParseResult],
    hostname_filter: str,
) -> None:
    """Parse a single discovered file and merge into *results_by_rmm*.

    Uses a composite key ``RMM:hostname:user`` so logs from different
    users/hosts produce separate ParseResult groups.
    """
    parser = ParserRegistry.get_for_file(d.filepath)
    if not parser:
        cprint(f"    [!] Sin parser para: {d.filename}", Fore.YELLOW)
        return

    try:
        hostname = d.hostname or hostname_filter or ""
        result = parser.parse(d.filepath, hostname=hostname)
    except Exception as exc:
        cprint(f"    [ERROR] {d.filename}: {exc}", Fore.RED)
        return

    # Stamp user_account on every session and connection from this file.
    user_account = d.user_account or ""
    if user_account:
        for s in result.sessions:
            if not s.extras.get("user_account"):
                s.extras["user_account"] = user_account
        for c in result.connections:
            if not c.extras.get("user_account"):
                c.extras["user_account"] = user_account

    # Build composite key: RMM:host:user  (separates per-user results).
    key = result.rmm_type.value
    if hostname:
        key += f":{hostname}"
    if user_account:
        key += f":{user_account}"

    if key in results_by_rmm:
        results_by_rmm[key].merge(result)
    else:
        results_by_rmm[key] = result


# ═══════════════════════════════════════════════════════════════════════════════
#  ANALYSIS PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def _run_analysis(
    input_path: str = "",
    rmm_filter: list[str] | None = None,
    incident: IncidentContext | None = None,
    hostname_filter: str = "",
    user_filter: str = "",
    trace_file: str = "",
    conn_file: str = "",
) -> tuple[dict[str, ParseResult], ForensicSummary, list[DiscoveredFile]]:
    """
    Run the full analysis pipeline.

    If trace_file/conn_file are set, uses legacy AnyDesk-only mode.
    Otherwise, uses LogDiscoveryEngine + ParserRegistry for multi-RMM.

    Returns (results_by_rmm, summary, discovered_files).
    """
    results: dict[str, ParseResult] = {}
    discovered: list[DiscoveredFile] = []

    # ── Legacy mode (--trace / --conn) ────────────────────────────────────
    if trace_file or conn_file:
        cprint("  [!] Modo legacy: usando parser AnyDesk directo", Fore.YELLOW)
        parser = ParserRegistry.get(RMMType.ANYDESK)
        if not parser:
            cprint("  [ERROR] Parser de AnyDesk no disponible", Fore.RED)
            return results, ForensicSummary(), discovered

        ad_result = ParseResult(rmm_type=RMMType.ANYDESK)

        if trace_file and os.path.exists(trace_file):
            cprint(f"  -> Parseando ad.trace: {trace_file}", Fore.CYAN)
            pr = parser.parse(trace_file, hostname=hostname_filter)
            ad_result.merge(pr)
            cprint(
                f"    {len(pr.sessions)} sesiones, "
                f"{pr.total_events} eventos",
                Fore.GREEN,
            )

        if conn_file and os.path.exists(conn_file):
            cprint(f"  -> Parseando connection_trace: {conn_file}", Fore.CYAN)
            pr = parser.parse(conn_file, hostname=hostname_filter)
            ad_result.merge(pr)
            cprint(f"    {len(pr.connections)} conexiones", Fore.GREEN)

        if ad_result.sessions or ad_result.connections:
            score_all(ad_result.sessions)
            results[RMMType.ANYDESK.value] = ad_result

    # ── Multi-RMM discovery mode ──────────────────────────────────────────
    elif input_path:
        cprint(f"  -> Descubriendo archivos RMM en: {input_path}", Fore.CYAN)
        parse_results, discovered = _discover_and_parse(
            input_path,
            rmm_filter=rmm_filter,
            hostname_filter=hostname_filter,
        )

        for idx, pr in enumerate(parse_results):
            score_all(pr.sessions)
            # Use the RMM type as base key; append index if there are
            # multiple ParseResults for the same RMM (different users).
            rmm_name = pr.rmm_type.value
            key = rmm_name
            if key in results:
                key = f"{rmm_name}_{idx}"
            results[key] = pr
            # Build display label with host/user info.
            label = rmm_name
            if pr.hostname:
                label += f" ({pr.hostname})"
            # Check if sessions carry user_account info.
            user_accounts = {
                s.extras.get("user_account", "")
                for s in pr.sessions if s.extras.get("user_account")
            } | {
                c.extras.get("user_account", "")
                for c in pr.connections if c.extras.get("user_account")
            }
            if user_accounts:
                label += f" [{', '.join(sorted(user_accounts))}]"
            cprint(
                f"    {label}: {len(pr.sessions)} sesiones, "
                f"{len(pr.connections)} conexiones",
                Fore.GREEN,
            )

    # ── Incident context ──────────────────────────────────────────────────
    if incident and incident.has_incident_date:
        all_sessions = _collect_all_sessions(results)
        for s in all_sessions:
            if s.start_dt:
                s.incident_proximity_hours = incident.proximity_hours(s.start_dt)
                s.incident_proximity_label = incident.classify_proximity(s.start_dt)

    # ── Correlation ───────────────────────────────────────────────────────
    summary = correlate(results, incident=incident)

    return results, summary, discovered


def _collect_all_public_ips(results: dict[str, ParseResult]) -> set[str]:
    """Collect all public IPs from all parse results."""
    ips: set[str] = set()
    for pr in results.values():
        ips |= pr.public_ips
    return ips


def _collect_all_sessions(results: dict[str, ParseResult]) -> list[RMMSession]:
    """Collect all sessions from all parse results, sorted by date."""
    sessions: list[RMMSession] = []
    for pr in results.values():
        sessions.extend(pr.sessions)
    return sorted(sessions, key=lambda s: s.start_dt or datetime.min)


def _collect_source_files(
    results: dict[str, ParseResult],
    discovered: list[DiscoveredFile],
) -> list[str]:
    """Collect all source file paths."""
    files: list[str] = []
    for pr in results.values():
        files.extend(pr.source_files)
    for d in discovered:
        if d.filepath not in files:
            files.append(d.filepath)
    return files


# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_outputs(
    results: dict[str, ParseResult],
    summary: ForensicSummary,
    ip_results: list[IPEnrichment],
    output_dir: str,
    incident_ctx: IncidentContext | None = None,
    source_files: list[str] | None = None,
    do_html: bool = True,
    do_xlsx: bool = True,
    do_csv: bool = True,
) -> None:
    """Generate report files. Handles missing report modules gracefully."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    meta = {"files": source_files or []}

    # ── HTML ──────────────────────────────────────────────────────────
    if do_html:
        out = os.path.join(output_dir, "informe_rmm_forensic.html")
        try:
            html = generate_html(
                summary,
                ip_results,
                incident=incident_ctx,
                meta=meta,
            )
            with open(out, "w", encoding="utf-8") as f:
                f.write(html)
            cprint(f"  [v] HTML -> {out}", Fore.GREEN)
        except Exception as exc:
            cprint(f"  [ERROR] HTML: {exc}", Fore.RED)

    # ── XLSX ──────────────────────────────────────────────────────────
    if do_xlsx:
        out = os.path.join(output_dir, "informe_rmm_forensic.xlsx")
        try:
            generate_xlsx(
                summary=summary,
                ip_results=ip_results,
                outpath=out,
                incident=incident_ctx,
            )
            cprint(f"  [v] XLSX -> {out}", Fore.GREEN)
        except Exception as exc:
            cprint(f"  [ERROR] XLSX: {exc}", Fore.RED)

    # ── CSV ───────────────────────────────────────────────────────────
    if do_csv:
        csv_dir = os.path.join(output_dir, "csv")
        try:
            generate_csvs(
                summary=summary,
                ip_results=ip_results,
                outdir=csv_dir,
                incident=incident_ctx,
            )
            cprint(f"  [v] CSV  -> {csv_dir}/", Fore.GREEN)
        except Exception as exc:
            cprint(f"  [ERROR] CSV: {exc}", Fore.RED)


# ═══════════════════════════════════════════════════════════════════════════════
#  CONSOLE SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

def _print_console_summary(
    results: dict[str, ParseResult],
    summary: ForensicSummary,
    ip_results: list[IPEnrichment],
    incident: IncidentContext | None = None,
) -> None:
    """Print a detailed forensic summary to the console, organized by RMM."""
    print()
    sep("=")
    cprint("  RESUMEN FORENSE MULTI-RMM", Fore.CYAN, True)
    sep("=")

    # ── Global stats ──────────────────────────────────────────────────────
    kv = [
        ("RMMs detectados",         ", ".join(summary.rmm_types_found) or "--"),
        ("Hosts analizados",        ", ".join(summary.hostnames_found) or "--"),
        ("Conexiones totales",      summary.total_connections),
        ("  -> Entrantes",          summary.incoming),
        ("  -> Salientes",          summary.outgoing),
        ("Sesiones totales",        summary.total_sessions),
        ("IDs remotos unicos",      len(summary.unique_ids)),
        ("File transfers",          summary.total_file_transfers),
        ("Sesiones con elevacion",  summary.elevated_sessions),
        ("Clipboard events",        summary.total_clipboard),
        ("Text transfers",          summary.total_text_transfers),
        ("Max archivos clipboard",  summary.max_clipboard_files),
        ("IPs publicas unicas",     len(summary.all_public_ips)),
    ]

    for label, val in kv:
        marker = ""
        if label in ("File transfers", "Sesiones con elevacion") and val:
            marker = f" {Fore.RED}<< REVISAR{Style.RESET_ALL}"
        cprint(f"  {label:<35} {val}{marker}")

    # ── Date ranges ───────────────────────────────────────────────────────
    if summary.date_range_conn:
        cprint(
            f"  {'Rango conexiones':<35} "
            f"{fmt_dt(summary.date_range_conn[0])} - "
            f"{fmt_dt(summary.date_range_conn[1])}",
        )
    if summary.date_range_sessions:
        cprint(
            f"  {'Rango sesiones':<35} "
            f"{fmt_dt(summary.date_range_sessions[0])} - "
            f"{fmt_dt(summary.date_range_sessions[1])}",
        )

    # ── Per-RMM sections ─────────────────────────────────────────────────
    for rmm_name in sorted(results.keys()):
        pr = results[rmm_name]
        print()
        sep("-", 50)
        cprint(f"  [{rmm_name}]", Fore.CYAN, True)
        sep("-", 50)

        cprint(f"  Sesiones:    {len(pr.sessions)}")
        cprint(f"  Conexiones:  {len(pr.connections)}")
        cprint(f"  IPs:         {len(pr.public_ips)}")
        cprint(f"  Errores:     {pr.error_count}")
        if pr.source_files:
            cprint(f"  Archivos:    {', '.join(pr.source_files)}")
        if pr.hostname:
            cprint(f"  Hostname:    {pr.hostname}")
        if pr.tool_versions:
            cprint(f"  Versiones:   {', '.join(pr.tool_versions)}")

        if pr.sessions:
            print()
            hdr = (
                f"  {'#':>3}  {'ID Remoto':<14} {'Alias':<18} "
                f"{'Inicio':<20} {'FT':>3} {'CB':>4} {'Riesgo':<10}"
            )
            cprint(hdr, Fore.CYAN)
            for s in pr.sessions:
                color = (
                    Fore.RED if s.risk == "CRÍTICO" else
                    Fore.YELLOW if s.risk == "ALTO" else
                    Fore.WHITE
                )
                proximity = ""
                if s.incident_proximity_label:
                    proximity = f" [{s.incident_proximity_label}]"
                country = ""
                if s.country_classification:
                    country = f" ({s.country_classification})"

                line = (
                    f"  {s.idx:>3}  {s.remote_id:<14} "
                    f"{(s.alias or '--')[:18]:<18} "
                    f"{fmt_dt(s.start_dt):<20} "
                    f"{s.file_transfers:>3} {s.clipboard_events:>4} "
                    f"{s.risk:<10}{proximity}{country}"
                )
                cprint(line, color)

    # ── Cross-RMM correlation ─────────────────────────────────────────────
    if summary.cross_rmm_ips:
        print()
        sep("-", 50)
        cprint("  CORRELACION CROSS-RMM (IPs compartidas)", Fore.CYAN, True)
        sep("-", 50)
        for ip, rmms in summary.cross_rmm_ips.items():
            cprint(f"  {ip:<20} -> {', '.join(rmms)}", Fore.YELLOW)

    # ── Incident proximity ────────────────────────────────────────────────
    if incident and incident.has_incident_date:
        print()
        sep("-", 50)
        cprint(
            f"  PROXIMIDAD AL INCIDENTE ({fmt_dt(incident.incident_date)})",
            Fore.CYAN, True,
        )
        sep("-", 50)

        if summary.sessions_within_24h:
            cprint(
                f"  Sesiones +-24h (CRÍTICO): "
                f"{len(summary.sessions_within_24h)}",
                Fore.RED, True,
            )
            for s in summary.sessions_within_24h:
                h = s.incident_proximity_hours
                if h is not None:
                    cprint(
                        f"    {s.rmm_type.value}: {s.remote_id} "
                        f"@ {fmt_dt(s.start_dt)} ({h:.1f}h del incidente)",
                        Fore.RED,
                    )
                else:
                    cprint(
                        f"    {s.rmm_type.value}: {s.remote_id} "
                        f"@ {fmt_dt(s.start_dt)}",
                        Fore.RED,
                    )

        if summary.sessions_within_3d:
            extra_3d = (
                len(summary.sessions_within_3d)
                - len(summary.sessions_within_24h)
            )
            if extra_3d > 0:
                cprint(
                    f"  Sesiones +-3d (ALTO):     {extra_3d} adicionales",
                    Fore.YELLOW,
                )

        if summary.sessions_within_7d:
            extra_7d = (
                len(summary.sessions_within_7d)
                - len(summary.sessions_within_3d)
            )
            if extra_7d > 0:
                cprint(
                    f"  Sesiones +-7d (MEDIO):    {extra_7d} adicionales",
                    Fore.WHITE,
                )

        if summary.anomalous_patterns:
            print()
            cprint("  Patrones anomalos detectados:", Fore.RED, True)
            for pat in summary.anomalous_patterns:
                cprint(f"    !! {pat}", Fore.RED)

    # ── Country classification ────────────────────────────────────────────
    if incident and incident.has_country:
        print()
        sep("-", 50)
        cprint(
            f"  CLASIFICACION POR PAIS (origen: {incident.origin_country})",
            Fore.CYAN, True,
        )
        sep("-", 50)
        cprint(f"  Sesiones informativas: {summary.informative_sessions}")
        cprint(
            f"  Sesiones sospechosas:  {summary.suspicious_sessions}",
            Fore.YELLOW if summary.suspicious_sessions else "",
        )

    # ── IP enrichment results ─────────────────────────────────────────────
    if ip_results:
        print()
        sep("-", 50)
        cprint("  ENRIQUECIMIENTO DE IPs", Fore.CYAN, True)
        sep("-", 50)
        for e in ip_results:
            parts = [f"{e.ip:<18}"]
            if e.country:
                parts.append(f"Pais={e.country}")
            if e.abuse_score is not None:
                color = (
                    Fore.RED if e.abuse_score >= 75
                    else (Fore.YELLOW if e.abuse_score >= 25 else Fore.GREEN)
                )
                parts.append(f"Abuse={color}{e.abuse_score}%{Style.RESET_ALL}")
            if e.vt_malicious is not None and e.vt_malicious > 0:
                parts.append(f"{Fore.RED}VT={e.vt_malicious} mal{Style.RESET_ALL}")
            if e.is_tor:
                parts.append(f"{Fore.RED}TOR{Style.RESET_ALL}")
            if hasattr(e, "criminalip_is_vpn") and e.criminalip_is_vpn:
                parts.append(f"{Fore.YELLOW}VPN{Style.RESET_ALL}")
            cprint(f"  {' | '.join(parts)}")

    # ── Risk distribution ─────────────────────────────────────────────────
    if summary.risk_dist:
        print()
        sep("-", 50)
        cprint("  DISTRIBUCION DE RIESGO", Fore.CYAN, True)
        sep("-", 50)
        for level in ["CRÍTICO", "ALTO", "MEDIO", "BAJO"]:
            count = summary.risk_dist.get(level, 0)
            if count:
                color = (
                    Fore.RED if level == "CRÍTICO" else
                    Fore.YELLOW if level == "ALTO" else
                    Fore.WHITE
                )
                cprint(f"  {level:<10} {count}", color)

    print()


# ═══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ═══════════════════════════════════════════════════════════════════════════════

def menu() -> None:
    """Interactive menu for the forensic analyzer."""
    _banner()

    # ── Persistent state ──────────────────────────────────────────────────
    input_path:  str = ""
    output_dir:  str = cfg.output_dir
    rmm_filter:  list[str] = []
    incident     = IncidentContext()
    results:     dict[str, ParseResult] = {}
    summary      = ForensicSummary()
    ip_results:  list[IPEnrichment] = []
    discovered:  list[DiscoveredFile] = []
    cache        = IPCache(cfg.get("ip_cache_file", "ip_cache.json"))
    analyzed     = False
    hostname_filter: str = ""
    user_filter:     str = ""

    if HAS_RICH:
        console = Console()

    def _prompt(text: str, default: str = "") -> str:
        if HAS_RICH:
            return Prompt.ask(f"  {text}", default=default or None) or ""
        val = input(f"  {text} [{default or '--'}]: ").strip()
        return val if val else default

    while True:
        print()

        # ── Menu display ──────────────────────────────────────────────────
        if HAS_RICH:
            menu_table = Table(show_header=False, box=None, padding=(0, 2))
            menu_table.add_column("opt", style="bold cyan", width=5)
            menu_table.add_column("desc")
            menu_table.add_row("[1]", "Configurar entrada (ruta a logs / ZIP / carpeta KAPE)")
            menu_table.add_row("[2]", "Configurar parametros (RMM, fecha incidente, pais, hostname)")
            menu_table.add_row("[3]", "Configurar API keys")
            menu_table.add_row("[4]", "Descubrir y analizar logs")
            menu_table.add_row("[5]", "Consultar IPs con APIs")
            menu_table.add_row("[6]", "Generar informes (HTML / XLSX / CSV)")
            menu_table.add_row("[7]", "Ver resumen en consola")
            menu_table.add_row("[8]", "Cache de IPs (ver / limpiar)")
            menu_table.add_row("[0]", "Salir")
            console.print(Panel(menu_table, title="MENU PRINCIPAL", border_style="cyan"))
        else:
            sep("-", 64)
            cprint("  MENU PRINCIPAL", Fore.CYAN, True)
            sep("-", 64)
            menu_items = [
                ("1", "Configurar entrada (ruta a logs / ZIP / carpeta KAPE)"),
                ("2", "Configurar parametros (RMM, fecha incidente, pais, hostname)"),
                ("3", "Configurar API keys"),
                ("4", "Descubrir y analizar logs"),
                ("5", "Consultar IPs con APIs"),
                ("6", "Generar informes (HTML / XLSX / CSV)"),
                ("7", "Ver resumen en consola"),
                ("8", "Cache de IPs (ver / limpiar)"),
                ("0", "Salir"),
            ]
            for n, txt in menu_items:
                cprint(f"  [{n}] {txt}")
            sep("-", 64)

        # ── Status display ────────────────────────────────────────────────
        rmm_label = ", ".join(rmm_filter) if rmm_filter else "Todos"
        disc_label = "No"
        if discovered:
            by_rmm: dict[str, int] = {}
            for df in discovered:
                by_rmm[df.rmm_type] = by_rmm.get(df.rmm_type, 0) + 1
            parts = [f"{c} {n}" for n, c in by_rmm.items()]
            disc_label = f"{len(discovered)} descubiertos ({', '.join(parts)})"

        analyzed_label = "No"
        if analyzed:
            total_sess = sum(len(pr.sessions) for pr in results.values())
            total_conn = sum(len(pr.connections) for pr in results.values())
            analyzed_label = (
                f"Si ({total_sess} sesiones, {total_conn} conexiones)"
            )

        incident_label = "--"
        if incident.has_incident_date:
            incident_label = fmt_dt(incident.incident_date)
            if incident.has_country:
                incident_label += f" | Pais: {incident.origin_country}"

        if HAS_RICH:
            st = Table(show_header=False, box=None, padding=(0, 1))
            st.add_column("label", style="dim", width=18)
            st.add_column("value")
            st.add_row("Entrada:", input_path or "[dim]No configurada[/dim]")
            st.add_row("RMM Filter:", rmm_label)
            st.add_row("Archivos:", disc_label)
            st.add_row("Analizado:", analyzed_label)
            st.add_row("Incidente:", incident_label)
            st.add_row("Hostname:", hostname_filter or "[dim]--[/dim]")
            st.add_row("Usuario:", user_filter or "[dim]--[/dim]")
            st.add_row(
                "VT:",
                f"[green]v[/green] {_mask(cfg.vt_key)}"
                if cfg.vt_key
                else "[red]x[/red] No configurada",
            )
            st.add_row(
                "AbuseIPDB:",
                f"[green]v[/green] {_mask(cfg.abuse_key)}"
                if cfg.abuse_key
                else "[red]x[/red] No configurada",
            )
            st.add_row(
                "CriminalIP:",
                f"[green]v[/green] {_mask(cfg.criminalip_key)}"
                if cfg.criminalip_key
                else "[red]x[/red] No configurada",
            )
            st.add_row("Salida:", output_dir)
            console.print(Panel(st, title="Estado", border_style="dim"))
        else:
            print(_status_line("Entrada",     input_path or "No configurada", bool(input_path)))
            print(_status_line("RMM Filter",  rmm_label))
            print(_status_line("Archivos",    disc_label,                     bool(discovered)))
            print(_status_line("Analizado",   analyzed_label,                 analyzed))
            print(_status_line("Incidente",   incident_label))
            print(_status_line("Hostname",    hostname_filter or "--"))
            print(_status_line("Usuario",     user_filter or "--"))
            print(_status_line("VT API",      _mask(cfg.vt_key),              bool(cfg.vt_key)))
            print(_status_line("AbuseIPDB",   _mask(cfg.abuse_key),           bool(cfg.abuse_key)))
            print(_status_line("CriminalIP",  _mask(cfg.criminalip_key),      bool(cfg.criminalip_key)))
            print(_status_line("Salida",      output_dir))
            sep("-", 64)

        choice = input("  Opcion: ").strip()

        # ── 1: Configure input ────────────────────────────────────────────
        if choice == "1":
            print()
            p = _prompt(
                "Ruta de entrada (directorio / ZIP / archivo)",
                input_path,
            )
            if p and not os.path.exists(p):
                cprint(f"  [!] No existe: {p}", Fore.RED)
            elif p:
                input_path = p
                discovered = []
                analyzed = False
                results = {}
                ip_results = []

            d = _prompt("Directorio de salida", output_dir)
            if d:
                output_dir = d
                cfg.set("default_output_dir", d)

        # ── 2: Configure parameters ──────────────────────────────────────
        elif choice == "2":
            print()
            cprint("  CONFIGURACION DE PARAMETROS", Fore.CYAN, True)
            print()

            # RMM filter
            r = _prompt(
                "Filtrar RMMs (separados por coma, vacio=todos)",
                ", ".join(rmm_filter),
            )
            if r and r != "--":
                rmm_filter = _parse_rmm_filter(r)
                cprint(f"  [v] Filtro RMM: {', '.join(rmm_filter)}", Fore.GREEN)
            elif not r or r == "--":
                rmm_filter = []

            # Incident date
            date_str = _prompt(
                "Fecha del incidente (YYYY-MM-DD o vacio para omitir)",
                fmt_dt(incident.incident_date) if incident.incident_date else "",
            )
            if date_str and date_str != "--":
                dt = _parse_incident_date(date_str)
                if dt:
                    incident.incident_date = dt
                    cprint(f"  [v] Fecha: {fmt_dt(dt)}", Fore.GREEN)
                else:
                    cprint(f"  [!] Formato no reconocido: {date_str}", Fore.RED)
                    cprint(
                        "      Formatos aceptados: YYYY-MM-DD, "
                        "YYYY-MM-DDTHH:MM:SS, DD/MM/YYYY",
                        Fore.YELLOW,
                    )

            # Country
            country = _prompt(
                "Pais de origen (codigo ISO, ej: MX, CO, AR)",
                incident.origin_country,
            )
            if country and country != "--":
                incident.origin_country = country.upper().strip()
                cprint(f"  [v] Pais: {incident.origin_country}", Fore.GREEN)

            # Hostname
            hn = _prompt("Filtrar por hostname", hostname_filter)
            if hn and hn != "--":
                hostname_filter = hn
                incident.hostname_filter = hn
            elif hn == "--":
                hostname_filter = ""
                incident.hostname_filter = ""

            # User
            user = _prompt("Filtrar por usuario", user_filter)
            if user and user != "--":
                user_filter = user
                incident.user_filter = user
            elif user == "--":
                user_filter = ""
                incident.user_filter = ""

        # ── 3: Configure API keys ─────────────────────────────────────────
        elif choice == "3":
            print()
            cprint("  CONFIGURACION DE API KEYS", Fore.CYAN, True)
            cprint("  Las claves se guardan en config.json (excluido de Git).")
            cprint(
                "  Variables de entorno: VT_API_KEY / "
                "ABUSEIPDB_API_KEY / CRIMINALIP_API_KEY"
            )
            print()

            vt = input(f"  VirusTotal API Key [{_mask(cfg.vt_key)}]: ").strip()
            if vt == "-":
                cfg.vt_key = ""
            elif vt and not vt.endswith("****"):
                cfg.vt_key = vt

            ab = input(f"  AbuseIPDB API Key  [{_mask(cfg.abuse_key)}]: ").strip()
            if ab == "-":
                cfg.abuse_key = ""
            elif ab and not ab.endswith("****"):
                cfg.abuse_key = ab

            cip = input(
                f"  CriminalIP API Key [{_mask(cfg.criminalip_key)}]: "
            ).strip()
            if cip == "-":
                cfg.criminalip_key = ""
            elif cip and not cip.endswith("****"):
                cfg.criminalip_key = cip

            print()
            cprint("  Donde guardar?")
            cprint("  [1] config.json local (junto al proyecto)  <- recomendado")
            cprint("  [2] ~/.rmm_forensic/config.json            (global)")
            cprint("  [0] No guardar (solo en memoria)")
            save_choice = input("  Opcion: ").strip()

            if save_choice == "1":
                p = cfg.save_local()
                cprint(f"  [v] Guardado en: {p}", Fore.GREEN)
            elif save_choice == "2":
                p = cfg.save_global()
                cprint(f"  [v] Guardado en: {p}", Fore.GREEN)
            else:
                cprint("  [.] API keys en memoria (no persistidas)", Fore.YELLOW)

        # ── 4: Discover & analyze ─────────────────────────────────────────
        elif choice == "4":
            if not input_path:
                cprint(
                    "  [!] Configura la ruta de entrada primero (opcion 1)",
                    Fore.RED,
                )
                continue

            analyzed = False
            ip_results = []

            results, summary, discovered = _run_analysis(
                input_path=input_path,
                rmm_filter=rmm_filter or None,
                incident=incident if incident.has_incident_date else None,
                hostname_filter=hostname_filter,
                user_filter=user_filter,
            )

            if results:
                analyzed = True
                total_s = sum(len(pr.sessions) for pr in results.values())
                total_c = sum(len(pr.connections) for pr in results.values())
                cprint(
                    f"\n  [v] Analisis completado: {total_s} sesiones, "
                    f"{total_c} conexiones en {len(results)} RMM(s)",
                    Fore.GREEN, True,
                )

                # Apply country classification if configured
                if incident.has_country:
                    all_sessions = _collect_all_sessions(results)
                    classify_sessions_by_country(
                        all_sessions, ip_results, incident,
                    )
                    summary.informative_sessions = sum(
                        1 for s in all_sessions
                        if s.country_classification == "Informativa"
                    )
                    summary.suspicious_sessions = sum(
                        1 for s in all_sessions
                        if s.country_classification == "Sospechosa"
                    )
            else:
                cprint(
                    "  [!] No se obtuvieron resultados del analisis",
                    Fore.YELLOW,
                )

        # ── 5: Enrich IPs ─────────────────────────────────────────────────
        elif choice == "5":
            if not analyzed:
                cprint(
                    "  [!] Ejecuta el analisis primero (opcion 4)",
                    Fore.RED,
                )
                continue

            if not cfg.vt_key and not cfg.abuse_key and not cfg.criminalip_key:
                cprint(
                    "  [!] Configura al menos una API key (opcion 3)",
                    Fore.YELLOW,
                )
                continue

            all_ips = _collect_all_public_ips(results)
            if not all_ips:
                cprint("  [!] No se encontraron IPs publicas", Fore.YELLOW)
                continue

            cprint(f"  Consultando {len(all_ips)} IPs...", Fore.CYAN)
            ip_results = enrich_ips(all_ips, cache, cfg)
            cache.save()
            cprint(
                f"  [v] {len(ip_results)} IPs enriquecidas. "
                f"Cache: {cache.stats()}",
                Fore.GREEN,
            )

            # Apply country classification if incident context has country
            if incident.has_country and ip_results:
                all_sessions = _collect_all_sessions(results)
                apply_incident_context(all_sessions, ip_results, incident)
                classify_sessions_by_country(
                    all_sessions, ip_results, incident,
                )
                summary.informative_sessions = sum(
                    1 for s in all_sessions
                    if s.country_classification == "Informativa"
                )
                summary.suspicious_sessions = sum(
                    1 for s in all_sessions
                    if s.country_classification == "Sospechosa"
                )

        # ── 6: Generate reports ───────────────────────────────────────────
        elif choice == "6":
            if not analyzed:
                cprint(
                    "  [!] Ejecuta el analisis primero (opcion 4)",
                    Fore.RED,
                )
                continue

            print()
            cprint("  Formatos a generar:")
            cprint("  [1] Todos (HTML + XLSX + CSV)")
            cprint("  [2] Solo HTML")
            cprint("  [3] Solo XLSX")
            cprint("  [4] Solo CSV")
            fmt_choice = input("  Opcion [1]: ").strip() or "1"

            do_h = fmt_choice in ("1", "2")
            do_x = fmt_choice in ("1", "3")
            do_c = fmt_choice in ("1", "4")

            source_files = _collect_source_files(results, discovered)
            incident_ctx = incident if incident.has_incident_date else None

            _generate_outputs(
                results, summary, ip_results, output_dir,
                incident_ctx=incident_ctx,
                source_files=source_files,
                do_html=do_h, do_xlsx=do_x, do_csv=do_c,
            )
            cprint(f"\n  [v] Informes en: {output_dir}/", Fore.GREEN)

        # ── 7: Console summary ────────────────────────────────────────────
        elif choice == "7":
            if not analyzed:
                cprint(
                    "  [!] Ejecuta el analisis primero (opcion 4)",
                    Fore.RED,
                )
                continue
            _print_console_summary(
                results, summary, ip_results,
                incident=incident if incident.has_incident_date else None,
            )

        # ── 8: IP Cache ───────────────────────────────────────────────────
        elif choice == "8":
            print()
            cprint(f"  Estado cache: {cache.stats()}", Fore.CYAN)
            cprint("  [1] Limpiar toda la cache")
            cprint("  [2] Purgar solo expiradas")
            cprint("  [0] Volver")
            cc = input("  Opcion: ").strip()
            if cc == "1":
                n = cache.clear()
                cprint(f"  [v] {n} entradas eliminadas", Fore.GREEN)
            elif cc == "2":
                n = cache.purge_expired()
                cprint(f"  [v] {n} entradas expiradas eliminadas", Fore.GREEN)

        # ── 0: Exit ───────────────────────────────────────────────────────
        elif choice == "0":
            cprint("\n  Hasta pronto.\n", Fore.CYAN)
            sys.exit(0)

        else:
            cprint(f"  [!] Opcion '{choice}' no reconocida.", Fore.RED)


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI MODE
# ═══════════════════════════════════════════════════════════════════════════════

def cli_mode(args: argparse.Namespace) -> None:
    """Run the analyzer in non-interactive CLI mode."""
    # Override API keys from CLI flags
    if args.vt_key:
        cfg.vt_key = args.vt_key
    if args.abuse_key:
        cfg.abuse_key = args.abuse_key
    if args.criminalip_key:
        cfg.criminalip_key = args.criminalip_key

    output_dir = args.output or cfg.output_dir
    _banner()

    cache = IPCache(cfg.get("ip_cache_file", "ip_cache.json"))

    # ── Build incident context ────────────────────────────────────────────
    incident: IncidentContext | None = None
    if args.incident_date:
        dt = _parse_incident_date(args.incident_date)
        if dt:
            incident = IncidentContext(incident_date=dt)
            if args.country:
                incident.origin_country = args.country.upper()
            if args.hostname:
                incident.hostname_filter = args.hostname
            if args.user:
                incident.user_filter = args.user
            cprint(f"  -> Contexto de incidente: {fmt_dt(dt)}", Fore.CYAN)
        else:
            cprint(
                f"  [!] Formato de fecha no reconocido: {args.incident_date}",
                Fore.RED,
            )
            sys.exit(1)
    elif args.country:
        incident = IncidentContext(origin_country=args.country.upper())

    # ── Parse RMM filter ──────────────────────────────────────────────────
    rmm_filter: list[str] | None = None
    if args.rmm:
        rmm_filter = _parse_rmm_filter(args.rmm)
        cprint(f"  -> Filtro RMM: {', '.join(rmm_filter)}", Fore.CYAN)

    # ── Legacy flag handling ──────────────────────────────────────────────
    trace_file = ""
    conn_file = ""
    if args.trace or args.conn:
        warnings.warn(
            "Los flags --trace y --conn estan deprecados. "
            "Usa --input <directorio> para analisis multi-RMM.",
            DeprecationWarning,
            stacklevel=2,
        )
        cprint(
            "  [DEPRECADO] --trace/--conn seran eliminados en v4.0. "
            "Usa --input <directorio>.",
            Fore.YELLOW,
        )
        trace_file = args.trace or ""
        conn_file = args.conn or ""

    # ── Run analysis ──────────────────────────────────────────────────────
    input_path = args.input or ""
    results, summary, discovered = _run_analysis(
        input_path=input_path,
        rmm_filter=rmm_filter,
        incident=incident,
        hostname_filter=args.hostname or "",
        user_filter=args.user or "",
        trace_file=trace_file,
        conn_file=conn_file,
    )

    if not results:
        cprint(
            "  [!] No se obtuvieron resultados. Verifica la ruta de entrada.",
            Fore.YELLOW,
        )
        sys.exit(1)

    # ── Country classification ────────────────────────────────────────────
    if incident and incident.has_country:
        all_sessions = _collect_all_sessions(results)
        classify_sessions_by_country(all_sessions, [], incident)
        summary.informative_sessions = sum(
            1 for s in all_sessions
            if s.country_classification == "Informativa"
        )
        summary.suspicious_sessions = sum(
            1 for s in all_sessions
            if s.country_classification == "Sospechosa"
        )

    # ── IP enrichment ─────────────────────────────────────────────────────
    ip_results: list[IPEnrichment] = []
    if not args.no_api:
        all_ips = _collect_all_public_ips(results)
        if (cfg.vt_key or cfg.abuse_key or cfg.criminalip_key) and all_ips:
            cprint(f"  -> Enriqueciendo {len(all_ips)} IPs...", Fore.CYAN)
            ip_results = enrich_ips(all_ips, cache, cfg)
            cache.save()
            cprint(f"  [v] {len(ip_results)} IPs enriquecidas", Fore.GREEN)

            # Apply country classification with enrichment data
            if incident and incident.has_country:
                all_sessions = _collect_all_sessions(results)
                apply_incident_context(all_sessions, ip_results, incident)
                classify_sessions_by_country(
                    all_sessions, ip_results, incident,
                )
                summary.informative_sessions = sum(
                    1 for s in all_sessions
                    if s.country_classification == "Informativa"
                )
                summary.suspicious_sessions = sum(
                    1 for s in all_sessions
                    if s.country_classification == "Sospechosa"
                )

    # ── Console summary ──────────────────────────────────────────────────
    if args.summary:
        _print_console_summary(results, summary, ip_results, incident=incident)

    # ── Generate reports ──────────────────────────────────────────────────
    source_files = _collect_source_files(results, discovered)
    incident_ctx = incident if (incident and incident.has_incident_date) else None

    _generate_outputs(
        results, summary, ip_results, output_dir,
        incident_ctx=incident_ctx,
        source_files=source_files,
        do_html=not args.no_html,
        do_xlsx=not args.no_xlsx,
        do_csv=not args.no_csv,
    )

    cprint(f"\n  [v] Completado -> {output_dir}/\n", Fore.GREEN, True)


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    p = argparse.ArgumentParser(
        prog="rmm-forensic",
        description=(
            f"RMM Forensic Analyzer v{_VERSION} -- DFIR Edition (Multi-RMM)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Variables de entorno (alternativa a config.json):
  VT_API_KEY           VirusTotal API key
  ABUSEIPDB_API_KEY    AbuseIPDB API key
  CRIMINALIP_API_KEY   CriminalIP API key

Ejemplos:
  # Menu interactivo:
  rmm-forensic

  # Analisis de directorio completo (multi-RMM):
  rmm-forensic --input /ruta/al/caso

  # Solo AnyDesk y TeamViewer:
  rmm-forensic --input /caso --rmm anydesk,teamviewer

  # Con fecha de incidente y pais:
  rmm-forensic --input /caso --incident-date 2024-03-15 --country MX

  # Con APIs y directorio de salida:
  rmm-forensic --input /caso --vt-key TU_KEY --abuse-key TU_KEY \\
      --criminalip-key TU_KEY --output caso_2024/

  # Solo resumen en consola, sin archivos:
  rmm-forensic --input /caso --summary --no-html --no-xlsx --no-csv

  # Legacy (deprecado): archivos AnyDesk individuales:
  rmm-forensic --trace ad.trace --conn connection_trace.txt
""",
    )

    # Main input
    p.add_argument(
        "--input", metavar="PATH",
        help="Directorio, ZIP o archivo de entrada (multi-RMM)",
    )

    # RMM filter
    p.add_argument(
        "--rmm", metavar="LIST",
        help=(
            "Filtrar RMMs (separados por coma): "
            "anydesk,teamviewer,screenconnect,chrome,splashtop,rustdesk"
        ),
    )

    # Incident context
    p.add_argument(
        "--incident-date", dest="incident_date", metavar="DATE",
        help="Fecha del incidente (YYYY-MM-DD o YYYY-MM-DDTHH:MM:SS)",
    )
    p.add_argument(
        "--country", metavar="CC",
        help="Codigo ISO del pais de origen (ej: MX, CO, AR)",
    )
    p.add_argument(
        "--hostname", metavar="NAME",
        help="Filtrar por hostname especifico",
    )
    p.add_argument(
        "--user", metavar="USERNAME",
        help="Filtrar por nombre de usuario",
    )

    # API keys
    p.add_argument(
        "--no-api", dest="no_api", action="store_true",
        help="No consultar APIs de enriquecimiento",
    )
    p.add_argument(
        "--vt-key", dest="vt_key", metavar="KEY",
        help="VirusTotal API key",
    )
    p.add_argument(
        "--abuse-key", dest="abuse_key", metavar="KEY",
        help="AbuseIPDB API key",
    )
    p.add_argument(
        "--criminalip-key", dest="criminalip_key", metavar="KEY",
        help="CriminalIP API key",
    )

    # Output
    p.add_argument(
        "--output", metavar="DIR",
        help="Directorio de salida",
    )
    p.add_argument(
        "--summary", action="store_true",
        help="Mostrar resumen en consola",
    )
    p.add_argument(
        "--no-html", dest="no_html", action="store_true",
        help="No generar HTML",
    )
    p.add_argument(
        "--no-xlsx", dest="no_xlsx", action="store_true",
        help="No generar XLSX",
    )
    p.add_argument(
        "--no-csv", dest="no_csv", action="store_true",
        help="No generar CSVs",
    )

    # Legacy flags (deprecated, hidden from --help)
    p.add_argument("--trace", metavar="FILE", help=argparse.SUPPRESS)
    p.add_argument("--conn", metavar="FILE", help=argparse.SUPPRESS)

    args = p.parse_args()

    # Determine mode
    if args.input or args.trace or args.conn:
        cli_mode(args)
    else:
        menu()


if __name__ == "__main__":
    main()
