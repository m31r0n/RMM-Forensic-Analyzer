"""Generadores CSV multi-RMM: conexiones, sesiones, transferencias, IPs, timeline, cross-RMM."""
from __future__ import annotations
import csv
from datetime import datetime
from pathlib import Path
from ..models.base import RMMType, RMMSession, RMMConnection, ParseResult, ConnectionDirection
from ..models.enrichment import IPEnrichment
from ..models.incident import IncidentContext
from ..models.summary import ForensicSummary
from ..utils import fmt_dt, fmt_dur, clean, cprint

try:
    from colorama import Fore
except ImportError:
    class Fore:
        GREEN = YELLOW = RED = ""


def generate_csvs(
    summary: ForensicSummary,
    ip_results: list[IPEnrichment],
    outdir: str,
    incident: IncidentContext | None = None,
) -> None:
    Path(outdir).mkdir(parents=True, exist_ok=True)

    sessions = summary.all_sessions
    connections = summary.all_connections
    enriched_map: dict[str, IPEnrichment] = {e.ip: e for e in ip_results}

    # ── 1. conexiones.csv ────────────────────────────────────────────────
    with open(f"{outdir}/conexiones.csv", "w", newline="", encoding="utf-8-sig") as f:
        fields = ["#", "rmm_type", "hostname", "direccion", "datetime",
                  "usuario", "remote_id", "alias"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, conn in enumerate(connections, 1):
            dir_val = (conn.direction.value
                       if isinstance(conn.direction, ConnectionDirection)
                       else str(conn.direction))
            w.writerow({
                "#": i,
                "rmm_type": conn.rmm_type.value,
                "hostname": conn.hostname,
                "direccion": dir_val,
                "datetime": fmt_dt(conn.datetime) or conn.dt_str,
                "usuario": conn.user,
                "remote_id": conn.remote_id,
                "alias": conn.alias,
            })

    # ── 2. sesiones.csv ──────────────────────────────────────────────────
    with open(f"{outdir}/sesiones.csv", "w", newline="", encoding="utf-8-sig") as f:
        fields = ["#", "rmm_type", "hostname", "remote_id", "alias",
                  "inicio", "fin", "duracion", "file_transfers", "clipboard",
                  "text_transfers", "elevacion", "ips", "riesgo", "score",
                  "razones", "proximidad_incidente", "clasificacion_pais"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, s in enumerate(sessions, 1):
            w.writerow({
                "#": i,
                "rmm_type": s.rmm_type.value,
                "hostname": s.hostname,
                "remote_id": s.remote_id,
                "alias": s.alias,
                "inicio": fmt_dt(s.start_dt),
                "fin": fmt_dt(s.end_dt),
                "duracion": fmt_dur(s.duration_sec),
                "file_transfers": s.file_transfers,
                "clipboard": s.clipboard_events,
                "text_transfers": s.text_transfers,
                "elevacion": "SI" if s.elevated else "No",
                "ips": " | ".join(s.all_ips) if s.all_ips else "",
                "riesgo": s.risk,
                "score": s.risk_score,
                "razones": " | ".join(s.risk_reasons),
                "proximidad_incidente": s.incident_proximity_label,
                "clasificacion_pais": s.country_classification,
            })

    # ── 3. transferencias.csv ────────────────────────────────────────────
    with open(f"{outdir}/transferencias.csv", "w", newline="", encoding="utf-8-sig") as f:
        fields = ["sesion", "rmm_type", "remote_id", "inicio",
                  "file_transfers", "clipboard", "text_transfers", "riesgo"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for i, s in enumerate(sessions, 1):
            if any([s.file_transfers, s.clipboard_events, s.text_transfers]):
                w.writerow({
                    "sesion": i,
                    "rmm_type": s.rmm_type.value,
                    "remote_id": s.remote_id,
                    "inicio": fmt_dt(s.start_dt),
                    "file_transfers": s.file_transfers,
                    "clipboard": s.clipboard_events,
                    "text_transfers": s.text_transfers,
                    "riesgo": s.risk,
                })

    # ── 4. timeline.csv ──────────────────────────────────────────────────
    with open(f"{outdir}/timeline.csv", "w", newline="", encoding="utf-8-sig") as f:
        fields = ["datetime", "rmm_type", "evento", "remote_id", "alias",
                  "detalle", "riesgo"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()

        tl: list[tuple] = []
        for s in sessions:
            rmm_name = s.rmm_type.value
            if s.start_dt:
                detail_parts = []
                if s.file_transfers:
                    detail_parts.append(f"Transferencias: {s.file_transfers}")
                if s.clipboard_events:
                    detail_parts.append(f"Clipboard: {s.clipboard_events}")
                if s.text_transfers:
                    detail_parts.append(f"Texto: {s.text_transfers}")
                if s.elevated:
                    detail_parts.append("Elevado")
                detail = ", ".join(detail_parts) if detail_parts else ""
                tl.append((s.start_dt, rmm_name, "Sesión iniciada",
                           s.remote_id, s.alias, detail, s.risk))
            if s.end_dt:
                tl.append((s.end_dt, rmm_name, "Sesión cerrada",
                           s.remote_id, s.alias,
                           f"Duración: {fmt_dur(s.duration_sec)}", s.risk))

        for conn in connections:
            rmm_name = conn.rmm_type.value
            dt_ = conn.datetime
            if dt_:
                dir_val = (conn.direction.value
                           if isinstance(conn.direction, ConnectionDirection)
                           else str(conn.direction))
                detail = f"Usuario: {conn.user}" if conn.user else ""
                tl.append((dt_, rmm_name, f"Conexión {dir_val}",
                           conn.remote_id, conn.alias, detail, ""))

        tl.sort(key=lambda x: x[0] or datetime.min)

        for row in tl:
            dt_, rmm_n, ev, rid, alias, det, risk_ = row
            w.writerow({
                "datetime": fmt_dt(dt_),
                "rmm_type": rmm_n,
                "evento": ev,
                "remote_id": rid,
                "alias": alias,
                "detalle": det,
                "riesgo": risk_,
            })

    # ── 5. ips.csv ───────────────────────────────────────────────────────
    with open(f"{outdir}/ips.csv", "w", newline="", encoding="utf-8-sig") as f:
        fields = ["ip", "tipo", "pais", "isp", "abuse_score", "reportes",
                  "uso", "tor", "vt_malicious", "vt_suspicious",
                  "vt_reputation", "criminalip_risk", "criminalip_score",
                  "vpn", "proxy", "puertos_abiertos", "cves",
                  "dominios", "scanner", "darkweb", "hosting", "cloud",
                  "ids_alertas", "honeypot", "categorias"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for e in ip_results:
            w.writerow({
                "ip": e.ip,
                "tipo": e.ip_type,
                "pais": e.country,
                "isp": e.isp,
                "abuse_score": e.abuse_score if e.abuse_score is not None else "",
                "reportes": e.abuse_reports if e.abuse_reports is not None else "",
                "uso": e.abuse_usage,
                "tor": "SI" if e.is_tor else "",
                "vt_malicious": e.vt_malicious if e.vt_malicious is not None else "",
                "vt_suspicious": e.vt_suspicious if e.vt_suspicious is not None else "",
                "vt_reputation": e.vt_reputation if e.vt_reputation is not None else "",
                "criminalip_risk": e.criminalip_risk,
                "criminalip_score": e.criminalip_score if e.criminalip_score is not None else "",
                "vpn": "SI" if e.criminalip_is_vpn else "",
                "proxy": "SI" if e.criminalip_is_proxy else "",
                "puertos_abiertos": e.criminalip_open_port_count or "",
                "cves": e.criminalip_vuln_count or "",
                "dominios": e.criminalip_domain_count or "",
                "scanner": "SI" if e.criminalip_is_scanner else "",
                "darkweb": "SI" if e.criminalip_is_darkweb else "",
                "hosting": "SI" if e.criminalip_is_hosting else "",
                "cloud": "SI" if e.criminalip_is_cloud else "",
                "ids_alertas": e.criminalip_ids_count or "",
                "honeypot": e.criminalip_honeypot_count or "",
                "categorias": "; ".join(e.criminalip_categories) if e.criminalip_categories else "",
            })

    # ── 6. cross_rmm_correlation.csv (solo si hay IPs cross-RMM) ────────
    cross_ips = {ip: rmms for ip, rmms in summary.cross_rmm_ips.items()
                 if len(rmms) > 1}
    if cross_ips:
        with open(f"{outdir}/cross_rmm_correlation.csv", "w", newline="", encoding="utf-8-sig") as f:
            fields = ["ip", "rmms", "pais", "isp", "abuse_score", "vt_malicious"]
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            sorted_cross = sorted(cross_ips.items(), key=lambda x: (-len(x[1]), x[0]))
            for ip, rmms in sorted_cross:
                e = enriched_map.get(ip)
                w.writerow({
                    "ip": ip,
                    "rmms": ", ".join(sorted(rmms)),
                    "pais": e.country if e else "",
                    "isp": e.isp if e else "",
                    "abuse_score": e.abuse_score if e and e.abuse_score is not None else "",
                    "vt_malicious": e.vt_malicious if e and e.vt_malicious is not None else "",
                })

    cprint(f"  [+] CSVs guardados en: {outdir}/", Fore.GREEN)
