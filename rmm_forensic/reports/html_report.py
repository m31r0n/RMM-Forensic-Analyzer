"""
Generador de informe HTML forense multi-RMM — paleta blanco + teal #1A8080.
Incluye graficos Chart.js, correlacion cross-RMM, proximidad al incidente
y clasificacion por pais.
"""

from __future__ import annotations
import json
from collections import defaultdict
from datetime import datetime

from ..models.base import RMMType, RMMSession, RMMConnection, ParseResult, ConnectionDirection
from ..models.enrichment import IPEnrichment
from ..models.incident import IncidentContext
from ..models.summary import ForensicSummary
from ..utils import fmt_dt, fmt_dur, clean
from ..__init__ import __version__
from .common import RMM_COLORS, rmm_badge, risk_badge, proximity_badge

TOOL_NAME = "RMM Forensic Analyzer"


# ═══════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════


def generate_html(
    summary: ForensicSummary,
    ip_results: list[IPEnrichment],
    incident: IncidentContext | None = None,
    meta: dict | None = None,
) -> str:
    meta = meta or {}
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sessions = summary.all_sessions
    connections = summary.all_connections
    rmm_types = summary.rmm_types_found
    hostnames = summary.hostnames_found
    multi_host = len(hostnames) > 1

    # Gather tool versions and OS versions from all parse results
    all_versions: list[str] = []
    all_os: list[str] = []
    for pr in summary.results_by_rmm.values():
        all_versions.extend(pr.tool_versions)
        all_os.extend(pr.os_versions)
    versions_str = ", ".join(dict.fromkeys(all_versions)) or "N/D"
    os_str = ", ".join(dict.fromkeys(all_os)) or "N/D"

    dr = summary.date_range_conn
    date_range = f"{fmt_dt(dr[0])} \u2192 {fmt_dt(dr[1])}" if dr else "\u2014"
    files_str = " | ".join(meta.get("files", []))
    evidence_sha256 = meta.get("evidence_sha256", "")

    has_anydesk = "AnyDesk" in rmm_types
    has_incident_date = incident is not None and incident.has_incident_date
    has_country = incident is not None and incident.has_country
    multi_rmm = len(rmm_types) > 1

    # ── Hallazgos (Findings) ────────────────────────────────────────
    findings = _build_findings(summary, sessions, has_anydesk)

    BG_MAP = {"CRITICO": "#fff0f0", "ALTO": "#fff8f0", "MEDIO": "#fffdf0", "BAJO": "#f0fff6"}
    DOT_MAP = {"CRITICO": "#c0392b", "ALTO": "#d68910", "MEDIO": "#b8a010", "BAJO": "#1a7a47"}

    findings_html = ""
    for lvl, ico, title, desc in findings:
        bg = BG_MAP.get(lvl, "#f0fff6")
        dot = DOT_MAP.get(lvl, "#1a7a47")
        findings_html += (
            '<div style="display:flex;gap:.75rem;align-items:flex-start;padding:.85rem 1rem;'
            f'border-radius:8px;margin-bottom:.6rem;background:{bg};border-left:4px solid {dot}">'
            f'<span style="font-size:1.2rem;flex-shrink:0">{ico}</span>'
            '<div>'
            f'<div style="font-weight:700;font-size:.9rem;margin-bottom:.25rem">{title} '
            f'<span style="background:{dot}22;color:{dot};border:1px solid {dot};'
            f'border-radius:12px;padding:.1rem .6rem;font-size:.72rem;font-weight:700">{lvl}</span></div>'
            f'<div style="font-size:.83rem;color:#4a6b6b">{desc}</div>'
            '</div></div>'
        )

    # ── Tabla conexiones ─────────────────────────────────────────
    conn_rows = _build_conn_rows(connections, multi_host)

    # ── Tabla sesiones ───────────────────────────────────────────
    sess_rows = _build_session_rows(sessions, has_anydesk, multi_host)

    # ── Transferencias ───────────────────────────────────────────
    ft_rows = _build_transfer_rows(sessions, has_anydesk)

    # ── Tabla IPs ────────────────────────────────────────────────
    ip_rows = _build_ip_rows(ip_results)

    # ── Timeline ─────────────────────────────────────────────────
    tl_html = _build_timeline(sessions, incident)

    # ── Incident proximity section ───────────────────────────────
    incident_html = ""
    if has_incident_date:
        incident_html = _build_incident_section(summary, incident)

    # ── Country classification section ───────────────────────────
    country_html = ""
    if has_country:
        country_html = _build_country_section(summary, incident, ip_results)

    # ── Cross-RMM correlation ────────────────────────────────────
    cross_rmm_html = ""
    if multi_rmm:
        cross_rmm_html = _build_cross_rmm_section(summary)

    # ── Per-RMM detail sections ──────────────────────────────────
    per_rmm_html = _build_per_rmm_sections(summary, sessions)

    # ── RMM header tags ──────────────────────────────────────────
    rmm_tags = "".join(
        f'<span class="hdr-tag" style="border-color:{RMM_COLORS.get(rt, "#fff")}60">'
        f'{rmm_badge(rt)}</span>'
        for rt in rmm_types
    )
    hostname_tags = ""
    if multi_host:
        hostname_tags = "".join(
            f'<span class="hdr-tag">Host: {h}</span>' for h in hostnames
        )

    # ── Per-RMM breakdown cards ──────────────────────────────────
    rmm_breakdown = ""
    for rt in rmm_types:
        s_count = summary.sessions_per_rmm.get(rt, 0)
        c_count = summary.connections_per_rmm.get(rt, 0)
        color = RMM_COLORS.get(rt, "#1A8080")
        rmm_breakdown += (
            f'<div class="stat" style="border-top:3px solid {color}">'
            f'<div class="n" style="color:{color}">{s_count}</div>'
            f'<div class="lbl">{rmm_badge(rt)} sesiones'
            f'<br><small style="color:#7a9b9b">{c_count} conexiones</small></div></div>'
        )

    # ── Datos para Chart.js ──────────────────────────────────────
    monthly = summary.monthly
    m_labels = json.dumps(list(monthly.keys()))
    m_data = json.dumps(list(monthly.values()))

    ids_conn = summary.conn_per_id
    id_labels = json.dumps(list(ids_conn.keys()))
    id_data = json.dumps(list(ids_conn.values()))

    rd = summary.risk_dist
    r_data = json.dumps([rd.get("CRITICO", 0), rd.get("ALTO", 0), rd.get("MEDIO", 0), rd.get("BAJO", 0)])

    hourly = summary.hourly
    h_data = json.dumps([hourly.get(h, 0) for h in range(24)])

    inc_count = summary.incoming
    out_count = summary.outgoing

    ft_chart_labels = json.dumps([f"Ses.{s.idx} {s.remote_id[:8]}" for s in sessions])
    ft_chart_ft = json.dumps([s.file_transfers for s in sessions])
    ft_chart_cb = json.dumps([s.clipboard_max_files for s in sessions])

    dur_labels = json.dumps([f"Ses.{s.idx}" for s in sessions if s.duration_sec])
    dur_data = json.dumps([round(s.duration_sec / 60, 1) for s in sessions if s.duration_sec])

    # Chart: Sesiones por RMM
    rmm_chart_labels = json.dumps(list(summary.sessions_per_rmm.keys()))
    rmm_chart_data = json.dumps(list(summary.sessions_per_rmm.values()))
    rmm_chart_colors = json.dumps([RMM_COLORS.get(k, "#1A8080") for k in summary.sessions_per_rmm.keys()])

    # Winlogon data (AnyDesk-specific, from extras)
    wl_data_list = []
    for s in sessions:
        wl = s.extras.get("winlogon_switches", 0) if s.rmm_type == RMMType.ANYDESK else 0
        wl_data_list.append(wl)
    ft_chart_wl = json.dumps(wl_data_list)

    # ── NAV items ────────────────────────────────────────────────
    nav_extra = ""
    if has_incident_date:
        nav_extra += '<a href="#proximidad">Proximidad</a>'
    if has_country:
        nav_extra += '<a href="#clasificacion-pais">Pais</a>'
    if multi_rmm:
        nav_extra += '<a href="#cross-rmm">Cross-RMM</a>'
    nav_extra += '<a href="#detalle-rmm">Detalle RMM</a>'

    # ── Extra session table columns ──────────────────────────────
    sess_th_winlogon = '<th>Winlogon</th>' if has_anydesk else ''
    sess_th_host = '<th>Host</th><th>Cuenta</th>' if multi_host else ''
    conn_th_host = '<th>Host</th><th>Cuenta</th>' if multi_host else ''

    # ── HTML FINAL ───────────────────────────────────────────────
    SEC = ('style="background:white;border:1px solid #d4e8e8;border-radius:10px;'
           'padding:1.75rem;margin-bottom:1.5rem;box-shadow:0 2px 12px rgba(26,135,135,.08)"')

    html_parts: list[str] = []
    html_parts.append(f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe Forense RMM \u2014 {now}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#f4fafa;color:#1a2c2c;font-family:'IBM Plex Sans',sans-serif;font-size:14px;line-height:1.6}}
code{{font-family:'IBM Plex Mono',monospace;font-size:.85em;background:#e8f5f5;padding:.1rem .35rem;border-radius:3px;color:#136060}}
.hdr{{background:#1A8080;color:white;padding:2rem 2.5rem}}
.hdr h1{{font-size:1.7rem;font-weight:700;letter-spacing:-.02em;margin:.4rem 0 .25rem}}
.hdr-meta{{opacity:.8;font-size:.83rem}}
.hdr-tags{{display:flex;gap:.5rem;flex-wrap:wrap;margin-top:.75rem}}
.hdr-tag{{background:rgba(255,255,255,.18);border:1px solid rgba(255,255,255,.3);border-radius:20px;padding:.2rem .85rem;font-size:.77rem}}
.nav{{background:white;border-bottom:2px solid #c2e4e4;padding:.55rem 2.5rem;display:flex;gap:.2rem;flex-wrap:wrap;position:sticky;top:0;z-index:100;box-shadow:0 2px 8px rgba(26,135,135,.08)}}
.nav a{{color:#1A8080;text-decoration:none;padding:.3rem .7rem;border-radius:5px;font-size:.82rem;font-weight:500;transition:.15s}}
.nav a:hover{{background:#e8f5f5}}
.content{{padding:1.75rem 2.5rem;max-width:1700px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:.85rem;margin:1.25rem 0}}
.stat{{background:white;border:1px solid #d4e8e8;border-radius:10px;padding:1rem 1.3rem;border-top:3px solid #1A8080}}
.stat .n{{font-size:2rem;font-weight:700;color:#1A8080;line-height:1.1}}
.stat .n.red{{color:#c0392b}}.stat .n.orange{{color:#d68910}}
.stat .lbl{{color:#4a6b6b;font-size:.76rem;margin-top:.3rem;font-weight:500}}
h2{{font-size:1rem;font-weight:700;color:#136060;margin-bottom:1.1rem;display:flex;align-items:center;gap:.5rem;padding-bottom:.7rem;border-bottom:2px solid #e8f5f5}}
.charts{{display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:1.1rem;margin-bottom:1.5rem}}
.chart-card{{background:white;border:1px solid #d4e8e8;border-radius:10px;padding:1.25rem;box-shadow:0 2px 8px rgba(26,135,135,.07)}}
.chart-title{{font-size:.8rem;font-weight:600;color:#4a6b6b;margin-bottom:.75rem;text-transform:uppercase;letter-spacing:.05em}}
.chart-wrap{{position:relative;height:215px}}
.table-wrap{{overflow-x:auto;border-radius:8px;border:1px solid #d4e8e8}}
table{{width:100%;border-collapse:collapse;font-size:.83rem}}
th{{background:#1A8080;color:white;text-align:left;padding:.6rem .9rem;white-space:nowrap;font-weight:600;font-size:.8rem}}
td{{padding:.5rem .9rem;border-bottom:1px solid #e8f5f5;vertical-align:top}}
tr:last-child td{{border-bottom:none}}
tr:hover td{{background:#f4fafa}}
.timeline{{position:relative;padding-left:1.25rem}}
.timeline::before{{content:'';position:absolute;left:.2rem;top:.5rem;bottom:.5rem;width:2px;background:#c2e4e4}}
.footer{{text-align:center;padding:2rem;border-top:2px solid #e8f5f5;color:#7a9b9b;font-size:.8rem;margin-top:2rem}}
.collapsible{{cursor:pointer;user-select:none}}
.collapsible::after{{content:' \\25BC';font-size:.7em;opacity:.5}}
.collapsible-body{{max-height:0;overflow:hidden;transition:max-height .3s ease}}
.collapsible-body.open{{max-height:none}}
@media print{{.nav{{display:none}}.section{{break-inside:avoid}}}}
</style>
</head>
<body>
<div class="hdr">
  <div style="display:flex;align-items:center;gap:1rem">
    <svg width="44" height="44" viewBox="0 0 44 44" fill="none">
      <circle cx="22" cy="22" r="20" stroke="rgba(255,255,255,.35)" stroke-width="2"/>
      <circle cx="22" cy="22" r="11" fill="rgba(255,255,255,.15)" stroke="rgba(255,255,255,.55)" stroke-width="1.5"/>
      <circle cx="22" cy="22" r="5" fill="white"/>
      <circle cx="30" cy="13" r="3.5" fill="rgba(255,255,255,.65)"/>
    </svg>
    <div>
      <div style="font-size:.78rem;opacity:.75;letter-spacing:.08em;text-transform:uppercase">Analisis Forense Digital</div>
      <h1>Informe Forense RMM</h1>
      <div class="hdr-meta">Generado: {now} &nbsp;&middot;&nbsp; {files_str} &nbsp;&middot;&nbsp; {TOOL_NAME} v{__version__}</div>
      {'<div class="hdr-meta" style="font-family:monospace;font-size:.72rem;opacity:.65">SHA-256: ' + evidence_sha256 + '</div>' if evidence_sha256 else ''}
    </div>
  </div>
  <div class="hdr-tags" style="margin-top:1rem">
    {rmm_tags}
    {hostname_tags}
    <span class="hdr-tag">OS: {os_str}</span>
    <span class="hdr-tag">Periodo: {date_range}</span>
    <span class="hdr-tag">{summary.total_connections} conexiones</span>
    <span class="hdr-tag">{summary.total_sessions} sesiones</span>
    <span class="hdr-tag">{len(summary.unique_ids)} IDs remotos</span>
    <span class="hdr-tag">{len(rmm_types)} RMM(s) detectados</span>
  </div>
</div>
<nav class="nav">
  <a href="#resumen">Resumen</a>
  <a href="#graficos">Graficos</a>
  <a href="#hallazgos">Hallazgos</a>
  <a href="#timeline">Timeline</a>
  <a href="#conexiones">Conexiones</a>
  <a href="#sesiones">Sesiones</a>
  <a href="#transferencias">Transferencias</a>
  <a href="#ips">IPs</a>
  {nav_extra}
</nav>
<div class="content">

<div id="resumen" {SEC}>
  <h2>Resumen Ejecutivo</h2>
  <div class="stats">
    <div class="stat"><div class="n">{summary.total_connections}</div><div class="lbl">Conexiones totales</div></div>
    <div class="stat"><div class="n">{summary.incoming}</div><div class="lbl">Conexiones entrantes</div></div>
    <div class="stat"><div class="n">{summary.outgoing}</div><div class="lbl">Conexiones salientes</div></div>
    <div class="stat"><div class="n">{len(summary.unique_ids)}</div><div class="lbl">IDs remotos unicos</div></div>
    <div class="stat"><div class="n">{summary.total_sessions}</div><div class="lbl">Sesiones totales</div></div>
    <div class="stat"><div class="n red">{summary.total_file_transfers}</div><div class="lbl">Transferencias de archivos</div></div>
    <div class="stat"><div class="n orange">{summary.elevated_sessions}</div><div class="lbl">Sesiones con elevacion</div></div>
    <div class="stat"><div class="n orange">{summary.total_text_transfers}</div><div class="lbl">Transferencias de texto</div></div>
    <div class="stat"><div class="n">{summary.max_clipboard_files}</div><div class="lbl">Max archivos clipboard</div></div>
    <div class="stat"><div class="n">{len(summary.all_public_ips)}</div><div class="lbl">IPs publicas unicas</div></div>
  </div>
  <!-- Per-RMM breakdown -->
  <div class="stats" style="margin-top:.5rem">
    {rmm_breakdown}
  </div>
  <p style="font-size:.88rem;color:#4a6b6b"><strong>IDs remotos detectados:</strong>&nbsp;
    {"  ".join(f'<code>{rid}</code>' for rid in summary.unique_ids)}
  </p>
</div>

<div id="graficos" {SEC}>
  <h2>Graficos para Informe</h2>
  <p style="font-size:.82rem;color:#4a6b6b;margin-bottom:1.1rem">
    Cada grafico puede capturarse individualmente para incluir en el informe forense (clic derecho / captura de pantalla).
  </p>
  <div class="charts">
    <div class="chart-card">
      <div class="chart-title">Sesiones por RMM</div>
      <div class="chart-wrap"><canvas id="cRMM"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Actividad mensual de conexiones</div>
      <div class="chart-wrap"><canvas id="cMonthly"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Conexiones por ID remoto</div>
      <div class="chart-wrap"><canvas id="cPerID"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Entrantes vs Salientes</div>
      <div class="chart-wrap"><canvas id="cDir"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Distribucion de riesgo (sesiones)</div>
      <div class="chart-wrap"><canvas id="cRisk"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Actividad por hora del dia</div>
      <div class="chart-wrap"><canvas id="cHourly"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Transferencias y clipboard por sesion</div>
      <div class="chart-wrap"><canvas id="cFT"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Duracion de sesiones (minutos)</div>
      <div class="chart-wrap"><canvas id="cDur"></canvas></div>
    </div>
  </div>
</div>

<div id="hallazgos" {SEC}>
  <h2>Hallazgos e Indicadores de Riesgo Forense</h2>
  {findings_html}
</div>

<div id="timeline" {SEC}>
  <h2>Linea de Tiempo de Eventos Clave</h2>
  <div class="timeline">
    {tl_html or '<p style="color:#7a9b9b">Sin eventos de sesion cargados.</p>'}
  </div>
</div>

<div id="conexiones" {SEC}>
  <h2>Historial de Conexiones</h2>
  <div class="table-wrap">
    <table>
      <thead><tr><th>#</th><th>RMM</th>{conn_th_host}<th>Direccion</th><th>Fecha / Hora</th><th>Usuario</th><th>ID Remoto / Alias</th></tr></thead>
      <tbody>{conn_rows or '<tr><td colspan="7" style="text-align:center;padding:2rem;color:#7a9b9b">Sin datos de conexiones cargados</td></tr>'}</tbody>
    </table>
  </div>
</div>

<div id="sesiones" {SEC}>
  <h2>Sesiones Detalladas</h2>
  <p style="font-size:.82rem;color:#4a6b6b;margin-bottom:.9rem">Borde rojo/naranja = riesgo CRITICO/ALTO. Las columnas de transferencias y clipboard destacan en rojo cuando superan umbrales forenses relevantes.</p>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>#</th><th>RMM</th>{sess_th_host}<th>ID / Alias</th><th>Inicio</th><th>Fin</th><th>Duracion</th>
          <th>File Transfers</th><th>Clipboard</th>
          <th>Txt Transfer</th>{sess_th_winlogon}<th>Elevacion</th>
          <th>IPs sesion</th><th>Ver. Remota</th><th>Riesgo</th>
        </tr>
      </thead>
      <tbody>{sess_rows or '<tr><td colspan="15" style="text-align:center;padding:2rem;color:#7a9b9b">Sin sesiones cargadas</td></tr>'}</tbody>
    </table>
  </div>
</div>

<div id="transferencias" {SEC}>
  <h2>Transferencias de Archivos y Portapapeles</h2>
  <p style="font-size:.82rem;color:#4a6b6b;margin-bottom:.9rem">
    Detalle de transferencias de archivos, portapapeles y texto por sesion.
  </p>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>#</th><th>RMM</th><th>ID / Alias</th><th>Inicio sesion</th>
          <th>File Transfers</th><th>Clipboard Max</th>
          <th>Txt Transfer</th>
          <th>Indicadores de riesgo</th><th>Nivel</th>
        </tr>
      </thead>
      <tbody>{ft_rows or '<tr><td colspan="9" style="text-align:center;padding:2rem;color:#7a9b9b">Sin transferencias detectadas</td></tr>'}</tbody>
    </table>
  </div>
</div>

{incident_html}
{country_html}
{cross_rmm_html}

<div id="ips" {SEC}>
  <h2>Analisis de IPs Detectadas</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>IP</th><th>Tipo</th><th>Pais</th><th>ISP / AS</th>
        <th>AbuseIPDB</th><th>Reportes</th><th>Uso</th><th>TOR</th>
        <th>VT Maliciosos</th><th>VT Reputacion</th>
        <th>CriminalIP Riesgo</th><th>CriminalIP Score</th>
        <th>Puertos</th><th>CVEs</th><th>Flags</th></tr>
      </thead>
      <tbody>{ip_rows}</tbody>
    </table>
  </div>
</div>

{per_rmm_html}

</div>
<div class="footer">
  {TOOL_NAME} v{__version__} &middot; Generado: {now}<br>
  <small>Documento confidencial \u2014 Uso exclusivo para analisis forense digital</small>
</div>
""")

    # ── Chart.js scripts ─────────────────────────────────────────
    html_parts.append("""<script>
const T='#1A8080',TL='rgba(26,128,128,.15)',TD='#136060',
      RED='#c0392b',ORA='#d68910',GRN='#1a7a47',GRY='#7a9b9b';
const font={family:"'IBM Plex Sans',sans-serif"};
const fontMono={family:"'IBM Plex Mono',monospace"};
Chart.defaults.font=font;
Chart.defaults.color='#4a6b6b';

const base={responsive:true,maintainAspectRatio:false,
  plugins:{legend:{labels:{font:{size:11}}},
           tooltip:{titleFont:fontMono,bodyFont:font,
             backgroundColor:'rgba(26,32,32,.92)',titleColor:'#e8f5f5',bodyColor:'#c2e4e4',
             borderColor:T,borderWidth:1,padding:10,cornerRadius:6}},
  scales:{
    x:{grid:{color:'rgba(26,128,128,.08)'},ticks:{font:{size:10}}},
    y:{grid:{color:'rgba(26,128,128,.08)'},ticks:{font:{size:10}}}
  }
};

// Collapsible sections
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('.collapsible').forEach(function(el){
    el.addEventListener('click',function(){
      var body=this.nextElementSibling;
      body.classList.toggle('open');
    });
  });
});
""")

    html_parts.append(f"""
// 0. Sesiones por RMM
new Chart(document.getElementById('cRMM'),{{
  type:'doughnut',
  data:{{labels:{rmm_chart_labels},
    datasets:[{{data:{rmm_chart_data},
      backgroundColor:{rmm_chart_colors},
      borderColor:['#fff'],borderWidth:3,hoverOffset:10}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{position:'bottom',labels:{{font:{{size:11}}}}}},
             tooltip:{{backgroundColor:'rgba(26,32,32,.9)',titleColor:'#e8f5f5',bodyColor:'#c2e4e4',
               borderColor:T,borderWidth:1,cornerRadius:6}}}}}}
}});

// 1. Actividad mensual
new Chart(document.getElementById('cMonthly'),{{
  type:'bar',
  data:{{labels:{m_labels},datasets:[{{label:'Conexiones',data:{m_data},
    backgroundColor:'rgba(26,128,128,.35)',borderColor:T,borderWidth:2,borderRadius:5}}]}},
  options:{{...base,plugins:{{...base.plugins,legend:{{display:false}}}},
    scales:{{...base.scales,y:{{...base.scales.y,ticks:{{stepSize:1}}}}}}}}
}});

// 2. Conexiones por ID
new Chart(document.getElementById('cPerID'),{{
  type:'bar',
  data:{{labels:{id_labels},datasets:[{{label:'Conexiones',data:{id_data},
    backgroundColor:['rgba(26,128,128,.7)','rgba(26,128,128,.4)'],
    borderRadius:5,borderWidth:0}}]}},
  options:{{...base,indexAxis:'y',
    plugins:{{...base.plugins,legend:{{display:false}}}},
    scales:{{x:{{...base.scales.x,ticks:{{stepSize:1}}}},y:{{...base.scales.y}}}}}}
}});

// 3. Direccion
new Chart(document.getElementById('cDir'),{{
  type:'doughnut',
  data:{{labels:['Entrantes','Salientes'],
    datasets:[{{data:[{inc_count},{out_count}],
      backgroundColor:['rgba(26,128,128,.85)','rgba(26,128,128,.25)'],
      borderColor:[TD,'rgba(26,128,128,.5)'],borderWidth:2,hoverOffset:10}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{position:'bottom',labels:{{font:{{size:11}}}}}},
             tooltip:{{backgroundColor:'rgba(26,32,32,.9)',titleColor:'#e8f5f5',bodyColor:'#c2e4e4',
               borderColor:T,borderWidth:1,cornerRadius:6}}}}}}
}});

// 4. Distribucion de riesgo
new Chart(document.getElementById('cRisk'),{{
  type:'doughnut',
  data:{{labels:['CRITICO','ALTO','MEDIO','BAJO'],
    datasets:[{{data:{r_data},
      backgroundColor:[RED,ORA,'rgba(184,160,16,.7)','rgba(26,122,71,.7)'],
      borderColor:['#fff','#fff','#fff','#fff'],borderWidth:3,hoverOffset:10}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{position:'bottom',labels:{{font:{{size:11}}}}}},
             tooltip:{{backgroundColor:'rgba(26,32,32,.9)',titleColor:'#e8f5f5',bodyColor:'#c2e4e4',
               borderColor:T,borderWidth:1,cornerRadius:6}}}}}}
}});

// 5. Actividad por hora
new Chart(document.getElementById('cHourly'),{{
  type:'bar',
  data:{{
    labels:Array.from({{length:24}},(_,i)=>String(i).padStart(2,'0')+':00'),
    datasets:[{{label:'Sesiones iniciadas',data:{h_data},
      backgroundColor:(ctx)=>ctx.raw>0?'rgba(26,128,128,.6)':'rgba(26,128,128,.08)',
      borderRadius:3,borderWidth:0}}]
  }},
  options:{{...base,plugins:{{...base.plugins,legend:{{display:false}}}},
    scales:{{
      x:{{...base.scales.x,ticks:{{font:{{size:8}},maxRotation:60}}}},
      y:{{...base.scales.y,ticks:{{stepSize:1}}}}
    }}}}
}});

// 6. Transferencias por sesion
const ftL={ft_chart_labels};
if(ftL.length>0){{
  new Chart(document.getElementById('cFT'),{{
    type:'bar',
    data:{{labels:ftL,datasets:[
      {{label:'File Transfers',data:{ft_chart_ft},backgroundColor:'rgba(192,57,43,.7)',borderRadius:3,borderWidth:0}},
      {{label:'Clipboard Max',data:{ft_chart_cb},backgroundColor:'rgba(26,128,128,.45)',borderRadius:3,borderWidth:0}}
    ]}},
    options:{{...base,scales:{{
      x:{{...base.scales.x,ticks:{{font:{{size:9}}}}}},
      y:{{...base.scales.y}}
    }}}}
  }});
}}else{{
  document.getElementById('cFT').closest('.chart-card').querySelector('.chart-wrap').innerHTML=
    '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#7a9b9b;font-size:.85rem">Sin datos de transferencia</div>';
}}

// 7. Duracion sesiones
const durL={dur_labels};
if(durL.length>0){{
  new Chart(document.getElementById('cDur'),{{
    type:'bar',
    data:{{labels:durL,datasets:[{{label:'Minutos',data:{dur_data},
      backgroundColor:'rgba(26,128,128,.5)',borderColor:T,borderWidth:1,borderRadius:4}}]}},
    options:{{...base,plugins:{{...base.plugins,legend:{{display:false}}}},
      scales:{{
        x:{{...base.scales.x,ticks:{{font:{{size:9}}}}}},
        y:{{...base.scales.y,title:{{display:true,text:'Minutos',font:{{size:10}}}}}}
      }}}}
  }});
}}else{{
  document.getElementById('cDur').closest('.chart-card').querySelector('.chart-wrap').innerHTML=
    '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#7a9b9b;font-size:.85rem">Sin datos de duracion</div>';
}}
</script>
</body>
</html>""")

    return "".join(html_parts)


# ═══════════════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════


def _build_findings(
    summary: ForensicSummary,
    sessions: list[RMMSession],
    has_anydesk: bool,
) -> list[tuple[str, str, str, str]]:
    """Build list of (level, icon, title, description) findings."""
    findings: list[tuple[str, str, str, str]] = []

    if summary.elevated_sessions:
        findings.append((
            "CRITICO", "&#9889;", "Elevacion de privilegios detectada",
            f"{summary.elevated_sessions} sesion(es) con elevacion de privilegios solicitada \u2014 "
            "indica operacion con privilegios elevados durante la sesion remota."
        ))

    if summary.total_file_transfers:
        findings.append((
            "ALTO", "&#128194;", "Transferencias de archivos confirmadas",
            f"{summary.total_file_transfers} evento(s) de transferencia de archivos detectados \u2014 "
            "intercambio de archivos mediante herramienta RMM."
        ))

    bk = summary.max_clipboard_files
    if bk > 100:
        findings.append((
            "CRITICO", "&#128680;", f"Portapapeles masivo: {bk} archivos simultaneos",
            "Cantidad de archivos en portapapeles incompatible con soporte remoto normal. "
            "Altamente compatible con exfiltracion masiva de datos."
        ))
    elif bk > 20:
        findings.append((
            "ALTO", "&#128230;", f"Portapapeles elevado: {bk} archivos",
            "Volumen de archivos en portapapeles significativamente elevado. Requiere revision."
        ))

    if summary.total_text_transfers:
        findings.append((
            "MEDIO", "&#128221;", "Texto copiado al portapapeles durante sesiones",
            f"{summary.total_text_transfers} evento(s) de texto transferido \u2014 "
            "posible copia de credenciales, comandos o datos sensibles."
        ))

    # AnyDesk-specific: Winlogon events
    if has_anydesk:
        total_wl = sum(
            s.extras.get("winlogon_switches", 0)
            for s in sessions if s.rmm_type == RMMType.ANYDESK
        )
        if total_wl:
            findings.append((
                "MEDIO", "&#128273;", f"{total_wl} evento(s) de cambio a Winlogon",
                "La sesion accedio a la pantalla de inicio de sesion mientras la conexion remota estaba "
                "activa. Compatible con intentos de cambio o captura de credenciales del sistema."
            ))

    # AnyDesk-specific: minimized sessions
    if has_anydesk:
        minimized = sum(
            1 for s in sessions
            if s.rmm_type == RMMType.ANYDESK and s.extras.get("minimized", False)
        )
        if minimized:
            findings.append((
                "MEDIO", "&#128065;", "Sesiones en modo oculto (ventana minimizada)",
                f"{minimized} sesion(es) con ventana minimizada \u2014 "
                "el operador remoto oculto la ventana de sesion, posiblemente para evitar deteccion."
            ))

    # Multi-RMM finding
    if len(summary.rmm_types_found) > 1:
        tools = ", ".join(summary.rmm_types_found)
        findings.append((
            "ALTO", "&#128279;", f"Multiples herramientas RMM detectadas: {tools}",
            "La presencia de multiples herramientas de acceso remoto es un indicador frecuente "
            "de actividad maliciosa o persistencia."
        ))

    # Cross-RMM IPs
    if summary.cross_rmm_ips:
        count = len(summary.cross_rmm_ips)
        findings.append((
            "CRITICO", "&#127760;", f"{count} IP(s) compartida(s) entre multiples RMMs",
            "Se detectaron direcciones IP que aparecen en conexiones de diferentes herramientas RMM. "
            "Esto es un fuerte indicador de actividad coordinada sospechosa."
        ))

    if not findings:
        findings.append((
            "BAJO", "&#9989;", "Sin indicadores criticos automaticos",
            "No se detectaron patrones de alto riesgo. Se recomienda revision manual contextual."
        ))

    return findings


def _build_conn_rows(connections: list[RMMConnection], multi_host: bool) -> str:
    """Build HTML table rows for connection records."""
    rows = ""
    for i, r in enumerate(connections, 1):
        is_in = r.direction == ConnectionDirection.INCOMING
        d_css = "background:#e8f5f5;color:#136060" if is_in else "background:#f5f5e8;color:#606013"
        d_txt = f"&#11015; {r.direction.value}" if is_in else f"&#11014; {r.direction.value}"
        alias = f'<br><code style="font-size:.75em;color:#7a9b9b">{r.alias}</code>' if r.alias else ""
        host_td = f'<td>{r.hostname or "\u2014"}</td>' if multi_host else ""
        user_acct = r.extras.get("user_account", "")
        user_td = f'<td style="font-size:.82em">{user_acct}</td>' if multi_host else ""
        rows += (
            f'<tr>'
            f'<td style="color:#7a9b9b;font-size:.8rem">{i}</td>'
            f'<td>{rmm_badge(r.rmm_type.value)}</td>'
            f'{host_td}{user_td}'
            f'<td><span style="padding:.15rem .6rem;border-radius:4px;font-size:.78rem;font-weight:600;{d_css}">{d_txt}</span></td>'
            f'<td style="font-family:IBM Plex Mono,monospace;font-size:.82em">{fmt_dt(r.datetime) or r.dt_str}</td>'
            f'<td>{r.user}</td>'
            f'<td><code>{r.remote_id}</code>{alias}</td>'
            f'</tr>'
        )
    return rows


def _build_session_rows(
    sessions: list[RMMSession], has_anydesk: bool, multi_host: bool
) -> str:
    """Build HTML table rows for sessions."""
    rows = ""
    for s in sessions:
        lvl = s.risk
        border = (
            "border-left:3px solid #c0392b" if lvl == "CRITICO"
            else ("border-left:3px solid #d68910" if lvl == "ALTO" else "")
        )
        ips = sorted(set(s.public_ips))
        ips_str = " ".join(f'<code style="font-size:.72em">{ip}</code>' for ip in ips)

        fo_color = "color:#c0392b;font-weight:700" if s.file_transfers > 0 else ""
        cb_color = "color:#c0392b;font-weight:700" if s.clipboard_max_files > 20 else ""
        elev_txt = (
            '<span style="background:#fde8e8;color:#c0392b;border-radius:4px;'
            'padding:.1rem .4rem;font-size:.75rem;font-weight:600">SI</span>'
            if s.elevated else 'No'
        )

        host_td = f'<td>{s.hostname or "\u2014"}</td>' if multi_host else ""
        user_acct = s.extras.get("user_account", "")
        user_td = f'<td style="font-size:.82em">{user_acct}</td>' if multi_host else ""

        # Winlogon column (AnyDesk only)
        wl_td = ""
        if has_anydesk:
            wl_val = s.extras.get("winlogon_switches", 0) if s.rmm_type == RMMType.ANYDESK else "\u2014"
            wl_td = f'<td style="text-align:center">{wl_val}</td>'

        rows += (
            f'<tr style="{border}">'
            f'<td style="color:#7a9b9b">{s.idx}</td>'
            f'<td>{rmm_badge(s.rmm_type.value)}</td>'
            f'{host_td}{user_td}'
            f'<td><code style="font-size:.85em">{s.remote_id}</code>'
            f'<br><small style="color:#7a9b9b">{s.alias}</small></td>'
            f'<td style="font-size:.8em;font-family:IBM Plex Mono,monospace">{fmt_dt(s.start_dt)}</td>'
            f'<td style="font-size:.8em;font-family:IBM Plex Mono,monospace">{fmt_dt(s.end_dt)}</td>'
            f'<td>{fmt_dur(s.duration_sec)}</td>'
            f'<td style="text-align:center;{fo_color}">{s.file_transfers}</td>'
            f'<td style="text-align:center;{cb_color}">{s.clipboard_max_files}'
            f'<br><small>{s.clipboard_events} ev.</small></td>'
            f'<td style="text-align:center">{s.text_transfers}</td>'
            f'{wl_td}'
            f'<td>{elev_txt}</td>'
            f'<td style="font-size:.78em">{ips_str or "\u2014"}</td>'
            f'<td><code style="font-size:.78em">{s.remote_version}</code></td>'
            f'<td>{risk_badge(lvl)}</td>'
            f'</tr>'
        )
    return rows


def _build_transfer_rows(sessions: list[RMMSession], has_anydesk: bool) -> str:
    """Build HTML table rows for the transfers section."""
    rows = ""
    for s in sessions:
        if s.file_transfers == 0 and s.clipboard_max_files == 0 and s.text_transfers == 0:
            continue
        reasons_str = "".join(
            f'<div style="font-size:.78rem;color:#4a6b6b">&bull; {r}</div>'
            for r in s.risk_reasons
        )
        rows += (
            f'<tr>'
            f'<td>{s.idx}</td>'
            f'<td>{rmm_badge(s.rmm_type.value)}</td>'
            f'<td><code style="font-size:.85em">{s.remote_id}</code>'
            f'<br><small style="color:#7a9b9b">{s.alias}</small></td>'
            f'<td style="font-size:.8em;font-family:IBM Plex Mono,monospace">{fmt_dt(s.start_dt)}</td>'
            f'<td style="text-align:center;font-weight:700;'
            f'color:{"#c0392b" if s.file_transfers > 0 else "inherit"}">'
            f'{s.file_transfers}</td>'
            f'<td style="text-align:center;font-weight:700;'
            f'color:{"#c0392b" if s.clipboard_max_files > 20 else "inherit"}">'
            f'{s.clipboard_max_files}</td>'
            f'<td style="text-align:center">{s.text_transfers}</td>'
            f'<td>{reasons_str}</td>'
            f'<td>{risk_badge(s.risk)}</td>'
            f'</tr>'
        )
    return rows


def _build_ip_rows(ip_results: list[IPEnrichment]) -> str:
    """Build HTML table rows for IP analysis."""
    if not ip_results:
        return (
            '<tr><td colspan="12" style="text-align:center;padding:2rem;color:#7a9b9b">'
            'Configure las API keys para enriquecer las IPs (VT_API_KEY / ABUSEIPDB_API_KEY / CRIMINALIP_API_KEY)'
            '</td></tr>'
        )

    rows = ""
    for ipr in ip_results:
        # AbuseIPDB score color
        sc = ipr.abuse_score
        sc_color = ""
        if isinstance(sc, int):
            sc_color = (
                "color:#c0392b;font-weight:700" if sc >= 75
                else ("color:#d68910;font-weight:700" if sc >= 25 else "color:#1a7a47;font-weight:600")
            )
        sc_display = ipr.abuse_error or (str(sc) if sc is not None else "N/A")

        # VT malicious color
        vt_m = ipr.vt_malicious
        vt_color = "color:#c0392b;font-weight:700" if isinstance(vt_m, int) and vt_m > 0 else ""
        if ipr.vt_error:
            vt_display = ipr.vt_error
        elif isinstance(vt_m, int) and vt_m > 0:
            vt_display = f"&#128308; {vt_m}"
        else:
            vt_display = str(vt_m) if vt_m is not None else "N/A"

        # TOR indicator
        tor_txt = ""
        if ipr.is_tor:
            tor_txt = '<span style="color:#c0392b;font-weight:600">&#9888; TOR</span>'

        # CriminalIP
        cip_risk = ipr.criminalip_risk or "\u2014"
        cip_risk_color = ""
        if cip_risk in ("dangerous", "critical"):
            cip_risk_color = "color:#c0392b;font-weight:700"
        elif cip_risk == "moderate":
            cip_risk_color = "color:#d68910;font-weight:700"
        elif cip_risk in ("low", "safe"):
            cip_risk_color = "color:#1a7a47;font-weight:600"

        cip_score = ipr.criminalip_error or (
            str(ipr.criminalip_score) if ipr.criminalip_score is not None else "\u2014"
        )

        # CriminalIP flag badges
        _badge = '<span style="background:{bg};color:{fg};border-radius:3px;padding:.05rem .3rem;font-size:.7rem;margin-left:2px">{txt}</span>'
        extra_flags = ""
        if ipr.criminalip_is_vpn or ipr.criminalip_is_anonymous_vpn:
            extra_flags += _badge.format(bg="#fef5e4", fg="#d68910", txt="VPN")
        if ipr.criminalip_is_proxy:
            extra_flags += _badge.format(bg="#fef5e4", fg="#d68910", txt="Proxy")
        if ipr.criminalip_is_darkweb:
            extra_flags += _badge.format(bg="#fadbd8", fg="#922b21", txt="DarkWeb")
        if ipr.criminalip_is_scanner:
            extra_flags += _badge.format(bg="#fadbd8", fg="#922b21", txt="Scanner")
        if ipr.criminalip_is_hosting:
            extra_flags += _badge.format(bg="#e8e8f5", fg="#3b3b8a", txt="Hosting")
        if ipr.criminalip_is_cloud:
            extra_flags += _badge.format(bg="#e8e8f5", fg="#3b3b8a", txt="Cloud")

        # Port / Vuln counts
        port_count = ipr.criminalip_open_port_count or 0
        vuln_count = ipr.criminalip_vuln_count or 0
        port_display = str(port_count) if port_count else "\u2014"
        vuln_display = str(vuln_count) if vuln_count else "\u2014"
        vuln_color = ""
        if vuln_count >= 5:
            vuln_color = "color:#c0392b;font-weight:700"
        elif vuln_count > 0:
            vuln_color = "color:#d68910;font-weight:700"

        # IP type badge
        tipo = ipr.ip_type or "\u2014"
        tipo_css = {
            "Relay": "background:#e8f5f5;color:#136060",
            "Externo": "background:#fef5e4;color:#8a6010",
            "Candidato": "background:#fde8e8;color:#922b21",
            "Sesion": "background:#e8e8f5;color:#3b3b8a",
        }.get(tipo, "")

        rows += (
            f'<tr>'
            f'<td><code style="font-size:.85em">{ipr.ip}</code></td>'
            f'<td><span style="padding:.1rem .5rem;border-radius:4px;font-size:.75rem;{tipo_css}">{tipo}</span></td>'
            f'<td>{ipr.country or "\u2014"}</td>'
            f'<td style="font-size:.8em">{ipr.isp or "\u2014"}</td>'
            f'<td style="{sc_color}">{sc_display}</td>'
            f'<td>{ipr.abuse_reports if ipr.abuse_reports is not None else "\u2014"}</td>'
            f'<td style="font-size:.78em">{ipr.abuse_usage or "\u2014"}</td>'
            f'<td>{tor_txt}</td>'
            f'<td style="{vt_color}">{vt_display}</td>'
            f'<td>{ipr.vt_reputation if ipr.vt_reputation is not None else "\u2014"}</td>'
            f'<td style="{cip_risk_color}">{cip_risk}</td>'
            f'<td>{cip_score}</td>'
            f'<td>{port_display}</td>'
            f'<td style="{vuln_color}">{vuln_display}</td>'
            f'<td>{extra_flags or "\u2014"}</td>'
            f'</tr>'
        )
    return rows


def _build_timeline(
    sessions: list[RMMSession],
    incident: IncidentContext | None,
) -> str:
    """Build unified timeline HTML across all RMMs."""
    tl_events: list[tuple[datetime | None, str, dict]] = []

    for s in sessions:
        rmm_color = RMM_COLORS.get(s.rmm_type.value, "#1A8080")
        badge = rmm_badge(s.rmm_type.value)
        if s.start_dt:
            tl_events.append((s.start_dt, "START", {
                "s": s, "color": rmm_color, "badge": badge
            }))
        if s.elevated and s.start_dt:
            tl_events.append((s.start_dt, "ELEV", {
                "s": s, "color": "#c0392b", "badge": badge
            }))
        # AnyDesk-specific: bulk clipboard events
        if s.rmm_type == RMMType.ANYDESK:
            for cr in s.extras.get("clipboard_relays", []):
                files = getattr(cr, "files", 0) if not isinstance(cr, dict) else cr.get("files", 0)
                cr_dt_raw = getattr(cr, "dt", None) if not isinstance(cr, dict) else cr.get("dt")
                # Convert ISO string to datetime if needed
                if isinstance(cr_dt_raw, str):
                    try:
                        cr_dt_raw = datetime.fromisoformat(cr_dt_raw)
                    except (ValueError, TypeError):
                        cr_dt_raw = None
                if files > 20 and cr_dt_raw:
                    tl_events.append((cr_dt_raw, "BULK", {
                        "files": files, "s": s, "color": "#d68910", "badge": badge
                    }))
        if s.end_dt:
            tl_events.append((s.end_dt, "END", {
                "s": s, "color": "#7a9b9b", "badge": badge
            }))

    tl_events.sort(key=lambda x: x[0] or datetime.min)

    html = ""

    # Incident date marker
    if incident and incident.has_incident_date:
        html += (
            '<div style="position:relative;padding-left:1.5rem;margin-bottom:1.2rem">'
            '<div style="position:absolute;left:-.3rem;top:.15rem;width:16px;height:16px;'
            'border-radius:50%;background:#c0392b;border:3px solid white;'
            'box-shadow:0 0 0 3px #c0392b55"></div>'
            '<div style="font-size:.75rem;color:#c0392b;font-family:IBM Plex Mono,monospace;font-weight:700">'
            f'{fmt_dt(incident.incident_date)}</div>'
            '<div style="font-size:.88rem;font-weight:700;color:#c0392b">'
            '&#9888; FECHA DEL INCIDENTE</div>'
            '</div>'
        )

    for dt_, etype, data in tl_events:
        s = data.get("s")
        dot_color = data.get("color", "#1A8080")
        badge_html = data.get("badge", "")

        if etype == "START":
            ico = "&#128279;"
            msg_ = f'{badge_html} Sesion iniciada &middot; <code>{s.remote_id}</code> / {s.alias}'
            det = f'Host: {s.hostname}' if s.hostname else ""
        elif etype == "END":
            ico = "&#9209;"
            msg_ = f'{badge_html} Sesion cerrada &middot; <code>{s.remote_id}</code>'
            det = f'Duracion: {fmt_dur(s.duration_sec)}'
        elif etype == "BULK":
            ico = "&#128230;"
            msg_ = f'{badge_html} Clipboard masivo: {data["files"]} archivos &middot; sesion <code>{s.remote_id}</code>'
            det = "Posible exfiltracion \u2014 revisar contexto"
        elif etype == "ELEV":
            ico = "&#9889;"
            msg_ = f'{badge_html} Elevacion de privilegios &middot; <code>{s.remote_id}</code>'
            det = "Backend elevado solicitado durante esta sesion"
        else:
            ico = "&middot;"
            msg_ = ""
            det = ""

        html += (
            f'<div style="position:relative;padding-left:1.5rem;margin-bottom:.9rem">'
            f'<div style="position:absolute;left:-.1rem;top:.3rem;width:10px;height:10px;'
            f'border-radius:50%;background:{dot_color};border:2px solid white;'
            f'box-shadow:0 0 0 2px {dot_color}33"></div>'
            f'<div style="font-size:.75rem;color:#7a9b9b;font-family:IBM Plex Mono,monospace">{fmt_dt(dt_)}</div>'
            f'<div style="font-size:.88rem">{ico} {msg_}</div>'
            + (f'<div style="font-size:.78rem;color:#4a6b6b;margin-top:.1rem">{det}</div>' if det else "")
            + '</div>'
        )

    return html


def _build_incident_section(summary: ForensicSummary, incident: IncidentContext) -> str:
    """Build incident proximity analysis section."""
    SEC = ('style="background:white;border:1px solid #d4e8e8;border-radius:10px;'
           'padding:1.75rem;margin-bottom:1.5rem;box-shadow:0 2px 12px rgba(26,135,135,.08)"')

    html = f'<div id="proximidad" {SEC}>\n'
    html += '<h2>Proximidad al Incidente</h2>\n'
    html += (
        f'<p style="font-size:.88rem;color:#4a6b6b;margin-bottom:1rem">'
        f'Fecha del incidente: <strong style="color:#c0392b">{fmt_dt(incident.incident_date)}</strong> '
        f'&mdash; Sesiones clasificadas por ventana temporal de proximidad.</p>\n'
    )

    # Color-coded bands
    bands = [
        ("CRITICO (+-24h)", "#fde8e8", "#c0392b", summary.sessions_within_24h),
        ("ALTO (+-3d)", "#fef5e4", "#d68910", summary.sessions_within_3d),
        ("MEDIO (+-7d)", "#fefae4", "#9a7a10", summary.sessions_within_7d),
    ]

    for label, bg, color, sess_list in bands:
        display_label = label.replace("+-", "\u00b1")
        html += (
            f'<div style="background:{bg};border-left:4px solid {color};border-radius:6px;'
            f'padding:.8rem 1rem;margin-bottom:.6rem">'
            f'<div style="font-weight:700;color:{color};font-size:.9rem;margin-bottom:.3rem">'
            f'{display_label}: {len(sess_list)} sesion(es)</div>'
        )
        if sess_list:
            html += '<div style="font-size:.82rem;color:#4a6b6b">'
            for s in sess_list[:10]:
                html += (
                    f'<div>&bull; {rmm_badge(s.rmm_type.value)} '
                    f'<code>{s.remote_id}</code> \u2014 {fmt_dt(s.start_dt)} '
                    f'({fmt_dur(s.duration_sec)})</div>'
                )
            if len(sess_list) > 10:
                html += f'<div style="color:#7a9b9b">\u2026 y {len(sess_list) - 10} mas</div>'
            html += '</div>'
        html += '</div>\n'

    # Anomalous patterns
    if summary.anomalous_patterns:
        html += (
            '<div style="background:#fff0f0;border-left:4px solid #c0392b;border-radius:6px;'
            'padding:.8rem 1rem;margin-top:.8rem">'
            '<div style="font-weight:700;color:#c0392b;font-size:.9rem;margin-bottom:.3rem">'
            'Patrones anomalos detectados</div>'
            '<div style="font-size:.82rem;color:#4a6b6b">'
        )
        for pattern in summary.anomalous_patterns:
            html += f'<div>&bull; {pattern}</div>'
        html += '</div></div>\n'

    html += '</div>\n'
    return html


def _build_country_section(
    summary: ForensicSummary,
    incident: IncidentContext,
    ip_results: list[IPEnrichment],
) -> str:
    """Build country classification section."""
    SEC = ('style="background:white;border:1px solid #d4e8e8;border-radius:10px;'
           'padding:1.75rem;margin-bottom:1.5rem;box-shadow:0 2px 12px rgba(26,135,135,.08)"')

    domestic_ips = [ipr for ipr in ip_results if incident.classify_country(ipr.country) == "Informativa"]
    foreign_ips = [ipr for ipr in ip_results if incident.classify_country(ipr.country) == "Sospechosa"]

    html = f'<div id="clasificacion-pais" {SEC}>\n'
    html += '<h2>Clasificacion por Pais</h2>\n'
    html += (
        f'<p style="font-size:.88rem;color:#4a6b6b;margin-bottom:1rem">'
        f'Pais de origen configurado: <strong>{incident.origin_country.upper()}</strong> '
        f'&mdash; IPs clasificadas como Informativa (domesticas) vs Sospechosa (extranjeras).</p>\n'
    )

    # Stats
    html += '<div class="stats" style="margin-bottom:1rem">'
    html += (
        f'<div class="stat" style="border-top:3px solid #1a7a47">'
        f'<div class="n" style="color:#1a7a47">{len(domestic_ips)}</div>'
        f'<div class="lbl">IPs Informativas (domesticas)</div></div>'
    )
    html += (
        f'<div class="stat" style="border-top:3px solid #c0392b">'
        f'<div class="n" style="color:#c0392b">{len(foreign_ips)}</div>'
        f'<div class="lbl">IPs Sospechosas (extranjeras)</div></div>'
    )
    html += (
        f'<div class="stat" style="border-top:3px solid #d68910">'
        f'<div class="n" style="color:#d68910">{summary.suspicious_sessions}</div>'
        f'<div class="lbl">Sesiones con IPs extranjeras</div></div>'
    )
    html += '</div>\n'

    # Foreign IPs detail
    if foreign_ips:
        html += (
            '<div style="background:#fff0f0;border-left:4px solid #c0392b;border-radius:6px;'
            'padding:.8rem 1rem;margin-bottom:.6rem">'
            '<div style="font-weight:700;color:#c0392b;font-size:.9rem;margin-bottom:.3rem">'
            'Conexiones desde paises extranjeros</div>'
            '<div style="font-size:.82rem;color:#4a6b6b">'
        )
        for ipr in foreign_ips:
            html += (
                f'<div>&bull; <code>{ipr.ip}</code> \u2014 '
                f'{ipr.country or "Desconocido"} \u2014 {ipr.isp or "N/D"}</div>'
            )
        html += '</div></div>\n'

    html += '</div>\n'
    return html


def _build_cross_rmm_section(summary: ForensicSummary) -> str:
    """Build cross-RMM correlation section."""
    SEC = ('style="background:white;border:1px solid #d4e8e8;border-radius:10px;'
           'padding:1.75rem;margin-bottom:1.5rem;box-shadow:0 2px 12px rgba(26,135,135,.08)"')

    html = f'<div id="cross-rmm" {SEC}>\n'
    html += '<h2>Correlacion Cross-RMM</h2>\n'
    html += (
        '<p style="font-size:.88rem;color:#4a6b6b;margin-bottom:1rem">'
        'Direcciones IP que aparecen en conexiones de multiples herramientas RMM. '
        'Esto puede indicar actividad coordinada o un atacante usando multiples herramientas.</p>\n'
    )

    if summary.cross_rmm_ips:
        html += '<div class="table-wrap"><table>'
        html += '<thead><tr><th>IP</th><th>Herramientas RMM</th><th>Indicador</th></tr></thead>'
        html += '<tbody>'
        for ip, rmm_list in sorted(summary.cross_rmm_ips.items()):
            badges = " ".join(rmm_badge(r) for r in rmm_list)
            html += (
                f'<tr>'
                f'<td><code style="font-size:.85em">{ip}</code></td>'
                f'<td>{badges}</td>'
                f'<td><span style="background:#fde8e8;color:#c0392b;border-radius:4px;'
                f'padding:.1rem .4rem;font-size:.75rem;font-weight:600">'
                f'&#9888; IP compartida ({len(rmm_list)} RMMs)</span></td>'
                f'</tr>'
            )
        html += '</tbody></table></div>\n'
    else:
        html += (
            '<div style="background:#f0fff6;border-left:4px solid #1a7a47;border-radius:6px;'
            'padding:.8rem 1rem">'
            '<div style="font-size:.88rem;color:#1a7a47">'
            'No se detectaron IPs compartidas entre herramientas RMM.</div></div>\n'
        )

    html += '</div>\n'
    return html


def _build_per_rmm_sections(summary: ForensicSummary, sessions: list[RMMSession]) -> str:
    """Build collapsible per-RMM detail sections."""
    SEC = ('style="background:white;border:1px solid #d4e8e8;border-radius:10px;'
           'padding:1.75rem;margin-bottom:1.5rem;box-shadow:0 2px 12px rgba(26,135,135,.08)"')

    html = f'<div id="detalle-rmm" {SEC}>\n'
    html += '<h2>Detalle por Herramienta RMM</h2>\n'

    for rmm_name, pr in sorted(summary.results_by_rmm.items()):
        color = RMM_COLORS.get(rmm_name, "#1A8080")
        rmm_sessions = [s for s in sessions if s.rmm_type.value == rmm_name]
        versions_str = ", ".join(pr.tool_versions) or "N/D"
        os_str = ", ".join(dict.fromkeys(pr.os_versions)) or "N/D"

        html += (
            f'<div style="border:1px solid {color}44;border-radius:8px;margin-bottom:1rem;overflow:hidden">'
            f'<div class="collapsible" style="background:{color}12;padding:.8rem 1rem;'
            f'border-bottom:1px solid {color}33">'
            f'<span style="font-weight:700;color:{color};font-size:.95rem">'
            f'{rmm_badge(rmm_name)} &mdash; {len(rmm_sessions)} sesiones, '
            f'{len(pr.connections)} conexiones</span>'
            f'<span style="font-size:.8rem;color:#7a9b9b;margin-left:1rem">'
            f'Versiones: {versions_str} | OS: {os_str}</span>'
            f'</div>'
            f'<div class="collapsible-body">'
            f'<div style="padding:1rem">'
        )

        if rmm_name == "AnyDesk":
            html += _build_anydesk_details(rmm_sessions, pr)
        elif rmm_name == "TeamViewer":
            html += _build_teamviewer_details(rmm_sessions, pr)
        else:
            html += _build_generic_rmm_details(rmm_sessions, pr)

        html += '</div></div></div>\n'

    html += '</div>\n'
    return html


def _build_anydesk_details(sessions: list[RMMSession], pr: ParseResult) -> str:
    """AnyDesk-specific details: permissions matrix, capabilities, Winlogon events."""
    html = ""

    # ── Permissions matrix ──────────────────────────────────────
    # perms is serialized as list[dict] with keys: name, enabled, forbidden, disabled, ...
    # Convert to dict[str, dict] keyed by name for easier lookup.
    def _perms_as_dict(raw) -> dict[str, dict]:
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, list):
            return {p["name"]: p for p in raw if isinstance(p, dict) and "name" in p}
        return {}

    all_perms: set[str] = set()
    for s in sessions:
        perms = _perms_as_dict(s.extras.get("perms", []))
        all_perms.update(perms.keys())
    pnames = sorted(all_perms)

    if pnames:
        html += '<h3 style="font-size:.88rem;color:#136060;margin-bottom:.5rem;margin-top:.5rem">Matriz de Permisos</h3>'
        html += (
            '<p style="font-size:.78rem;color:#4a6b6b;margin-bottom:.5rem">'
            '<span style="background:#e8f5ee;color:#1a7a47;padding:.1rem .4rem;border-radius:3px;font-weight:600;font-size:.72rem">ON</span> Habilitado '
            '<span style="background:#fde8e8;color:#c0392b;padding:.1rem .4rem;border-radius:3px;font-weight:600;font-size:.72rem">OFF</span> Prohibido '
            '<span style="background:#fef5e4;color:#d68910;padding:.1rem .4rem;border-radius:3px;font-weight:600;font-size:.72rem">DIS</span> Desactivado'
            '</p>'
        )
        perm_head = "".join(
            f'<th style="font-size:.72rem;padding:.5rem .6rem">{p.replace("_", " ")}</th>'
            for p in pnames
        )
        html += '<div class="table-wrap"><table>'
        html += f'<thead><tr><th>#</th><th>ID Remoto</th><th>Inicio</th><th>Perfil</th>{perm_head}</tr></thead>'
        html += '<tbody>'
        for s in sessions:
            perms = _perms_as_dict(s.extras.get("perms", []))
            profile = s.extras.get("perm_profile", "\u2014")
            cells = ""
            for p in pnames:
                pd = perms.get(p)
                if not pd:
                    cells += '<td style="text-align:center;color:#ccc;font-size:.72rem">\u2014</td>'
                elif pd.get("enabled"):
                    cells += '<td style="text-align:center;background:#e8f5ee;color:#1a7a47;font-size:.72rem;font-weight:600">ON</td>'
                elif pd.get("forbidden"):
                    cells += '<td style="text-align:center;background:#fde8e8;color:#c0392b;font-size:.72rem;font-weight:600">OFF</td>'
                elif pd.get("disabled"):
                    cells += '<td style="text-align:center;background:#fef5e4;color:#d68910;font-size:.72rem;font-weight:600">DIS</td>'
                else:
                    cells += '<td style="text-align:center;color:#ccc;font-size:.72rem">\u2014</td>'
            html += (
                f'<tr><td>{s.idx}</td>'
                f'<td><code style="font-size:.82em">{s.remote_id}</code></td>'
                f'<td style="font-size:.8em;font-family:IBM Plex Mono,monospace">{fmt_dt(s.start_dt)}</td>'
                f'<td style="font-size:.8em">{profile}</td>'
                f'{cells}</tr>'
            )
        html += '</tbody></table></div>\n'

    # ── Remote capabilities ────────────────────────────────────
    caps_map: dict[str, set[str]] = defaultdict(set)
    for s in sessions:
        for cap in s.extras.get("remote_caps", []):
            caps_map[cap].add(s.remote_id)

    cap_context = {
        "request_elevation": "Puede solicitar elevacion UAC en el equipo remoto",
        "request_elevation_pw": "Puede solicitar elevacion con contrasena",
        "sysinfo": "Puede acceder a informacion del sistema operativo",
        "remote_restart": "Puede reiniciar el equipo remoto",
        "filetransfer_server": "Actua como servidor para transferencias de archivos",
        "filetransfer_client": "Puede solicitar transferencias de archivos",
        "send_sas": "Puede enviar Secure Attention Sequence (Ctrl+Alt+Del)",
        "block_input": "Puede bloquear el teclado/raton del usuario local",
        "tcp_tunnel": "Puede crear tuneles TCP (pivoting de red)",
        "clip_paste_files": "Puede pegar archivos mediante portapapeles",
        "clip_src_files": "Puede copiar archivos al portapapeles",
        "whiteboard": "Puede usar la pizarra de anotaciones",
        "remote_printing": "Puede imprimir en la impresora remota",
        "volatile_token": "Token de sesion volatil (sesion unica)",
        "switch_sides": "Puede cambiar el control de la sesion",
        "keyboard_unicode": "Soporte completo de teclado internacional",
        "keyb_hint_src": "Puede enviar sugerencias de teclado",
    }

    if caps_map:
        html += '<h3 style="font-size:.88rem;color:#136060;margin-bottom:.5rem;margin-top:1rem">Capacidades Remotas Declaradas</h3>'
        html += '<div class="table-wrap"><table>'
        html += '<thead><tr><th>Capacidad</th><th>ID Remoto(s)</th><th>Contexto forense</th></tr></thead>'
        html += '<tbody>'
        for cap, rids in sorted(caps_map.items()):
            ctx = cap_context.get(cap, "Capacidad declarada por el cliente remoto")
            risk_flag = ""
            if cap in {"request_elevation", "request_elevation_pw", "block_input", "tcp_tunnel", "send_sas"}:
                risk_flag = (' <span style="background:#fde8e8;color:#c0392b;border-radius:4px;'
                             'padding:.1rem .35rem;font-size:.7rem;font-weight:600;margin-left:.5rem">'
                             '&#9888; Alto riesgo</span>')
            elif cap in {"sysinfo", "remote_restart", "filetransfer_server", "filetransfer_client",
                         "clip_paste_files", "clip_src_files"}:
                risk_flag = (' <span style="background:#fef5e4;color:#d68910;border-radius:4px;'
                             'padding:.1rem .35rem;font-size:.7rem;font-weight:600;margin-left:.5rem">'
                             'Relevante</span>')
            html += (
                f'<tr>'
                f'<td><code>{cap}</code>{risk_flag}</td>'
                f'<td>{", ".join(sorted(rids))}</td>'
                f'<td style="font-size:.82rem;color:#4a6b6b">{ctx}</td>'
                f'</tr>'
            )
        html += '</tbody></table></div>\n'

    # ── Winlogon events ────────────────────────────────────────
    wl_sessions = [s for s in sessions if s.extras.get("winlogon_switches", 0) > 0]
    if wl_sessions:
        html += '<h3 style="font-size:.88rem;color:#136060;margin-bottom:.5rem;margin-top:1rem">Eventos Winlogon</h3>'
        html += '<div class="table-wrap"><table>'
        html += '<thead><tr><th>#</th><th>ID Remoto</th><th>Inicio</th><th>Eventos Winlogon</th><th>Detalle</th></tr></thead>'
        html += '<tbody>'
        for s in wl_sessions:
            wl_count = s.extras.get("winlogon_switches", 0)
            desktop_switches = s.extras.get("desktop_switches", [])
            detail_html = ""
            for we in desktop_switches[:5]:
                we_dt = getattr(we, "dt", None) if not isinstance(we, dict) else we.get("dt")
                we_from = getattr(we, "from_desk", "") if not isinstance(we, dict) else we.get("from_desk", "")
                we_to = getattr(we, "to_desk", "") if not isinstance(we, dict) else we.get("to_desk", "")
                detail_html += (
                    f'<div style="font-size:.75rem;font-family:IBM Plex Mono,monospace;color:#4a6b6b">'
                    f'{fmt_dt(we_dt)} {we_from}\u2192{we_to}</div>'
                )
            html += (
                f'<tr><td>{s.idx}</td>'
                f'<td><code>{s.remote_id}</code></td>'
                f'<td style="font-size:.8em;font-family:IBM Plex Mono,monospace">{fmt_dt(s.start_dt)}</td>'
                f'<td style="text-align:center;font-weight:700;color:#c0392b">{wl_count}</td>'
                f'<td>{detail_html or "\u2014"}</td></tr>'
            )
        html += '</tbody></table></div>\n'

    return html


def _build_teamviewer_details(sessions: list[RMMSession], pr: ParseResult) -> str:
    """TeamViewer-specific details."""
    html = ""
    html += '<h3 style="font-size:.88rem;color:#136060;margin-bottom:.5rem;margin-top:.5rem">Detalle de Conexiones TeamViewer</h3>'

    if sessions:
        html += '<div class="table-wrap"><table>'
        html += '<thead><tr><th>#</th><th>ID Remoto</th><th>Inicio</th><th>Fin</th><th>Duracion</th><th>IP</th><th>Detalles</th></tr></thead>'
        html += '<tbody>'
        for s in sessions:
            extras_html = ""
            for key, val in sorted(s.extras.items()):
                if val and key not in ("perms", "remote_caps"):
                    extras_html += f'<div style="font-size:.75rem;color:#4a6b6b"><strong>{key}:</strong> {val}</div>'
            html += (
                f'<tr><td>{s.idx}</td>'
                f'<td><code>{s.remote_id}</code></td>'
                f'<td style="font-size:.8em;font-family:IBM Plex Mono,monospace">{fmt_dt(s.start_dt)}</td>'
                f'<td style="font-size:.8em;font-family:IBM Plex Mono,monospace">{fmt_dt(s.end_dt)}</td>'
                f'<td>{fmt_dur(s.duration_sec)}</td>'
                f'<td><code style="font-size:.78em">{s.remote_ip or "\u2014"}</code></td>'
                f'<td>{extras_html or "\u2014"}</td></tr>'
            )
        html += '</tbody></table></div>\n'
    else:
        html += '<p style="color:#7a9b9b">Sin sesiones TeamViewer.</p>\n'

    return html


def _build_generic_rmm_details(sessions: list[RMMSession], pr: ParseResult) -> str:
    """Generic RMM details for ScreenConnect, Chrome Remote Desktop, Splashtop, RustDesk."""
    html = ""
    rmm_name = pr.rmm_type.value
    html += f'<h3 style="font-size:.88rem;color:#136060;margin-bottom:.5rem;margin-top:.5rem">Detalle de Sesiones {rmm_name}</h3>'

    if sessions:
        html += '<div class="table-wrap"><table>'
        html += '<thead><tr><th>#</th><th>ID Remoto</th><th>Inicio</th><th>Fin</th><th>Duracion</th><th>IP</th><th>Datos Adicionales</th></tr></thead>'
        html += '<tbody>'
        for s in sessions:
            extras_html = ""
            for key, val in sorted(s.extras.items()):
                if val:
                    display_val = str(val) if not isinstance(val, (list, dict, set)) else json.dumps(val, default=str)
                    if len(display_val) > 200:
                        display_val = display_val[:200] + "\u2026"
                    extras_html += f'<div style="font-size:.75rem;color:#4a6b6b"><strong>{key}:</strong> {display_val}</div>'
            html += (
                f'<tr><td>{s.idx}</td>'
                f'<td><code>{s.remote_id}</code></td>'
                f'<td style="font-size:.8em;font-family:IBM Plex Mono,monospace">{fmt_dt(s.start_dt)}</td>'
                f'<td style="font-size:.8em;font-family:IBM Plex Mono,monospace">{fmt_dt(s.end_dt)}</td>'
                f'<td>{fmt_dur(s.duration_sec)}</td>'
                f'<td><code style="font-size:.78em">{s.remote_ip or "\u2014"}</code></td>'
                f'<td>{extras_html or "\u2014"}</td></tr>'
            )
        html += '</tbody></table></div>\n'
    else:
        html += f'<p style="color:#7a9b9b">Sin sesiones {rmm_name}.</p>\n'

    return html
