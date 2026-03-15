from collections import defaultdict
from datetime import datetime
from ..models.base import RMMSession, RMMConnection, ParseResult, RMMType, ConnectionDirection
from ..models.summary import ForensicSummary
from ..models.incident import IncidentContext

def correlate(
    results: dict[str, ParseResult],
    incident: IncidentContext | None = None,
) -> ForensicSummary:
    """
    Build a unified ForensicSummary from multiple ParseResults.
    Performs cross-RMM correlation and incident proximity analysis.
    """
    summary = ForensicSummary()
    summary.results_by_rmm = results

    all_sessions = []
    all_connections = []
    all_ips = set()

    for rmm_name, pr in results.items():
        all_sessions.extend(pr.sessions)
        all_connections.extend(pr.connections)
        all_ips |= pr.public_ips
        summary.sessions_per_rmm[rmm_name] = len(pr.sessions)
        summary.connections_per_rmm[rmm_name] = len(pr.connections)

        # Group by hostname
        hn = pr.hostname or "Desconocido"
        if hn not in summary.results_by_hostname:
            summary.results_by_hostname[hn] = []
        summary.results_by_hostname[hn].append(pr)

    # Global stats
    summary.total_connections = len(all_connections)
    summary.total_sessions = len(all_sessions)
    summary.incoming = sum(1 for c in all_connections if c.direction == ConnectionDirection.INCOMING)
    summary.outgoing = sum(1 for c in all_connections if c.direction == ConnectionDirection.OUTGOING)

    # Unique IDs (across all RMMs)
    all_ids = sorted(set(
        [c.remote_id for c in all_connections if c.remote_id] +
        [s.remote_id for s in all_sessions if s.remote_id]
    ))
    summary.unique_ids = all_ids

    # Date ranges
    conn_dts = [c.datetime for c in all_connections if c.datetime]
    sess_dts = [s.start_dt for s in all_sessions if s.start_dt]
    if conn_dts:
        summary.date_range_conn = (min(conn_dts), max(conn_dts))
    if sess_dts:
        summary.date_range_sessions = (min(sess_dts), max(sess_dts))

    # Activity indicators
    summary.total_file_transfers = sum(s.file_transfers for s in all_sessions)
    summary.total_clipboard = sum(s.clipboard_events for s in all_sessions)
    summary.total_text_transfers = sum(s.text_transfers for s in all_sessions)
    summary.elevated_sessions = sum(1 for s in all_sessions if s.elevated)
    summary.max_clipboard_files = max((s.clipboard_max_files for s in all_sessions), default=0)

    # Monthly distribution
    monthly = defaultdict(int)
    for c in all_connections:
        if c.datetime:
            monthly[c.datetime.strftime("%Y-%m")] += 1
    for s in all_sessions:
        if s.start_dt:
            monthly[s.start_dt.strftime("%Y-%m")] += 1
    summary.monthly = dict(sorted(monthly.items()))

    # Hourly distribution
    hourly = defaultdict(int)
    for s in all_sessions:
        if s.start_dt:
            hourly[s.start_dt.hour] += 1
    summary.hourly = {h: hourly.get(h, 0) for h in range(24)}

    # Risk distribution
    risk_dist = defaultdict(int)
    for s in all_sessions:
        risk_dist[s.risk] += 1
    summary.risk_dist = dict(risk_dist)

    # Connections per ID
    conn_per_id = defaultdict(int)
    for c in all_connections:
        if c.remote_id:
            conn_per_id[c.remote_id] += 1
    summary.conn_per_id = dict(sorted(conn_per_id.items()))

    # Cross-RMM IP correlation
    ip_to_rmms = defaultdict(set)
    for rmm_name, pr in results.items():
        for ip in pr.public_ips:
            ip_to_rmms[ip].add(rmm_name)
    summary.cross_rmm_ips = {
        ip: sorted(rmms) for ip, rmms in ip_to_rmms.items() if len(rmms) > 1
    }

    # Incident proximity
    if incident and incident.has_incident_date:
        for s in all_sessions:
            if s.start_dt:
                s.incident_proximity_hours = incident.proximity_hours(s.start_dt)
                s.incident_proximity_label = incident.classify_proximity(s.start_dt)

        summary.sessions_within_24h = [s for s in all_sessions if s.incident_proximity_label == "CRÍTICO (±24h)"]
        summary.sessions_within_3d = [s for s in all_sessions if s.incident_proximity_label in ("CRÍTICO (±24h)", "ALTO (±3d)")]
        summary.sessions_within_7d = [s for s in all_sessions if s.incident_proximity_label in ("CRÍTICO (±24h)", "ALTO (±3d)", "MEDIO (±7d)")]

        # Detect anomalies
        _detect_anomalies(summary, all_sessions, all_connections, incident)

    # Session-to-connection matching within each RMM
    _match_sessions_to_connections(all_sessions, all_connections)

    return summary


def _match_sessions_to_connections(sessions, connections):
    """Match sessions to their closest connection records."""
    by_rmm_id = defaultdict(list)
    for c in connections:
        by_rmm_id[(c.rmm_type.value, c.remote_id)].append(c)

    for s in sessions:
        matches = by_rmm_id.get((s.rmm_type.value, s.remote_id), [])
        if matches and s.start_dt:
            s.conn_record = min(
                matches,
                key=lambda c: abs((c.datetime - s.start_dt).total_seconds()) if c.datetime else 99999,
            )


def _detect_anomalies(summary, sessions, connections, incident):
    """Detect anomalous patterns around the incident date."""
    if not incident.incident_date:
        return

    # Unusual hours near incident (outside business hours 8-18)
    near_sessions = summary.sessions_within_3d
    odd_hours = [s for s in near_sessions if s.start_dt and (s.start_dt.hour < 7 or s.start_dt.hour > 20)]
    if odd_hours:
        summary.anomalous_patterns.append(
            f"{len(odd_hours)} sesión(es) en horario inusual (fuera de 07:00-20:00) dentro de ±3 días del incidente"
        )

    # First-seen remote IDs near incident
    all_ids_with_dates = defaultdict(list)
    for s in sessions:
        if s.start_dt and s.remote_id:
            all_ids_with_dates[s.remote_id].append(s.start_dt)

    for rid, dates in all_ids_with_dates.items():
        first_seen = min(dates)
        proximity = incident.classify_proximity(first_seen)
        if proximity in ("CRÍTICO (±24h)", "ALTO (±3d)"):
            summary.anomalous_patterns.append(
                f"ID remoto '{rid}' apareció por primera vez dentro de la ventana del incidente ({proximity})"
            )

    # Connection spike detection
    if near_sessions:
        avg_sessions = len(sessions) / max(len(set(s.start_dt.date() for s in sessions if s.start_dt)), 1)
        incident_day_sessions = sum(1 for s in near_sessions if s.start_dt and s.start_dt.date() == incident.incident_date.date())
        if incident_day_sessions > avg_sessions * 2 and incident_day_sessions > 2:
            summary.anomalous_patterns.append(
                f"Pico de actividad el día del incidente: {incident_day_sessions} sesiones (promedio: {avg_sessions:.1f}/día)"
            )
