from ..models.base import RMMSession
from ..models.enrichment import IPEnrichment
from ..models.incident import IncidentContext

def apply_incident_context(
    sessions: list[RMMSession],
    ip_results: list[IPEnrichment],
    ctx: IncidentContext,
) -> None:
    """Apply incident context analysis to all sessions (in-place)."""
    if ctx.has_incident_date:
        for s in sessions:
            if s.start_dt:
                s.incident_proximity_hours = ctx.proximity_hours(s.start_dt)
                s.incident_proximity_label = ctx.classify_proximity(s.start_dt)

    if ctx.has_country:
        # Use IP enrichment data to classify sessions by country
        ip_countries = {e.ip: e.country for e in ip_results if e.country}
        for s in sessions:
            for ip in s.public_ips:
                country = ip_countries.get(ip, "")
                if country:
                    s.country_classification = ctx.classify_country(country)
                    break  # Use first matching IP's country
