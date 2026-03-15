from collections import defaultdict
from ..models.base import RMMSession
from ..models.enrichment import IPEnrichment
from ..models.incident import IncidentContext

def classify_sessions_by_country(
    sessions: list[RMMSession],
    ip_results: list[IPEnrichment],
    ctx: IncidentContext,
) -> dict[str, list[RMMSession]]:
    """
    Classify sessions by country origin.
    Returns dict with keys "Informativa", "Sospechosa", "Desconocida".
    """
    ip_countries = {e.ip: e.country for e in ip_results if e.country}

    result = {"Informativa": [], "Sospechosa": [], "Desconocida": []}

    for s in sessions:
        classified = False
        for ip in s.public_ips:
            country = ip_countries.get(ip, "")
            if country:
                classification = ctx.classify_country(country)
                s.country_classification = classification
                if classification:
                    result[classification].append(s)
                    classified = True
                    break
        if not classified:
            result["Desconocida"].append(s)

    return result


def get_country_summary(
    ip_results: list[IPEnrichment],
    origin_country: str,
) -> dict[str, int]:
    """Count IPs by country, highlighting foreign ones."""
    country_counts = defaultdict(int)
    for e in ip_results:
        if e.country:
            label = e.country
            if origin_country and e.country.upper() != origin_country.upper():
                label = f"{e.country} ⚠ EXTRANJERA"
            country_counts[label] += 1
    return dict(sorted(country_counts.items(), key=lambda x: -x[1]))
