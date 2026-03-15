"""Consulta CriminalIP API — con caché y manejo de errores."""

from __future__ import annotations
from typing import TYPE_CHECKING

from ..models.enrichment import IPEnrichment

if TYPE_CHECKING:
    from .cache import IPCache

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

_API_URL = "https://api.criminalip.io/v1/asset/ip/report"

# Mapeo del texto de score que devuelve la API a un valor numérico y nivel.
_SCORE_MAP: dict[str, tuple[int, str]] = {
    "critical":  (90, "critical"),
    "dangerous": (70, "dangerous"),
    "moderate":  (50, "moderate"),
    "low":       (20, "low"),
    "safe":      (5,  "safe"),
}


def query_criminalip(
    ip:    str,
    key:   str,
    cache: "IPCache",
) -> dict:
    """
    Consulta CriminalIP para una IP pública.
    Devuelve dict con campos normalizados y escribe en caché.
    """
    if not key:
        return {"error": "Sin API key configurada", "ip": ip}

    cache_key = f"criminalip_{ip}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    if not HAS_REQUESTS:
        return {"error": "Módulo 'requests' no instalado", "ip": ip}

    try:
        r = requests.get(
            _API_URL,
            headers={"x-api-key": key},
            params={"ip": ip, "full": "true"},
            timeout=15,
        )
        r.raise_for_status()
        d = r.json()

        result = _normalize_response(ip, d)
        cache.set(cache_key, result)
        return result

    except Exception as e:
        return {"error": str(e), "ip": ip}


def _normalize_response(ip: str, d: dict) -> dict:
    """Normaliza la respuesta cruda de CriminalIP a un dict plano."""

    # ── Score (la API devuelve strings: "Critical", "Safe", etc.) ─────
    score_data = d.get("score", {})
    inbound_raw = str(score_data.get("inbound", "")).strip().lower()
    outbound_raw = str(score_data.get("outbound", "")).strip().lower()
    inbound_score, inbound_risk = _SCORE_MAP.get(inbound_raw, (0, "unknown"))
    outbound_score, outbound_risk = _SCORE_MAP.get(outbound_raw, (0, "unknown"))

    # ── Issues / flags ────────────────────────────────────────────────
    issues = d.get("issues", {})

    # ── Whois (nested: whois.data[0]) ─────────────────────────────────
    whois_list = d.get("whois", {}).get("data", [])
    whois = whois_list[0] if whois_list else {}
    as_name = whois.get("as_name", "")
    as_no = whois.get("as_no", "")
    country = whois.get("org_country_code", "").upper()
    city = whois.get("city", "")
    region = whois.get("region", "")

    # ── Open ports ────────────────────────────────────────────────────
    port_data = d.get("port", {})
    port_count = port_data.get("count", 0)
    ports_list = port_data.get("data", [])
    open_ports_summary = []
    for p in ports_list[:20]:  # Limitar a 20 puertos
        port_no = p.get("open_port_no", "")
        protocol = p.get("protocol", "")
        app = p.get("app_name", "")
        tags = p.get("tags", [])
        entry = f"{port_no}/{protocol}"
        if app and app != "Unknown":
            entry += f" ({app})"
        if tags:
            entry += f" [{', '.join(tags)}]"
        open_ports_summary.append(entry)

    # ── Vulnerabilities ───────────────────────────────────────────────
    vuln_data = d.get("vulnerability", {})
    vuln_count = vuln_data.get("count", 0)
    vulns_list = vuln_data.get("data", [])
    vulns_summary = []
    for v in vulns_list[:10]:  # Top 10 vulns
        cve_id = v.get("cve_id", "")
        cvss3 = v.get("cvssv3_score", "")
        app = v.get("app_name", "")
        entry = cve_id
        if cvss3:
            entry += f" (CVSS3: {cvss3})"
        if app:
            entry += f" - {app}"
        vulns_summary.append(entry)

    # ── Domains ───────────────────────────────────────────────────────
    domain_data = d.get("domain", {})
    domain_count = domain_data.get("count", 0)

    # ── Hostnames ─────────────────────────────────────────────────────
    hostname_data = d.get("hostname", {})
    hostname_count = hostname_data.get("count", 0)
    hostnames = [
        h.get("domain_name_full", "")
        for h in hostname_data.get("data", [])[:10]
        if h.get("domain_name_full")
    ]

    # ── IDS alerts ────────────────────────────────────────────────────
    ids_data = d.get("ids", {})
    ids_count = ids_data.get("count", 0)
    ids_summary = []
    for alert in ids_data.get("data", [])[:5]:
        msg = alert.get("message", "")
        classification = alert.get("classification", "")
        entry = classification
        if msg:
            entry += f": {msg[:120]}"
        ids_summary.append(entry)

    # ── Honeypot ──────────────────────────────────────────────────────
    honeypot_data = d.get("honeypot", {})
    honeypot_count = honeypot_data.get("count", 0)

    # ── IP categories ─────────────────────────────────────────────────
    categories_data = d.get("ip_category", {})
    categories = [
        c.get("type", "")
        for c in categories_data.get("data", [])
        if c.get("type")
    ]

    result = {
        "ip":               ip,
        "source":           "CriminalIP",
        # Score
        "score":            inbound_score,
        "score_outbound":   outbound_score,
        "risk":             inbound_risk,
        "risk_outbound":    outbound_risk,
        # Geo / ISP
        "country":          country,
        "city":             city,
        "region":           region,
        "isp":              as_name,
        "as_no":            as_no,
        # Issue flags
        "is_vpn":           issues.get("is_vpn", False),
        "is_proxy":         issues.get("is_proxy", False),
        "is_tor":           issues.get("is_tor", False),
        "is_cloud":         issues.get("is_cloud", False),
        "is_hosting":       issues.get("is_hosting", False),
        "is_darkweb":       issues.get("is_darkweb", False),
        "is_scanner":       issues.get("is_scanner", False),
        "is_snort":         issues.get("is_snort", False),
        "is_anonymous_vpn": issues.get("is_anonymous_vpn", False),
        "is_mobile":        issues.get("is_mobile", False),
        # Open ports
        "open_port_count":  port_count,
        "open_ports":       open_ports_summary,
        # Vulnerabilities
        "vuln_count":       vuln_count,
        "vulns":            vulns_summary,
        # Domains / Hostnames
        "domain_count":     domain_count,
        "hostname_count":   hostname_count,
        "hostnames":        hostnames,
        # IDS / Honeypot
        "ids_count":        ids_count,
        "ids_alerts":       ids_summary,
        "honeypot_count":   honeypot_count,
        # Categories
        "categories":       categories,
    }

    return result


def apply_criminalip(enrichment: IPEnrichment, result: dict) -> None:
    """Vuelca el dict de resultado en un objeto IPEnrichment."""
    if "error" in result:
        enrichment.criminalip_error = result["error"]
        return

    # Score & risk
    enrichment.criminalip_score       = result.get("score")
    enrichment.criminalip_score_outbound = result.get("score_outbound")
    enrichment.criminalip_risk        = result.get("risk", "")
    enrichment.criminalip_risk_outbound = result.get("risk_outbound", "")

    # Geo / ISP
    enrichment.criminalip_country     = result.get("country", "")
    enrichment.criminalip_city        = result.get("city", "")
    enrichment.criminalip_isp         = result.get("isp", "")
    enrichment.criminalip_as_no       = result.get("as_no", "")

    # Issue flags
    enrichment.criminalip_is_vpn      = result.get("is_vpn", False)
    enrichment.criminalip_is_proxy    = result.get("is_proxy", False)
    enrichment.criminalip_is_tor      = result.get("is_tor", False)
    enrichment.criminalip_is_cloud    = result.get("is_cloud", False)
    enrichment.criminalip_is_hosting  = result.get("is_hosting", False)
    enrichment.criminalip_is_darkweb  = result.get("is_darkweb", False)
    enrichment.criminalip_is_scanner  = result.get("is_scanner", False)
    enrichment.criminalip_is_anonymous_vpn = result.get("is_anonymous_vpn", False)

    # Port / Vuln / Domain / IDS / Honeypot
    enrichment.criminalip_open_port_count = result.get("open_port_count", 0)
    enrichment.criminalip_open_ports  = result.get("open_ports", [])
    enrichment.criminalip_vuln_count  = result.get("vuln_count", 0)
    enrichment.criminalip_vulns       = result.get("vulns", [])
    enrichment.criminalip_domain_count = result.get("domain_count", 0)
    enrichment.criminalip_hostname_count = result.get("hostname_count", 0)
    enrichment.criminalip_hostnames   = result.get("hostnames", [])
    enrichment.criminalip_ids_count   = result.get("ids_count", 0)
    enrichment.criminalip_ids_alerts  = result.get("ids_alerts", [])
    enrichment.criminalip_honeypot_count = result.get("honeypot_count", 0)
    enrichment.criminalip_categories  = result.get("categories", [])
