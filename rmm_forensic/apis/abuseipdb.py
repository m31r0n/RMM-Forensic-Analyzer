"""Consulta AbuseIPDB v2 — con caché y manejo de errores."""

from __future__ import annotations
from typing import TYPE_CHECKING

from ..models.enrichment import IPEnrichment
from ..utils import cprint

if TYPE_CHECKING:
    from .cache import IPCache

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore
except ImportError:
    class Fore:
        RED = YELLOW = ""

_API_URL = "https://api.abuseipdb.com/api/v2/check"


def query_abuseipdb(
    ip:      str,
    key:     str,
    cache:   "IPCache",
    max_age: int = 90,
) -> dict:
    """
    Consulta AbuseIPDB v2 para una IP pública.
    Devuelve dict con campos normalizados y escribe en caché.
    """
    if not key:
        return {"error": "Sin API key configurada", "ip": ip}

    cache_key = f"abuse_{ip}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    if not HAS_REQUESTS:
        return {"error": "Módulo 'requests' no instalado", "ip": ip}

    try:
        r = requests.get(
            _API_URL,
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age},
            timeout=10,
        )
        r.raise_for_status()
        d = r.json().get("data", {})

        result = {
            "ip":            ip,
            "score":         d.get("abuseConfidenceScore", 0),
            "country":       d.get("countryCode", ""),
            "isp":           d.get("isp", ""),
            "domain":        d.get("domain", ""),
            "reports":       d.get("totalReports", 0),
            "last_reported": d.get("lastReportedAt", ""),
            "usage":         d.get("usageType", ""),
            "whitelisted":   d.get("isWhitelisted", False),
            "tor":           d.get("isTor", False),
            "source":        "AbuseIPDB",
        }
        cache.set(cache_key, result)
        return result

    except Exception as e:
        return {"error": str(e), "ip": ip}


def apply_abuseipdb(enrichment: IPEnrichment, result: dict) -> None:
    """Vuelca el dict de resultado en un objeto IPEnrichment."""
    if "error" in result:
        enrichment.abuse_error = result["error"]
        return
    enrichment.abuse_score   = result.get("score")
    enrichment.abuse_country = result.get("country", "")
    enrichment.abuse_isp     = result.get("isp", "")
    enrichment.abuse_reports = result.get("reports")
    enrichment.abuse_usage   = result.get("usage", "")
    enrichment.abuse_tor     = result.get("tor", False)
