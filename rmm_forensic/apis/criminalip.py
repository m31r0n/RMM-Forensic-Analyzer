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
            params={"ip": ip},
            timeout=15,
        )
        r.raise_for_status()
        d = r.json()

        score_data = d.get("score", {})
        issues = d.get("issues", {})

        result = {
            "ip":         ip,
            "score":      score_data.get("inbound", 0),
            "risk":       _map_risk(score_data.get("inbound", 0)),
            "country":    d.get("ip_scoring", {}).get("country", ""),
            "isp":        d.get("whois", {}).get("as_name", ""),
            "is_vpn":     issues.get("is_vpn", False),
            "is_proxy":   issues.get("is_proxy", False),
            "is_tor":     issues.get("is_tor", False),
            "source":     "CriminalIP",
        }
        cache.set(cache_key, result)
        return result

    except Exception as e:
        return {"error": str(e), "ip": ip}


def _map_risk(score: float) -> str:
    """Mapea score numérico a nivel de riesgo."""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "dangerous"
    elif score >= 40:
        return "moderate"
    elif score >= 20:
        return "low"
    return "safe"


def apply_criminalip(enrichment: IPEnrichment, result: dict) -> None:
    """Vuelca el dict de resultado en un objeto IPEnrichment."""
    if "error" in result:
        enrichment.criminalip_error = result["error"]
        return
    enrichment.criminalip_score   = result.get("score")
    enrichment.criminalip_risk    = result.get("risk", "")
    enrichment.criminalip_country = result.get("country", "")
    enrichment.criminalip_isp     = result.get("isp", "")
    enrichment.criminalip_is_vpn  = result.get("is_vpn", False)
    enrichment.criminalip_is_proxy = result.get("is_proxy", False)
    enrichment.criminalip_is_tor  = result.get("is_tor", False)
