"""Consulta VirusTotal v3 IPs — con caché, rate-limit y manejo de errores."""

from __future__ import annotations
import time
from typing import TYPE_CHECKING

from ..models.enrichment import IPEnrichment

if TYPE_CHECKING:
    from .cache import IPCache

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

_API_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"


def query_virustotal(
    ip:         str,
    key:        str,
    cache:      "IPCache",
    rate_sleep: float = 0.5,
) -> dict:
    """
    Consulta el endpoint de IPs de VirusTotal v3.
    Aplica sleep post-llamada para respetar el rate limit de la free tier.
    """
    if not key:
        return {"error": "Sin API key configurada", "ip": ip}

    cache_key = f"vt_{ip}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    if not HAS_REQUESTS:
        return {"error": "Módulo 'requests' no instalado", "ip": ip}

    try:
        r = requests.get(
            _API_URL.format(ip=ip),
            headers={"x-apikey": key},
            timeout=15,
        )
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = {
            "ip":         ip,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "country":    attrs.get("country", ""),
            "asn":        attrs.get("asn", ""),
            "as_owner":   attrs.get("as_owner", ""),
            "network":    attrs.get("network", ""),
            "reputation": attrs.get("reputation", 0),
            "source":     "VirusTotal",
        }
        cache.set(cache_key, result)
        time.sleep(rate_sleep)
        return result

    except Exception as e:
        return {"error": str(e), "ip": ip}


def apply_virustotal(enrichment: IPEnrichment, result: dict) -> None:
    """Vuelca el dict de resultado en un objeto IPEnrichment."""
    if "error" in result:
        enrichment.vt_error = result["error"]
        return
    enrichment.vt_malicious  = result.get("malicious")
    enrichment.vt_suspicious = result.get("suspicious")
    enrichment.vt_harmless   = result.get("harmless")
    enrichment.vt_country    = result.get("country", "")
    enrichment.vt_as_owner   = result.get("as_owner", "")
    enrichment.vt_network    = result.get("network", "")
    enrichment.vt_reputation = result.get("reputation")
