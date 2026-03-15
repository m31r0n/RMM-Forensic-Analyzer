"""
Orquestador de enriquecimiento de IPs.
Integra AbuseIPDB, VirusTotal, CriminalIP y verificación TOR.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

from ..models.enrichment import IPEnrichment
from ..utils import is_private

from .abuseipdb import query_abuseipdb, apply_abuseipdb
from .virustotal import query_virustotal, apply_virustotal
from .criminalip import query_criminalip, apply_criminalip
from .tor_exit_nodes import TorExitNodeChecker

if TYPE_CHECKING:
    from .cache import IPCache
    from ..config import Config

try:
    from colorama import Fore, Style
except ImportError:
    class Fore:
        YELLOW = GREEN = CYAN = RED = ""
    class Style:
        RESET_ALL = ""


def enrich_ips(
    public_ips: set[str],
    cache:      "IPCache",
    config:     "Config",
    ip_types:   dict[str, str] | None = None,
    verbose:    bool = True,
) -> list[IPEnrichment]:
    """
    Enriquece IPs públicas con AbuseIPDB, VirusTotal, CriminalIP y TOR.

    Args:
        public_ips: Conjunto de IPs públicas a enriquecer
        cache: Instancia de IPCache
        config: Instancia de Config
        ip_types: Mapeo opcional IP → tipo ("Relay", "Externo", "Candidato", "Sesión")
        verbose: Mostrar progreso
    """
    ip_types = ip_types or {}

    # Filtrar privadas y ordenar
    ordered: list[tuple[str, str]] = []
    for ip in sorted(public_ips):
        if ip and not is_private(ip):
            ordered.append((ip, ip_types.get(ip, "Sesión")))

    if not ordered:
        return []

    has_vt      = bool(config.vt_key)
    has_abuse   = bool(config.abuse_key)
    has_cip     = bool(config.criminalip_key)

    if not has_vt and not has_abuse and not has_cip:
        if verbose:
            print(f"  {Fore.YELLOW}[!] Sin API keys configuradas — solo verificación TOR{Style.RESET_ALL}")

    # TOR exit node checker
    tor_checker = TorExitNodeChecker(config.get("tor_exit_node_cache", "tor_exit_nodes.txt"))

    results: list[IPEnrichment] = []
    total = len(ordered)

    for i, (ip, ip_type) in enumerate(ordered, 1):
        if verbose:
            print(f"  {Fore.CYAN}[{i}/{total}] Consultando {ip} ({ip_type})...{Style.RESET_ALL}")

        enrichment = IPEnrichment(ip=ip, ip_type=ip_type)

        # TOR check (siempre, no requiere API key)
        enrichment.is_tor_exit_node = tor_checker.is_exit_node(ip)

        # AbuseIPDB
        if has_abuse:
            abuse_result = query_abuseipdb(
                ip, config.abuse_key, cache,
                max_age=config.get("max_age_days_abuseipdb", 90),
            )
            apply_abuseipdb(enrichment, abuse_result)

        # VirusTotal
        if has_vt:
            vt_result = query_virustotal(
                ip, config.vt_key, cache,
                rate_sleep=config.get("vt_rate_limit_sleep", 0.5),
            )
            apply_virustotal(enrichment, vt_result)

        # CriminalIP
        if has_cip:
            cip_result = query_criminalip(ip, config.criminalip_key, cache)
            apply_criminalip(enrichment, cip_result)

        if verbose:
            _print_ip_result(enrichment)

        results.append(enrichment)

    cache.save()
    return results


def _print_ip_result(e: IPEnrichment) -> None:
    """Imprime resultado de enriquecimiento de una IP."""
    parts = []

    if e.abuse_score is not None:
        color = Fore.RED if e.abuse_score >= 75 else (Fore.YELLOW if e.abuse_score >= 25 else Fore.GREEN)
        parts.append(f"Abuse={color}{e.abuse_score}%{Style.RESET_ALL}")

    if e.vt_malicious is not None:
        color = Fore.RED if e.vt_malicious > 0 else Fore.GREEN
        parts.append(f"VT={color}{e.vt_malicious} mal{Style.RESET_ALL}")

    if e.criminalip_risk:
        color = Fore.RED if e.criminalip_risk in ("dangerous", "critical") else (
            Fore.YELLOW if e.criminalip_risk == "moderate" else Fore.GREEN)
        parts.append(f"CIP={color}{e.criminalip_risk}{Style.RESET_ALL}")

    if e.is_tor:
        parts.append(f"{Fore.RED}TOR{Style.RESET_ALL}")

    if e.country:
        parts.append(f"País={e.country}")

    # CriminalIP enrichment flags
    flags = []
    if e.criminalip_is_vpn or e.criminalip_is_anonymous_vpn:
        flags.append("VPN")
    if e.criminalip_is_proxy:
        flags.append("Proxy")
    if e.criminalip_is_darkweb:
        flags.append("DarkWeb")
    if e.criminalip_is_scanner:
        flags.append("Scanner")
    if e.criminalip_is_hosting:
        flags.append("Hosting")
    if e.criminalip_is_cloud:
        flags.append("Cloud")
    if flags:
        parts.append(f"{Fore.YELLOW}{','.join(flags)}{Style.RESET_ALL}")

    if parts:
        print(f"    → {' | '.join(parts)}")

    # CriminalIP detail line (ports, vulns, IDS)
    details = []
    if e.criminalip_open_port_count:
        details.append(f"Puertos:{e.criminalip_open_port_count}")
    if e.criminalip_vuln_count:
        color = Fore.RED if e.criminalip_vuln_count >= 5 else Fore.YELLOW
        details.append(f"CVEs:{color}{e.criminalip_vuln_count}{Style.RESET_ALL}")
    if e.criminalip_domain_count:
        details.append(f"Dominios:{e.criminalip_domain_count}")
    if e.criminalip_ids_count:
        details.append(f"{Fore.RED}IDS:{e.criminalip_ids_count}{Style.RESET_ALL}")
    if e.criminalip_honeypot_count:
        details.append(f"{Fore.RED}Honeypot:{e.criminalip_honeypot_count}{Style.RESET_ALL}")
    if details:
        print(f"      CIP detalle: {' | '.join(details)}")
