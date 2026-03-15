"""Modelo de enriquecimiento de IP — datos de AbuseIPDB, VirusTotal, CriminalIP, TOR."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IPEnrichment:
    """Datos de enriquecimiento de una IP pública."""
    ip:            str
    ip_type:       str = ""        # "Relay", "Externo", "Candidato", "Sesión"

    # AbuseIPDB
    abuse_score:   Optional[int]   = None
    abuse_country: str             = ""
    abuse_isp:     str             = ""
    abuse_reports: Optional[int]   = None
    abuse_usage:   str             = ""
    abuse_tor:     bool            = False
    abuse_error:   str             = ""

    # VirusTotal
    vt_malicious:  Optional[int]   = None
    vt_suspicious: Optional[int]   = None
    vt_harmless:   Optional[int]   = None
    vt_country:    str             = ""
    vt_as_owner:   str             = ""
    vt_network:    str             = ""
    vt_reputation: Optional[int]   = None
    vt_error:      str             = ""

    # CriminalIP — score & risk
    criminalip_score:          Optional[float] = None
    criminalip_score_outbound: Optional[float] = None
    criminalip_risk:           str             = ""     # "safe", "low", "moderate", "dangerous", "critical"
    criminalip_risk_outbound:  str             = ""
    criminalip_error:          str             = ""

    # CriminalIP — geo / ISP
    criminalip_country: str = ""
    criminalip_city:    str = ""
    criminalip_isp:     str = ""
    criminalip_as_no:   str = ""

    # CriminalIP — issue flags
    criminalip_is_vpn:           bool = False
    criminalip_is_proxy:         bool = False
    criminalip_is_tor:           bool = False
    criminalip_is_cloud:         bool = False
    criminalip_is_hosting:       bool = False
    criminalip_is_darkweb:       bool = False
    criminalip_is_scanner:       bool = False
    criminalip_is_anonymous_vpn: bool = False

    # CriminalIP — open ports
    criminalip_open_port_count:  int             = 0
    criminalip_open_ports:       list[str]       = field(default_factory=list)

    # CriminalIP — vulnerabilities
    criminalip_vuln_count:       int             = 0
    criminalip_vulns:            list[str]       = field(default_factory=list)

    # CriminalIP — domains / hostnames
    criminalip_domain_count:     int             = 0
    criminalip_hostname_count:   int             = 0
    criminalip_hostnames:        list[str]       = field(default_factory=list)

    # CriminalIP — IDS / honeypot / categories
    criminalip_ids_count:        int             = 0
    criminalip_ids_alerts:       list[str]       = field(default_factory=list)
    criminalip_honeypot_count:   int             = 0
    criminalip_categories:       list[str]       = field(default_factory=list)

    # TOR exit node
    is_tor_exit_node:   bool            = False

    # ── Propiedades calculadas ────────────────────────────────────

    @property
    def is_malicious(self) -> bool:
        return (
            (self.abuse_score is not None and self.abuse_score >= 75)
            or (self.vt_malicious is not None and self.vt_malicious > 0)
            or self.criminalip_risk in ("dangerous", "critical")
        )

    @property
    def is_suspicious(self) -> bool:
        return (
            (self.abuse_score is not None and self.abuse_score >= 25)
            or self.abuse_tor
            or self.is_tor_exit_node
            or (self.vt_suspicious is not None and self.vt_suspicious > 0)
            or self.criminalip_risk == "moderate"
            or self.criminalip_is_vpn
            or self.criminalip_is_proxy
            or self.criminalip_is_tor
            or self.criminalip_is_darkweb
            or self.criminalip_is_scanner
        )

    @property
    def is_tor(self) -> bool:
        return self.abuse_tor or self.is_tor_exit_node or self.criminalip_is_tor

    @property
    def country(self) -> str:
        return self.abuse_country or self.vt_country or self.criminalip_country

    @property
    def isp(self) -> str:
        return self.abuse_isp or self.vt_as_owner or self.criminalip_isp

    def to_dict(self) -> dict:
        """Convierte a dict para compatibilidad con templates."""
        return {
            "ip": self.ip,
            "ip_type": self.ip_type,
            "abuse": {
                "score":   self.abuse_score,
                "country": self.abuse_country,
                "isp":     self.abuse_isp,
                "reports": self.abuse_reports,
                "usage":   self.abuse_usage,
                "tor":     self.abuse_tor,
                "error":   self.abuse_error,
            },
            "vt": {
                "malicious":  self.vt_malicious,
                "suspicious": self.vt_suspicious,
                "country":    self.vt_country,
                "as_owner":   self.vt_as_owner,
                "network":    self.vt_network,
                "reputation": self.vt_reputation,
                "error":      self.vt_error,
            },
            "criminalip": {
                "score":          self.criminalip_score,
                "score_outbound": self.criminalip_score_outbound,
                "risk":           self.criminalip_risk,
                "risk_outbound":  self.criminalip_risk_outbound,
                "country":        self.criminalip_country,
                "city":           self.criminalip_city,
                "isp":            self.criminalip_isp,
                "as_no":          self.criminalip_as_no,
                "is_vpn":         self.criminalip_is_vpn,
                "is_proxy":       self.criminalip_is_proxy,
                "is_tor":         self.criminalip_is_tor,
                "is_cloud":       self.criminalip_is_cloud,
                "is_hosting":     self.criminalip_is_hosting,
                "is_darkweb":     self.criminalip_is_darkweb,
                "is_scanner":     self.criminalip_is_scanner,
                "is_anonymous_vpn": self.criminalip_is_anonymous_vpn,
                "open_port_count": self.criminalip_open_port_count,
                "open_ports":     self.criminalip_open_ports,
                "vuln_count":     self.criminalip_vuln_count,
                "vulns":          self.criminalip_vulns,
                "domain_count":   self.criminalip_domain_count,
                "hostname_count": self.criminalip_hostname_count,
                "hostnames":      self.criminalip_hostnames,
                "ids_count":      self.criminalip_ids_count,
                "ids_alerts":     self.criminalip_ids_alerts,
                "honeypot_count": self.criminalip_honeypot_count,
                "categories":     self.criminalip_categories,
                "error":          self.criminalip_error,
            },
            "is_tor": self.is_tor,
            "country": self.country,
            "isp": self.isp,
        }
