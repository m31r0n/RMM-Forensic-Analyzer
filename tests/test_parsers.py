"""
Tests básicos — se ejecutan sin archivos reales.
pytest tests/
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from rmm_forensic.models.base import RMMType, RMMSession, ParseResult, ConnectionDirection, RMMConnection
from rmm_forensic.models.enrichment import IPEnrichment
from rmm_forensic.models.incident import IncidentContext
from rmm_forensic.models.summary import ForensicSummary
from rmm_forensic.analyzer.risk_scoring import score_session, score_all
from rmm_forensic.apis.cache import IPCache
from rmm_forensic.config import Config
from rmm_forensic.utils import is_private, fmt_dur, fmt_dt


# ─── Models ───────────────────────────────────────────────────────────────────

def test_rmm_session_defaults():
    s = RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="123456")
    assert s.risk == "BAJO"
    assert s.file_transfers == 0
    assert s.elevated is False
    assert s.public_ips == []


def test_rmm_session_to_dict():
    s = RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="123456")
    d = s.to_dict()
    assert d["rmm_type"] == "AnyDesk"
    assert d["remote_id"] == "123456"


def test_rmm_session_all_ips():
    s = RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="123",
                   public_ips=["1.2.3.4", "5.6.7.8", "1.2.3.4"])
    assert "1.2.3.4" in s.all_ips
    assert "5.6.7.8" in s.all_ips
    # Deduplicated
    assert len(s.all_ips) == 2


def test_parse_result_merge():
    r1 = ParseResult(rmm_type=RMMType.ANYDESK)
    r1.sessions.append(RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="111"))
    r1.public_ips = {"1.2.3.4"}

    r2 = ParseResult(rmm_type=RMMType.ANYDESK)
    r2.sessions.append(RMMSession(idx=2, rmm_type=RMMType.ANYDESK, remote_id="222"))
    r2.public_ips = {"5.6.7.8"}

    r1.merge(r2)
    assert len(r1.sessions) == 2
    assert "5.6.7.8" in r1.public_ips


def test_connection_direction():
    c = RMMConnection(
        rmm_type=RMMType.TEAMVIEWER,
        direction=ConnectionDirection.INCOMING,
        datetime=None,
        dt_str="2024-01-01",
    )
    assert c.direction == ConnectionDirection.INCOMING


# ─── Risk scoring ─────────────────────────────────────────────────────────────

def test_risk_low_empty_session():
    s = RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="123")
    level, score, reasons = score_session(s)
    assert level == "BAJO"
    assert score == 0
    assert reasons == []


def test_risk_elevated_increases_score():
    s = RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="123",
                   elevated=True)
    level, score, reasons = score_session(s)
    assert score >= 3
    assert any("elevad" in r for r in reasons)


def test_risk_file_transfers():
    s = RMMSession(idx=1, rmm_type=RMMType.TEAMVIEWER, remote_id="123",
                   file_transfers=5)
    level, score, reasons = score_session(s)
    assert score >= 3
    assert any("transferencia" in r for r in reasons)


def test_risk_massive_clipboard():
    s = RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="123",
                   clipboard_max_files=272)
    level, score, reasons = score_session(s)
    assert level in ("CRÍTICO", "ALTO")
    assert score >= 4
    assert any("272" in r for r in reasons)


def test_risk_anydesk_winlogon():
    s = RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="123",
                   extras={"winlogon_switches": 3})
    level, score, reasons = score_session(s)
    assert score >= 2
    assert any("Winlogon" in r for r in reasons)


def test_risk_screenconnect_commands():
    s = RMMSession(idx=1, rmm_type=RMMType.SCREENCONNECT, remote_id="abc",
                   extras={"commands_executed": 5})
    level, score, reasons = score_session(s)
    assert score >= 2
    assert any("comando" in r for r in reasons)


def test_score_all_applies_to_list():
    sessions = [
        RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="111"),
        RMMSession(idx=2, rmm_type=RMMType.ANYDESK, remote_id="222", elevated=True),
    ]
    score_all(sessions)
    assert sessions[0].risk == "BAJO"
    assert sessions[1].risk_score >= 3


# ─── Incident Context ────────────────────────────────────────────────────────

def test_incident_context_proximity():
    from datetime import datetime, timedelta
    ctx = IncidentContext(incident_date=datetime(2024, 3, 15, 12, 0, 0))

    # Within 24h
    near = datetime(2024, 3, 15, 20, 0, 0)
    assert ctx.classify_proximity(near) == "CRÍTICO (±24h)"

    # Within 3 days
    mid = datetime(2024, 3, 17, 12, 0, 0)
    assert ctx.classify_proximity(mid) == "ALTO (±3d)"

    # Within 7 days
    far = datetime(2024, 3, 20, 12, 0, 0)
    assert ctx.classify_proximity(far) == "MEDIO (±7d)"

    # Outside
    outside = datetime(2024, 4, 1, 12, 0, 0)
    assert ctx.classify_proximity(outside) == "Fuera de ventana"


def test_incident_context_country():
    ctx = IncidentContext(origin_country="MX")
    assert ctx.classify_country("MX") == "Informativa"
    assert ctx.classify_country("mx") == "Informativa"
    assert ctx.classify_country("RU") == "Sospechosa"
    assert ctx.classify_country("") == ""


def test_incident_context_no_date():
    ctx = IncidentContext()
    assert ctx.has_incident_date is False
    assert ctx.classify_proximity(None) == ""


# ─── IPEnrichment ─────────────────────────────────────────────────────────────

def test_ip_enrichment_malicious():
    e = IPEnrichment(ip="1.2.3.4", abuse_score=90)
    assert e.is_malicious is True

    e2 = IPEnrichment(ip="1.2.3.4", vt_malicious=3)
    assert e2.is_malicious is True

    e3 = IPEnrichment(ip="1.2.3.4", criminalip_risk="dangerous")
    assert e3.is_malicious is True


def test_ip_enrichment_tor():
    e = IPEnrichment(ip="1.2.3.4", abuse_tor=True)
    assert e.is_tor is True

    e2 = IPEnrichment(ip="1.2.3.4", is_tor_exit_node=True)
    assert e2.is_tor is True


def test_ip_enrichment_country_priority():
    e = IPEnrichment(ip="1.2.3.4", abuse_country="US", vt_country="US",
                     criminalip_country="US")
    assert e.country == "US"

    # Abuse has priority
    e2 = IPEnrichment(ip="1.2.3.4", abuse_country="", vt_country="DE")
    assert e2.country == "DE"


def test_ip_enrichment_to_dict():
    e = IPEnrichment(ip="1.2.3.4", abuse_score=50)
    d = e.to_dict()
    assert d["ip"] == "1.2.3.4"
    assert d["abuse"]["score"] == 50


# ─── ForensicSummary ──────────────────────────────────────────────────────────

def test_forensic_summary_all_sessions():
    from datetime import datetime
    pr = ParseResult(rmm_type=RMMType.ANYDESK)
    pr.sessions.append(RMMSession(idx=1, rmm_type=RMMType.ANYDESK, remote_id="111",
                                  start_dt=datetime(2024, 1, 2)))
    pr.sessions.append(RMMSession(idx=2, rmm_type=RMMType.ANYDESK, remote_id="222",
                                  start_dt=datetime(2024, 1, 1)))

    summary = ForensicSummary(results_by_rmm={"AnyDesk": pr})
    all_s = summary.all_sessions
    assert len(all_s) == 2
    # Should be sorted by date
    assert all_s[0].remote_id == "222"


def test_forensic_summary_all_public_ips():
    pr1 = ParseResult(rmm_type=RMMType.ANYDESK)
    pr1.public_ips = {"1.2.3.4"}
    pr2 = ParseResult(rmm_type=RMMType.TEAMVIEWER)
    pr2.public_ips = {"5.6.7.8", "1.2.3.4"}

    summary = ForensicSummary(results_by_rmm={"AnyDesk": pr1, "TeamViewer": pr2})
    assert summary.all_public_ips == {"1.2.3.4", "5.6.7.8"}


# ─── Cache ────────────────────────────────────────────────────────────────────

def test_cache_set_get():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = f.name
    try:
        cache = IPCache(tmp, ttl=3600)
        cache.set("abuse_1.2.3.4", {"score": 50})
        result = cache.get("abuse_1.2.3.4")
        assert result == {"score": 50}
    finally:
        os.unlink(tmp)


def test_cache_miss_returns_none():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = f.name
    try:
        cache = IPCache(tmp, ttl=3600)
        assert cache.get("not_existing_key") is None
    finally:
        os.unlink(tmp)


def test_cache_persistence():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = f.name
    try:
        c1 = IPCache(tmp)
        c1.set("vt_8.8.8.8", {"malicious": 0})
        c1.save()
        c2 = IPCache(tmp)
        assert c2.get("vt_8.8.8.8") == {"malicious": 0}
    finally:
        os.unlink(tmp)


def test_cache_clear():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp = f.name
    try:
        cache = IPCache(tmp)
        cache.set("key1", "val1")
        cache.set("key2", "val2")
        n = cache.clear()
        assert n == 2
        assert len(cache) == 0
    finally:
        os.unlink(tmp)


# ─── Config ───────────────────────────────────────────────────────────────────

def test_config_defaults():
    c = Config()
    assert c.output_dir == "output_forense"


def test_config_set_get():
    c = Config()
    c.vt_key = "test_key_123"
    assert c.vt_key == "test_key_123"


def test_config_criminalip():
    c = Config()
    c.criminalip_key = "cip_key_abc"
    assert c.criminalip_key == "cip_key_abc"


def test_config_env_override(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "env_key_abc")
    c = Config()
    c._load()
    assert c.vt_key == "env_key_abc"


def test_config_save_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "config.json")
        c = Config()
        c.vt_key = "abc123"
        c.abuse_key = "xyz789"
        from pathlib import Path
        c.save(Path(cfg_path))
        c2 = Config()
        c2._path = Path(cfg_path)
        c2._merge_file(Path(cfg_path))
        assert c2.vt_key == "abc123"
        assert c2.abuse_key == "xyz789"


# ─── Utils ────────────────────────────────────────────────────────────────────

def test_is_private():
    assert is_private("192.168.1.1") is True
    assert is_private("10.0.0.1") is True
    assert is_private("172.16.0.1") is True
    assert is_private("8.8.8.8") is False
    assert is_private("1.1.1.1") is False


def test_fmt_dur():
    assert fmt_dur(3661) == "1h 1m 1s"
    assert fmt_dur(90) == "1m 30s"
    assert fmt_dur(45) == "45s"
    assert fmt_dur(None) == "—"


def test_fmt_dt():
    from datetime import datetime
    dt = datetime(2024, 3, 15, 14, 30, 0)
    assert fmt_dt(dt) == "2024-03-15 14:30:00"
    assert fmt_dt(None) == "—"


# ─── Parser Registry ─────────────────────────────────────────────────────────

def test_parser_registry_has_anydesk():
    from rmm_forensic.parsers.registry import ParserRegistry
    assert "AnyDesk" in ParserRegistry.available_rmms()


def test_parser_registry_has_teamviewer():
    from rmm_forensic.parsers.registry import ParserRegistry
    assert "TeamViewer" in ParserRegistry.available_rmms()


def test_parser_registry_has_screenconnect():
    from rmm_forensic.parsers.registry import ParserRegistry
    assert "ScreenConnect" in ParserRegistry.available_rmms()


def test_parser_registry_get_for_file_anydesk(tmp_path):
    from rmm_forensic.parsers.registry import ParserRegistry
    trace = tmp_path / "ad.trace"
    trace.write_text("info 2024-01-01 10:00:00.000 A 1234 5678 some log line\n")
    parser = ParserRegistry.get_for_file(str(trace))
    assert parser is not None
    assert parser.rmm_type == RMMType.ANYDESK


def test_parser_registry_get_by_names():
    from rmm_forensic.parsers.registry import ParserRegistry
    parsers = ParserRegistry.get_by_names(["anydesk", "teamviewer"])
    names = [p.rmm_type.value for p in parsers]
    assert "AnyDesk" in names
    assert "TeamViewer" in names


# ─── Correlator ──────────────────────────────────────────────────────────────

def test_correlate_basic():
    from rmm_forensic.analyzer.correlator import correlate
    from datetime import datetime

    pr = ParseResult(rmm_type=RMMType.ANYDESK)
    pr.sessions.append(RMMSession(
        idx=1, rmm_type=RMMType.ANYDESK, remote_id="111",
        start_dt=datetime(2024, 1, 1, 10, 0), file_transfers=3,
    ))
    pr.connections.append(RMMConnection(
        rmm_type=RMMType.ANYDESK, direction=ConnectionDirection.INCOMING,
        datetime=datetime(2024, 1, 1, 10, 0), dt_str="2024-01-01",
        remote_id="111",
    ))

    summary = correlate({"AnyDesk": pr})
    assert summary.total_sessions == 1
    assert summary.total_connections == 1
    assert summary.incoming == 1
    assert summary.total_file_transfers == 3


def test_correlate_cross_rmm():
    from rmm_forensic.analyzer.correlator import correlate

    pr1 = ParseResult(rmm_type=RMMType.ANYDESK)
    pr1.public_ips = {"1.2.3.4"}

    pr2 = ParseResult(rmm_type=RMMType.TEAMVIEWER)
    pr2.public_ips = {"1.2.3.4", "5.6.7.8"}

    summary = correlate({"AnyDesk": pr1, "TeamViewer": pr2})
    assert "1.2.3.4" in summary.cross_rmm_ips
    assert "5.6.7.8" not in summary.cross_rmm_ips
