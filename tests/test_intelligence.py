import asyncio, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.intelligence import collect, VirusTotal, URLhaus, tls
from app.features import normalize


def test_private_network_never_collected():
    r = asyncio.run(collect(normalize("http://169.254.169.254/latest/meta-data/")))
    assert r[0]["status"] == "blocked"


def test_missing_keys_are_unknown(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)
    for p in (VirusTotal(), URLhaus()):
        r = asyncio.run(p.lookup(normalize("https://example.com")))
        assert r["malicious"] is None and r["status"] == "not configured"


def test_sensitive_url_not_sent(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "fixture")
    r = asyncio.run(VirusTotal().lookup(normalize("https://example.com/token")))
    assert r["status"] == "privacy blocked"


def test_tls_disabled(monkeypatch):
    monkeypatch.delenv("ENABLE_TLS", raising=False)
    assert tls(normalize("https://example.com"))["status"] == "disabled"
