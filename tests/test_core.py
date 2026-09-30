import os, sys, json, math
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.features import normalize, extract, redact, NAMES
from app.engine import assess


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "javascript://alert(1)",
        "ftp://example.com",
        "https://user:secret@example.com",
        "http://127.1",
        "http://2130706433",
        "http://0x7f000001",
        "https://a..com",
        "https://example.com:99999",
        "https://example.com:0",
        "https://example.com\\@evil.com",
        "https://%31%32%37.0.0.1",
        "https://[fe80::1%25eth0]/",
    ],
)
def test_reject(raw):
    with pytest.raises(ValueError):
        normalize(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "http://127.0.0.1",
        "http://10.0.0.1",
        "http://169.254.169.254",
        "https://[::1]",
        "https://[::ffff:127.0.0.1]",
        "https://localhost",
        "https://office.local",
    ],
)
def test_nonpublic(raw):
    assert normalize(raw)["is_private"]


def test_normalize():
    n = normalize("HTTPS://Example.COM:443/login?a=1#fragment")
    assert n["canonical"] == "https://example.com/login?a=1"
    assert normalize("https://a.b.example.co.uk/")["domain"] == "example.co.uk"
    assert normalize("https://user.github.io/")["domain"] == "user.github.io"
    assert normalize("https://bücher.de")["hostname"] == "xn--bcher-kva.de"


def test_privacy():
    n = normalize("https://example.com/private-secret?token=secret#x")
    r = assess(n)
    assert "private-secret" not in json.dumps(r) and "token=secret" not in json.dumps(r)
    assert "redacted" in r["url"]


def test_features_and_model():
    r = assess(normalize("https://example.com/"))
    assert set(r["features"]) == set(NAMES)
    assert all(math.isfinite(v) for v in r["features"].values())
    assert 0 <= r["model"]["probability"] <= 1
    assert r["confidence"] == "limited"


def test_provider_hit_does_not_lower_risk():
    r = assess(
        normalize("https://example.com"),
        [{"provider": "test", "status": "ok", "malicious": True}],
    )
    assert r["risk_score"] >= 95


@pytest.fixture
def client(tmp_path, monkeypatch):
    for role in ("USER", "ANALYST", "ADMIN"):
        monkeypatch.setenv("API_" + role + "_KEY", role.lower() + "-" + "x" * 40)
    monkeypatch.setenv("URL_HASH_SECRET", "s" * 64)
    from app.main import create_app
    from fastapi.testclient import TestClient

    with TestClient(
        create_app("sqlite:///" + str(tmp_path / "test.db"), testing=True)
    ) as c:
        yield c


def hdr(role="user"):
    return {"Authorization": "Bearer " + role + "-" + "x" * 40}


def test_scan_history_privacy_export(client, monkeypatch):
    assert (
        client.post("/api/v1/scan", json={"url": "https://example.com"}).status_code
        == 401
    )
    response = client.post(
        "/api/v1/scan",
        json={"url": "https://example.com/token123?password=private"},
        headers=hdr(),
    )
    assert response.status_code == 200
    r = response.json()
    assert "token123" not in json.dumps(r)
    id = r["id"]
    assert client.get("/api/v1/scan/" + id, headers=hdr()).status_code == 200
    assert len(client.get("/api/v1/history", headers=hdr()).json()) == 1
    assert client.get(
        "/api/v1/scan/" + id + "/report.pdf", headers=hdr()
    ).content.startswith(b"%PDF")

    from app.worker import investigate

    queued = []
    monkeypatch.setattr(
        investigate, "delay", lambda job_id, normalized: queued.append(normalized)
    )
    result = client.post(
        "/api/v1/scan",
        json={"url": "https://example.com:8443/", "mode": "deep"},
        headers=hdr(),
    )
    assert result.status_code == 200
    assert queued[-1]["canonical"] == "https://example.com:8443/"
    result = client.post(
        "/api/v1/scan",
        json={
            "url": "https://example.com/private-secret?token=private-secret",
            "mode": "deep",
        },
        headers=hdr(),
    )
    assert result.status_code == 200
    assert "private-secret" not in json.dumps(queued[-1])


def test_roles_feedback_and_audit(client):
    r = client.post(
        "/api/v1/scan", json={"url": "https://example.com"}, headers=hdr()
    ).json()
    id = r["id"]
    body = {"verdict": "malicious", "note": "Verified using independent evidence."}
    assert (
        client.post(
            "/api/v1/scan/" + id + "/verification", json=body, headers=hdr()
        ).status_code
        == 403
    )
    v = client.post(
        "/api/v1/scan/" + id + "/verification", json=body, headers=hdr("analyst")
    )
    assert v.status_code == 200
    assert v.json()["model"] == r["model"]
    assert v.json()["verification"]["verdict"] == "malicious"
    assert (
        client.post(
            "/api/v1/feedback",
            json={"investigation_id": id, "category": "false_positive"},
            headers=hdr(),
        ).status_code
        == 200
    )
    assert client.get("/api/v1/audit", headers=hdr()).status_code == 403
    assert len(client.get("/api/v1/audit", headers=hdr("admin")).json()) == 2


def test_cookie_origin_and_isolation(client):
    r = client.post(
        "/api/v1/scan", json={"url": "https://example.com"}, headers=hdr("admin")
    ).json()
    assert client.get("/api/v1/scan/" + r["id"], headers=hdr()).status_code == 404
    assert (
        client.post("/api/v1/login", json={"token": "user-" + "x" * 40}).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/scan",
            json={"url": "https://example.com"},
            headers={"Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/scan",
            json={"url": "https://example.com"},
            headers={"Origin": "http://localhost:3000"},
        ).status_code
        == 200
    )
