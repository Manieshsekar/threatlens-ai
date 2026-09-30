"""Run after Docker Compose starts. Reads the local user key without printing it."""

import json, urllib.request
from pathlib import Path

values = dict(
    line.split("=", 1)
    for line in Path(".env").read_text().splitlines()
    if "=" in line and not line.startswith("#")
)


def call(path, data=None):
    req = urllib.request.Request(
        "http://localhost:3000/api/v1/" + path,
        data=json.dumps(data).encode() if data else None,
        headers={
            "Authorization": "Bearer " + values["API_USER_KEY"],
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


assert call("health")["status"] == "ok"
r = call("scan", {"url": "https://example.com", "mode": "quick"})
assert r["model"]["version"] == "phiusiil-lr-v1"
assert call("scan/" + r["id"])["id"] == r["id"]
assert any(x["id"] == r["id"] for x in call("history"))
print(
    "PASS: gateway, API, PostgreSQL, Redis health, inference, and persistent history."
)
