"""Bounded collectors. No webpage fetching or user-controlled HTTP endpoint."""

import asyncio, base64, hashlib, ipaddress, os, socket, ssl
from datetime import datetime, timezone
import httpx
import dns.resolver


def unavailable(provider, reason, status="unavailable"):
    return {
        "provider": provider,
        "status": status,
        "detail": reason,
        "malicious": None,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


async def fixed_json(client, url, **kwargs):
    async with client.stream("GET", url, **kwargs) as r:
        if r.status_code != 200:
            return None, r.status_code
        b = bytearray()
        async for chunk in r.aiter_bytes():
            b.extend(chunk)
            if len(b) > 1_000_000:
                raise ValueError("Provider response exceeds size limit")
        import json

        return json.loads(b), r.status_code


class ThreatIntelProvider:
    name = "provider"

    async def lookup(self, n):
        raise NotImplementedError


class VirusTotal(ThreatIntelProvider):
    name = "VirusTotal"

    async def lookup(self, n):
        key = os.getenv("VIRUSTOTAL_API_KEY")
        if not key:
            return unavailable(
                self.name, "API key is not configured.", "not configured"
            )
        if n["path"] != "/" or n["query"]:
            return unavailable(
                self.name,
                "Full URL sharing is disabled; this URL contains a path or query.",
                "privacy blocked",
            )
        uid = base64.urlsafe_b64encode(n["canonical"].encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as c:
            data, code = await fixed_json(
                c,
                "https://www.virustotal.com/api/v3/urls/" + uid,
                headers={"x-apikey": key},
            )
        if code != 200:
            return unavailable(
                self.name,
                "No report available."
                if code == 404
                else f"Provider returned HTTP {code}.",
            )
        stats = (
            data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        )
        return {
            "provider": self.name,
            "status": "ok",
            "malicious": stats.get("malicious", 0) > 0,
            "counts": stats,
            "detail": "Existing report lookup only; no URL submission.",
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }


class URLhaus(ThreatIntelProvider):
    name = "URLhaus"

    async def lookup(self, n):
        key = os.getenv("URLHAUS_AUTH_KEY")
        if not key:
            return unavailable(
                self.name, "Auth key is not configured.", "not configured"
            )
        # Domain-only query avoids disclosing URL tokens. A host hit is not an exact URL verdict.
        async with httpx.AsyncClient(timeout=8, follow_redirects=False) as c:
            r = await c.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                headers={"Auth-Key": key},
                data={"host": n["hostname"]},
            )
            if len(r.content) > 1_000_000:
                raise ValueError("Oversized response")
            if r.status_code != 200:
                return unavailable(
                    self.name, f"Provider returned HTTP {r.status_code}."
                )
            d = r.json()
        return {
            "provider": self.name,
            "status": "ok"
            if d.get("query_status") in ("ok", "no_results")
            else "unavailable",
            "malicious": None,
            "host_listed": d.get("query_status") == "ok",
            "url_count": d.get("url_count", 0),
            "detail": "Host-level malware observation, not proof this URL is malicious.",
            "observed_at": datetime.now(timezone.utc).isoformat(),
        }


def dns_lookup(n):
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2
    resolver.timeout = 1
    for kind in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        try:
            a = resolver.resolve(n["hostname"], kind)
            records[kind] = {
                "ttl": a.rrset.ttl,
                "values": [x.to_text()[:500] for x in list(a)[:20]],
            }
        except Exception:
            records[kind] = {"values": [], "status": "no answer or unavailable"}
    return {
        "provider": "DNS",
        "status": "ok"
        if any(v.get("values") for v in records.values())
        else "unavailable",
        "malicious": None,
        "records": records,
        "detail": "Missing records do not prove maliciousness. DNSSEC validation is not performed.",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


async def rdap(n):
    # Explicit registry mapping avoids following arbitrary referral URLs.
    domain = n["domain"]
    tld = domain.rsplit(".", 1)[-1]
    base = {
        "com": "https://rdap.verisign.com/com/v1/domain/",
        "net": "https://rdap.verisign.com/net/v1/domain/",
    }.get(tld)
    if not base:
        return unavailable(
            "RDAP",
            "This registry is not enabled in the initial allowlist.",
            "unsupported registry",
        )
    async with httpx.AsyncClient(timeout=8, follow_redirects=False) as c:
        d, code = await fixed_json(c, base + domain)
    if code != 200:
        return unavailable("RDAP", f"Registry returned HTTP {code}.")
    events = d.get("events", [])
    created = next(
        (e.get("eventDate") for e in events if e.get("eventAction") == "registration"),
        None,
    )
    age = None
    if created:
        try:
            age = max(
                0,
                (
                    datetime.now(timezone.utc)
                    - datetime.fromisoformat(created.replace("Z", "+00:00"))
                ).days,
            )
        except ValueError:
            pass
    return {
        "provider": "RDAP",
        "status": "ok",
        "malicious": None,
        "created_at": created,
        "age_days": age,
        "expires_at": next(
            (
                e.get("eventDate")
                for e in events
                if e.get("eventAction") == "expiration"
            ),
            None,
        ),
        "nameservers": [x.get("ldhName") for x in d.get("nameservers", [])],
        "detail": "Registry metadata can be incomplete; registration age is not a verdict.",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


def tls(n):
    if os.getenv("ENABLE_TLS") != "1":
        return unavailable("TLS", "Direct TLS inspection is disabled.", "disabled")
    if n["scheme"] != "https" or n["port"] not in (None, 443):
        return unavailable(
            "TLS", "Only HTTPS on port 443 can be inspected.", "unsupported"
        )
    addresses = {
        x[4][0] for x in socket.getaddrinfo(n["hostname"], 443, type=socket.SOCK_STREAM)
    }
    if not addresses or any(not ipaddress.ip_address(x).is_global for x in addresses):
        return unavailable("TLS", "Nonpublic or mixed DNS answer blocked.", "blocked")
    ip = sorted(addresses)[0]
    # Connect to the validated literal IP, never resolve the hostname a second time.
    with socket.create_connection((ip, 443), timeout=4) as s:
        with ssl.create_default_context().wrap_socket(
            s, server_hostname=n["hostname"]
        ) as conn:
            cert = conn.getpeercert()
            fingerprint = hashlib.sha256(conn.getpeercert(binary_form=True)).hexdigest()
    return {
        "provider": "TLS",
        "status": "ok",
        "malicious": None,
        "valid_chain_and_hostname": True,
        "issuer": str(cert.get("issuer")),
        "expires_at": cert.get("notAfter"),
        "sans": cert.get("subjectAltName", [])[:30],
        "sha256": fingerprint,
        "detail": "A valid certificate protects transport; it does not prove legitimacy.",
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }


async def collect(n):
    if n["is_private"] or n["is_ip"] or "." not in n["hostname"]:
        return [
            unavailable(
                "Network inspection",
                "Nonpublic or literal-address destination is blocked.",
                "blocked",
            )
        ]

    async def guarded(name, call):
        try:
            return await asyncio.wait_for(call, timeout=15)
        except Exception as e:
            return unavailable(name, "Lookup failed: " + type(e).__name__)

    return await asyncio.gather(
        guarded("DNS", asyncio.to_thread(dns_lookup, n)),
        guarded("RDAP", rdap(n)),
        guarded("TLS", asyncio.to_thread(tls, n)),
        guarded("VirusTotal", VirusTotal().lookup(n)),
        guarded("URLhaus", URLhaus().lookup(n)),
    )
