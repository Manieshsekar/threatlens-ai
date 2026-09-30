"""Deterministic network-free feature extraction for training and inference."""

import ipaddress, math, re
from collections import Counter
from urllib.parse import urlsplit, urlunsplit, unquote
import tldextract

PSL = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
VERSION = "lexical-1.0"
WORDS = (
    "login",
    "signin",
    "verify",
    "account",
    "password",
    "secure",
    "update",
    "confirm",
    "wallet",
    "payment",
    "bank",
)
BRANDS = (
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
)
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly"}
NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "underscore_count",
    "slash_count",
    "digit_count",
    "letter_count",
    "digit_ratio",
    "letter_ratio",
    "entropy",
    "is_ip",
    "is_https",
    "nonstandard_port",
    "punycode",
    "percent_count",
    "parameter_count",
    "max_char_run",
    "suspicious_extension",
    "credential_words",
    "brand_match",
    "shortener",
    "redirect_parameter",
    "at_count",
    "equal_count",
    "question_count",
    "host_digit_ratio",
]


def normalize(raw):
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 4096:
        raise ValueError("Enter a URL between 1 and 4096 characters.")
    raw = raw.strip()
    if re.search(r"[\x00-\x20\x7f\\]", raw):
        raise ValueError(
            "Whitespace, control characters and backslashes are not accepted."
        )
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    p = urlsplit(raw)
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        raise ValueError("Only HTTP and HTTPS URLs with a hostname are supported.")
    if p.username is not None or p.password is not None:
        raise ValueError("URLs containing credentials are not accepted.")
    try:
        host = p.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = p.port
    except (ValueError, UnicodeError):
        raise ValueError("Invalid hostname or port.")
    if "%" in host or not host:
        raise ValueError("Encoded hosts and IPv6 zone identifiers are not accepted.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if not ip and (
        len(host) > 253
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
            for x in host.split(".")
        )
    ):
        raise ValueError("Invalid domain name.")
    if not ip and re.fullmatch(
        r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", host
    ):
        raise ValueError("Noncanonical numeric addresses are not accepted.")
    if port == 0:
        raise ValueError("Port zero is not supported.")
    hostport = "[" + host + "]" if ip and ip.version == 6 else host
    if port and port != (443 if p.scheme == "https" else 80):
        hostport += ":" + str(port)
    canonical = urlunsplit((p.scheme.lower(), hostport, p.path or "/", p.query, ""))
    ext = PSL(host)
    return {
        "canonical": canonical,
        "hostname": host,
        "domain": ext.top_domain_under_public_suffix or host,
        "scheme": p.scheme.lower(),
        "port": port,
        "path": p.path or "/",
        "query": p.query,
        "is_ip": bool(ip),
        "is_private": bool(ip and not ip.is_global)
        or host == "localhost"
        or host.endswith((".localhost", ".local", ".internal")),
        "subdomains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
    }


def extract(n):
    u = n["canonical"]
    h = n["hostname"]
    lower = unquote(u).lower()
    digits = sum(c.isdigit() for c in u)
    letters = sum(c.isalpha() for c in u)
    entropy = -sum((v / len(u)) * math.log2(v / len(u)) for v in Counter(u).values())
    vals = [
        len(u),
        len(h),
        len(n["path"]),
        len(n["query"]),
        n["subdomains"],
        u.count("."),
        u.count("-"),
        u.count("_"),
        u.count("/"),
        digits,
        letters,
        digits / len(u),
        letters / len(u),
        entropy,
        int(n["is_ip"]),
        int(n["scheme"] == "https"),
        int(n["port"] is not None and n["port"] not in (80, 443)),
        int("xn--" in h),
        u.count("%"),
        len(n["query"].split("&")) if n["query"] else 0,
        max((len(x.group(0)) for x in re.finditer(r"(.)\1*", u)), default=0),
        int(bool(re.search(r"\.(exe|scr|zip|apk|iso)(?:$|[?])", lower))),
        sum(lower.count(w) for w in WORDS),
        sum(b in h and n["domain"] != b + ".com" for b in BRANDS),
        int(n["domain"] in SHORTENERS),
        int(
            bool(
                re.search(
                    r"(?:^|&)(?:url|redirect|next|continue|return|dest)=",
                    n["query"],
                    re.I,
                )
            )
        ),
        u.count("@"),
        u.count("="),
        u.count("?"),
        sum(c.isdigit() for c in h) / len(h),
    ]
    return dict(zip(NAMES, vals))


def redact(n):
    p = urlsplit(n["canonical"])
    return urlunsplit(
        (
            p.scheme,
            p.netloc,
            "/[path redacted]" if p.path != "/" else "/",
            "[query redacted]" if p.query else "",
            "",
        )
    )


def signals(n, f):
    out = []

    def add(ok, title, detail, weight):
        if ok:
            out.append(
                {
                    "title": title,
                    "detail": detail,
                    "weight": weight,
                    "source": "lexical rule",
                }
            )

    add(
        f["brand_match"],
        "Brand reference outside its standard domain",
        "A brand name appears in this hostname. This may be imitation or a legitimate reference.",
        25,
    )
    add(
        f["is_ip"],
        "IP address used as host",
        "An IP literal replaces a domain name; legitimate infrastructure may do this too.",
        15,
    )
    add(
        f["punycode"],
        "Internationalized domain",
        "Punycode may be legitimate. Inspect the displayed name for imitation.",
        10,
    )
    add(
        f["credential_words"] >= 2,
        "Multiple account-related terms",
        "Several login, payment or security words occur in the URL.",
        15,
    )
    add(
        f["subdomain_count"] >= 3,
        "Deeply nested hostname",
        "Many subdomains can obscure the registrable domain.",
        10,
    )
    add(
        f["nonstandard_port"],
        "Unusual web port",
        "The URL uses a port other than 80 or 443.",
        5,
    )
    add(
        not f["is_https"],
        "Unencrypted URL scheme",
        "HTTP does not protect traffic in transit; this alone does not establish phishing.",
        10,
    )
    add(
        f["url_length"] > 160,
        "Long URL",
        "Long URLs can hide destinations; legitimate tracking links may also be long.",
        5,
    )
    add(
        f["redirect_parameter"],
        "Redirect parameter",
        "A destination-like parameter is present. No redirect was followed.",
        5,
    )
    add(
        f["suspicious_extension"],
        "Download-like path",
        "The path suggests an executable or archive.",
        15,
    )
    add(
        n["is_private"],
        "Nonpublic destination",
        "Lexical analysis is allowed; network inspection is blocked.",
        0,
    )
    return out
