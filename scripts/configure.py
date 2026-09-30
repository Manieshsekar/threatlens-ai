"""Create local secrets once; never commit .env."""

from pathlib import Path
import secrets

p = Path(".env")
if p.exists():
    raise SystemExit(".env already exists. It was preserved.")
password = secrets.token_hex(24)
values = {
    "POSTGRES_PASSWORD": password,
    "DATABASE_URL": f"postgresql+psycopg://threatlens:{password}@postgres:5432/threatlens",
    "REDIS_URL": "redis://redis:6379/0",
    "URL_HASH_SECRET": secrets.token_hex(32),
    "API_USER_KEY": secrets.token_urlsafe(32),
    "API_ANALYST_KEY": secrets.token_urlsafe(32),
    "API_ADMIN_KEY": secrets.token_urlsafe(32),
    "PUBLIC_ORIGIN": "http://localhost:3000",
    "COOKIE_SECURE": "0",
    "ENABLE_TLS": "0",
    "VIRUSTOTAL_API_KEY": "",
    "URLHAUS_AUTH_KEY": "",
}
p.write_text("\n".join(f"{k}={v}" for k, v in values.items()) + "\n")
p.chmod(0o600)
print(
    "Created .env. Open it locally to retrieve your access keys. Do not share or commit it."
)
