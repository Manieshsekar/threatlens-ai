import asyncio, hashlib, hmac, io, json, os, secrets, time, uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal
from fastapi import FastAPI, HTTPException, Request, Response, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, func, text
from redis import Redis
from .database import (
    Base,
    connect,
    Domain,
    UrlEntity,
    Investigation,
    Feedback,
    Verification,
    Audit,
)
from .features import normalize, redact
from .engine import assess, load_model


def uid():
    return str(uuid.uuid4())


class ScanInput(BaseModel):
    url: str = Field(min_length=1, max_length=4096)
    mode: Literal["quick", "deep"] = "quick"


class Login(BaseModel):
    token: str = Field(min_length=20, max_length=300)


class Review(BaseModel):
    verdict: Literal["clean", "malicious", "unsure"]
    note: str = Field(min_length=10, max_length=2000)


class FeedbackInput(BaseModel):
    investigation_id: str
    category: Literal["false_positive", "false_negative", "unsure"]
    note: str = Field(default="", max_length=2000)


def create_app(database_url=None, testing=False):
    if not testing and database_url and not database_url.startswith("postgresql"):
        raise RuntimeError("Production requires PostgreSQL")
    if not testing and not os.getenv("DATABASE_URL", "postgresql").startswith(
        "postgresql"
    ):
        raise RuntimeError("Production requires PostgreSQL")
    engine, Session = connect(database_url)
    cache = (
        None
        if testing
        else Redis.from_url(
            os.getenv("REDIS_URL", "redis://redis:6379/0"), decode_responses=True
        )
    )
    keys = {
        r: os.getenv("API_" + r.upper() + "_KEY", "")
        for r in ("user", "analyst", "admin")
    }
    salt = os.getenv("URL_HASH_SECRET", "")
    if not testing and (
        any(len(k) < 32 for k in keys.values())
        or len(set(keys.values())) != 3
        or len(salt) < 32
    ):
        raise RuntimeError(
            "Generate distinct role keys and URL_HASH_SECRET using scripts/configure.py"
        )

    @asynccontextmanager
    async def lifespan(app):
        Base.metadata.create_all(engine)
        if cache:
            cache.ping()
        load_model()
        yield
        engine.dispose()

    app = FastAPI(
        title="ThreatLens AI",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    app.state.Session = Session

    @app.middleware("http")
    async def security_headers(req, call_next):
        # Cookie-authenticated writes must be same-origin; Bearer API clients are not cookie-authenticated.
        if (
            req.method not in ("GET", "HEAD", "OPTIONS")
            and req.cookies.get("tl_session")
            and not req.headers.get("authorization")
        ):
            origin = req.headers.get("origin")
            expected = os.getenv("PUBLIC_ORIGIN", "http://localhost:3000")
            if origin != expected:
                return Response("Origin check failed", status_code=403)
        if (
            req.url.path == "/api/v1/login"
            and req.headers.get("origin")
            and req.headers["origin"]
            != os.getenv("PUBLIC_ORIGIN", "http://localhost:3000")
        ):
            return Response("Origin check failed", status_code=403)
        length = req.headers.get("content-length")
        if length and (not length.isdigit() or int(length) > 20000):
            return Response("Request too large", status_code=413)
        response = await call_next(req)
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
            }
        )
        return response

    def role_for(token):
        for role, key in keys.items():
            if key and secrets.compare_digest(token, key):
                return role
        return None

    def auth(req: Request):
        token = req.headers.get("authorization", "").removeprefix(
            "Bearer "
        ) or req.cookies.get("tl_session", "")
        role = role_for(token)
        if not role:
            raise HTTPException(401, "Sign in with a configured access key.")
        if cache:
            bucket = (
                "rate:"
                + hashlib.sha256(token.encode()).hexdigest()
                + ":"
                + str(int(time.time()) // 60)
            )
            count = cache.eval(
                "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],61) end; return n",
                1,
                bucket,
            )
            if count > 60:
                raise HTTPException(429, "Request limit reached; retry in one minute.")
        return role

    def get_case(db, id, role):
        x = db.get(Investigation, id)
        if not x or (role == "user" and x.owner != role):
            raise HTTPException(404, "Investigation not found.")
        return x

    def pack(x):
        return dict(
            x.report,
            id=x.id,
            status=x.status,
            mode=x.mode,
            created_at=x.created_at.isoformat(),
        )

    @app.get("/api/v1/health")
    def health():
        try:
            with engine.connect() as c:
                c.execute(text("SELECT 1"))
            if cache:
                cache.ping()
            return {
                "status": "ok",
                "database": "postgresql"
                if engine.dialect.name == "postgresql"
                else "test database",
                "cache": "redis" if cache else "test mode",
            }
        except Exception:
            raise HTTPException(503, "A required service is unavailable.")

    @app.post("/api/v1/login")
    def login(body: Login, req: Request, response: Response):
        if cache:
            ident = hashlib.sha256(
                (req.client.host if req.client else "unknown").encode()
            ).hexdigest()
            key = f"login:{ident}:{int(time.time()) // 60}"
            n = cache.eval(
                "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],61) end; return n",
                1,
                key,
            )
            if n > 10:
                raise HTTPException(429, "Too many login attempts.")
        role = role_for(body.token)
        if not role:
            raise HTTPException(401, "Invalid access key.")
        response.set_cookie(
            "tl_session",
            body.token,
            httponly=True,
            secure=os.getenv("COOKIE_SECURE") == "1",
            samesite="strict",
            max_age=8 * 3600,
            path="/api/",
        )
        return {"role": role}

    @app.post("/api/v1/logout")
    def logout(response: Response):
        response.delete_cookie("tl_session", path="/api/")
        return {"ok": True}

    @app.get("/api/v1/system")
    def system(role=Depends(auth)):
        return {
            "mode": "full",
            "role": role,
            "model": load_model(),
            "database": "PostgreSQL",
            "queue": "Celery / Redis",
            "providers": {
                "VirusTotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
                "URLhaus": bool(os.getenv("URLHAUS_AUTH_KEY")),
                "TLS": os.getenv("ENABLE_TLS") == "1",
            },
            "features": ["scan", "history", "review", "feedback", "export"],
        }

    @app.post("/api/v1/scan")
    def scan(body: ScanInput, role=Depends(auth)):
        try:
            n = normalize(body.url)
        except ValueError as e:
            raise HTTPException(422, str(e))
        # Canonical input never enters logs, DB or task payloads.
        key = hmac.new(
            salt.encode(), n["canonical"].encode(), hashlib.sha256
        ).hexdigest()
        report = assess(n)
        with Session.begin() as db:
            from sqlalchemy.dialects.postgresql import insert as pg_insert
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            ins = pg_insert if engine.dialect.name == "postgresql" else sqlite_insert
            db.execute(ins(Domain).values(name=n["domain"]).on_conflict_do_nothing())
            db.execute(
                ins(UrlEntity)
                .values(key=key, domain=n["domain"], display=redact(n))
                .on_conflict_do_nothing()
            )
            previous = db.scalar(
                select(Verification)
                .join(Investigation, Verification.investigation_id == Investigation.id)
                .where(Investigation.url_key == key)
                .order_by(Verification.created_at.desc())
                .limit(1)
            )
            count = (
                db.scalar(
                    select(func.count())
                    .select_from(Investigation)
                    .where(Investigation.url_key == key)
                )
                or 0
            )
            report["reputation"] = {
                "status": "verified_" + previous.verdict
                if previous and previous.verdict != "unsure"
                else "unknown",
                "prior_scans": count,
                "source": "analyst" if previous else None,
            }
            if previous:
                report["reputation"]["verified_at"] = previous.created_at.isoformat()
            if previous and previous.verdict == "malicious":
                report["recommendation"] = (
                    "A previous analyst verification marked this exact URL malicious. Avoid interaction and review that evidence."
                )
            x = Investigation(
                id=uid(),
                url_key=key,
                owner=role,
                mode=body.mode,
                status="queued" if body.mode == "deep" else "complete",
                report=report,
            )
            db.add(x)
            db.flush()
            result = pack(x)
        if body.mode == "deep":
            from .worker import investigate

            safe_n = {
                **n,
                "canonical": n["canonical"]
                if n["path"] == "/" and not n["query"]
                else n["scheme"] + "://" + n["hostname"] + "/",
                "path": "[redacted]" if n["path"] != "/" else "/",
                "query": "[redacted]" if n["query"] else "",
            }
            try:
                investigate.delay(result["id"], safe_n)
            except Exception:
                with Session.begin() as db:
                    db.get(Investigation, result["id"]).status = "failed"
                raise HTTPException(
                    503, "Investigation saved but background queue is unavailable."
                )
        return result

    @app.get("/api/v1/scan/{id}")
    def get_scan(id: str, role=Depends(auth)):
        with Session() as db:
            return pack(get_case(db, id, role))

    @app.get("/api/v1/history")
    def history(q: str = "", limit: int = 50, role=Depends(auth)):
        with Session() as db:
            stmt = (
                select(Investigation)
                .order_by(Investigation.created_at.desc())
                .limit(max(1, min(limit, 200)))
            )
            if role == "user":
                stmt = stmt.where(Investigation.owner == role)
            if q:
                stmt = stmt.join(UrlEntity).where(
                    UrlEntity.domain.contains(q[:253], autoescape=True)
                )
            return [pack(x) for x in db.scalars(stmt)]

    @app.get("/api/v1/domain/{domain}")
    def domain_report(domain: str, role=Depends(auth)):
        with Session() as db:
            stmt = (
                select(Investigation)
                .join(UrlEntity)
                .where(UrlEntity.domain == domain)
                .order_by(Investigation.created_at.desc())
                .limit(100)
            )
            if role == "user":
                stmt = stmt.where(Investigation.owner == role)
            rows = list(db.scalars(stmt))
            return {"domain": domain, "investigations": [pack(x) for x in rows]}

    @app.post("/api/v1/feedback")
    def feedback(body: FeedbackInput, role=Depends(auth)):
        with Session.begin() as db:
            get_case(db, body.investigation_id, role)
            db.add(Feedback(id=uid(), owner=role, **body.model_dump()))
            db.add(
                Audit(
                    id=uid(),
                    actor=role,
                    action="feedback_submitted",
                    subject=body.investigation_id,
                )
            )
        return {
            "status": "received",
            "detail": "Feedback awaits review; it does not change model labels.",
        }

    @app.post("/api/v1/scan/{id}/verification")
    def verify(id: str, body: Review, role=Depends(auth)):
        if role not in ("analyst", "admin"):
            raise HTTPException(403, "Analyst role required.")
        with Session.begin() as db:
            x = get_case(db, id, role)
            if x.status != "complete":
                raise HTTPException(
                    409, "Wait for the investigation to complete before reviewing."
                )
            v = Verification(
                id=uid(), investigation_id=id, analyst=role, **body.model_dump()
            )
            db.add(v)
            report = {
                **x.report,
                "verification": {
                    **body.model_dump(),
                    "analyst": role,
                    "at": datetime.now(timezone.utc).isoformat(),
                },
            }
            # Review is case-scoped. Never modify original machine assessment or propagate a clean verdict to unrelated URLs.
            report["verification_conflict"] = (
                body.verdict == "clean" and x.report["risk_score"] >= 75
            )
            x.report = report
            db.add(
                Audit(id=uid(), actor=role, action="analyst_verification", subject=id)
            )
            db.flush()
            return pack(x)

    @app.get("/api/v1/audit")
    def audit(role=Depends(auth)):
        if role != "admin":
            raise HTTPException(403, "Administrator role required.")
        with Session() as db:
            return [
                {
                    "actor": x.actor,
                    "action": x.action,
                    "subject": x.subject,
                    "at": x.created_at.isoformat(),
                }
                for x in db.scalars(
                    select(Audit).order_by(Audit.created_at.desc()).limit(200)
                )
            ]

    @app.get("/api/v1/scan/{id}/report.pdf")
    def export_pdf(id: str, role=Depends(auth)):
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas

        with Session() as db:
            r = pack(get_case(db, id, role))
        import textwrap

        stream = io.BytesIO()
        c = canvas.Canvas(stream, pagesize=A4)
        y = 790
        lines = [
            "ThreatLens AI investigation",
            r["url"],
            r["created_at"],
            f"Assessment: {r['classification']} | Risk: {r['risk_score']}/100",
            "Evidence confidence: " + r["confidence"],
            r["recommendation"],
            "Model: " + r["model"]["version"],
            "The risk score is not a probability.",
        ] + [s["title"] + ": " + s["detail"] for s in r["signals"]]
        for line in lines:
            for part in textwrap.wrap(line, 90):
                if y < 60:
                    c.showPage()
                    y = 790
                c.setFont("Helvetica", 10)
                c.drawString(45, y, part)
                y -= 16
            y -= 8
        c.save()
        stream.seek(0)
        return StreamingResponse(
            stream,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="threatlens-{id}.pdf"'
            },
        )

    return app
