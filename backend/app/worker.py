import asyncio, os, json
from celery import Celery
from redis import Redis
from .database import connect, Investigation
from .intelligence import collect

celery = Celery("threatlens", broker=os.getenv("REDIS_URL", "redis://redis:6379/0"))
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_soft_time_limit=40,
    task_time_limit=50,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
)


@celery.task(name="threatlens.investigate")
def investigate(id, n):
    engine, Session = connect()
    cache = Redis.from_url(
        os.getenv("REDIS_URL", "redis://redis:6379/0"), decode_responses=True
    )
    try:
        with Session.begin() as db:
            x = db.get(Investigation, id)
            if not x or x.status == "complete":
                return
            x.status = "running"
        key = (
            "intel:v1:"
            + n["scheme"]
            + ":"
            + n["hostname"]
            + (":" + str(n.get("port")))
            + (":root" if n["path"] == "/" and not n["query"] else ":redacted")
        )
        cached = cache.get(key)
        observations = json.loads(cached) if cached else asyncio.run(collect(n))
        # Cache stores origin-level observations only. Unavailability has a short TTL.
        if not cached:
            cache.setex(key, 60, json.dumps(observations))
        with Session.begin() as db:
            x = db.get(Investigation, id)
            r = dict(x.report)
            r["observations"] = observations
            if any(
                o.get("malicious") is True and o.get("status") == "ok"
                for o in observations
            ):
                r.update(
                    risk_score=max(r["risk_score"], 95),
                    classification="high risk",
                    confidence="corroborated",
                    recommendation="Avoid entering credentials or downloading files; investigate the provider evidence.",
                )
            r["intel_cache_hit"] = bool(cached)
            x.report = r
            x.status = "complete"
    except Exception:
        with Session.begin() as db:
            x = db.get(Investigation, id)
            if x:
                x.status = "failed"
        raise
    finally:
        engine.dispose()
