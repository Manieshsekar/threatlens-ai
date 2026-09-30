import os
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine,
    String,
    Text,
    ForeignKey,
    DateTime,
    Integer,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


J = JSON().with_variant(JSONB, "postgresql")


def now():
    return datetime.now(timezone.utc)


class Domain(Base):
    __tablename__ = "domains"
    name: Mapped[str] = mapped_column(String(253), primary_key=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class UrlEntity(Base):
    __tablename__ = "url_entities"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    domain: Mapped[str] = mapped_column(ForeignKey("domains.name"), index=True)
    display: Mapped[str] = mapped_column(Text)


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    url_key: Mapped[str] = mapped_column(ForeignKey("url_entities.key"), index=True)
    owner: Mapped[str] = mapped_column(String(100), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now, index=True
    )
    status: Mapped[str] = mapped_column(String(20), default="complete")
    mode: Mapped[str] = mapped_column(String(10))
    report: Mapped[dict] = mapped_column(J)


class Verification(Base):
    __tablename__ = "analyst_verifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id"), index=True
    )
    verdict: Mapped[str] = mapped_column(String(20))
    analyst: Mapped[str] = mapped_column(String(100))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Feedback(Base):
    __tablename__ = "user_feedback"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id"), index=True
    )
    owner: Mapped[str] = mapped_column(String(100))
    category: Mapped[str] = mapped_column(String(30))
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Audit(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(60))
    subject: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


def connect(url=None):
    url = url or os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg://threatlens:change-me@postgres:5432/threatlens",
    )
    engine = create_engine(
        url,
        pool_pre_ping=True,
        **(
            {"connect_args": {"check_same_thread": False}}
            if url.startswith("sqlite")
            else {}
        ),
    )
    return engine, sessionmaker(engine, expire_on_commit=False)
