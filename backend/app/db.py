"""
SQLAlchemy models. Schema matches 07-DATA-MODEL-AND-MEMORY.md and
10-NETWORK-TUNNEL-ARCHITECTURE.md's network_routes extension, adapted to
run on SQLite-by-default (per config.py) while remaining Postgres-ready.
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import (
    create_engine, String, Integer, Boolean, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
)

from .config import settings


class Base(DeclarativeBase):
    pass


def now() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    operator = "operator"
    admin = "admin"


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default=Role.operator.value)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class NetworkRoute(Base):
    """A tunnel/pivot definition. See 10-NETWORK-TUNNEL-ARCHITECTURE.md."""
    __tablename__ = "network_routes"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    route_type: Mapped[str] = mapped_column(String(32), default="ssh_local_forward")
    pivot_host: Mapped[str] = mapped_column(String(255))
    pivot_port: Mapped[int] = mapped_column(Integer, default=22)
    pivot_username: Mapped[str] = mapped_column(String(128))
    # Encrypted at rest by the app's Fernet key (see security.py encrypt_secret).
    credential_encrypted: Mapped[str] = mapped_column(Text)
    credential_kind: Mapped[str] = mapped_column(String(32), default="ssh_key")
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class AuthorizedNetwork(Base):
    """Explicit allow-list of CIDRs this instance may ever connect to.
    This is the authoritative scope control described in
    05-SECURITY-ARCHITECTURE.md §1 — not a UI label."""
    __tablename__ = "authorized_networks"
    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    route_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_routes.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    ip_or_hostname: Mapped[str] = mapped_column(String(255))
    resolved_ip: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(Integer, default=9100)
    hostname: Mapped[str] = mapped_column(String(255), default="")
    model: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(16), default="unknown")
    source: Mapped[str] = mapped_column(String(32), default="manual")
    device_type: Mapped[str] = mapped_column(String(32), default="printer")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    added_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    adapter_id: Mapped[str] = mapped_column(String(64))
    operation_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default="queued")
    is_state_changing: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    route_id: Mapped[int | None] = mapped_column(ForeignKey("network_routes.id"), nullable=True)
    requested_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    params_json: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Result(Base):
    __tablename__ = "results"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"))
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    adapter_id: Mapped[str] = mapped_column(String(64))
    operation_id: Mapped[str] = mapped_column(String(64))
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=now)
    status: Mapped[str] = mapped_column(String(16))
    severity: Mapped[str] = mapped_column(String(16), default="info")
    summary: Mapped[str] = mapped_column(Text, default="")
    # Capped at write time by the adapter layer — see 07-DATA-MODEL-AND-MEMORY.md §4.
    evidence_json: Mapped[dict] = mapped_column(JSON, default=dict)
    remediation: Mapped[str] = mapped_column(Text, default="")
    error_detail: Mapped[str] = mapped_column(Text, default="")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(128))
    target_device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id"), nullable=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id"), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=now)
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    detail: Mapped[str] = mapped_column(Text, default="")


engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db() -> None:
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
