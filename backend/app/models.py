from datetime import datetime, timezone
from sqlalchemy import (String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), default="")
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="viewer")  # admin|analyst|viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(128), index=True)
    ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    os: Mapped[str] = mapped_column(String(128), default="unknown")
    status: Mapped[str] = mapped_column(String(32), default="active")  # active|inactive
    agent_status: Mapped[str] = mapped_column(String(32), default="none")  # connected|stale|none
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    source: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    host: Mapped[str] = mapped_column(String(128), default="", index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    dest_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    protocol: Mapped[str] = mapped_column(String(16), default="")
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="", index=True)
    process: Mapped[str] = mapped_column(String(256), default="")
    event_type: Mapped[str] = mapped_column(String(64), default="unknown", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="info")
    correlation_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    ioc_hits: Mapped[list] = mapped_column(JSON, default=list)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    normalized: Mapped[dict] = mapped_column(JSON, default=dict)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    parse_error: Mapped[str] = mapped_column(String(512), default="")


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    threshold: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    mitre: Mapped[dict] = mapped_column(JSON, default=dict)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16), index=True)  # critical|high|medium|low|info
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)  # open|acknowledged|resolved
    rule_code: Mapped[str] = mapped_column(String(64), default="", index=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    mitre: Mapped[dict] = mapped_column(JSON, default=dict)
    recommended_response: Mapped[str] = mapped_column(Text, default="")
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    # new|triaged|investigating|contained|remediating|resolved|closed
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    ai_analysis: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")
    events: Mapped[list["Event"]] = relationship(secondary="incident_events")


class IncidentEvent(Base):
    __tablename__ = "incident_events"
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), primary_key=True)


class IOC(Base):
    __tablename__ = "iocs"
    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str] = mapped_column(String(32), index=True)  # ip|domain|url|hash|cve
    value: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    source: Mapped[str] = mapped_column(String(128), default="manual")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class ThreatIntelRecord(Base):
    __tablename__ = "threat_intel"
    id: Mapped[int] = mapped_column(primary_key=True)
    feed: Mapped[str] = mapped_column(String(128), index=True)
    type: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(512), index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("feed", "value", name="uq_feed_value"),)


class ResponsePolicy(Base):
    __tablename__ = "response_policies"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    action_type: Mapped[str] = mapped_column(String(64), index=True)
    # block_ip|blocklist_ioc|lock_account|quarantine_file|terminate_process|isolate_host
    mode: Mapped[str] = mapped_column(String(16), default="approval")  # automatic|manual|approval
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    config: Mapped[dict] = mapped_column(JSON, default=dict)


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    policy_id: Mapped[int | None] = mapped_column(ForeignKey("response_policies.id"), nullable=True)
    action_type: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(512))
    reason: Mapped[str] = mapped_column(Text, default="")
    alert_id: Mapped[int | None] = mapped_column(ForeignKey("alerts.id"), nullable=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    # pending|approved|rejected|executed|failed|dry_run|unavailable
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_by: Mapped[str] = mapped_column(String(64), default="system")
    executed_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AIProviderConfig(Base):
    __tablename__ = "ai_provider"
    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(32), default="openai")  # openai|anthropic|google|custom
    endpoint: Mapped[str] = mapped_column(String(512), default="")
    api_key_enc: Mapped[str] = mapped_column(String(1024), default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    temperature: Mapped[float] = mapped_column(Float, default=0.2)
    max_tokens: Mapped[int] = mapped_column(Integer, default=1200)
    allow_auto_response: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Integration(Base):
    __tablename__ = "integrations"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    type: Mapped[str] = mapped_column(String(64))  # webhook|firewall|edr|identity|email|blocklist
    endpoint: Mapped[str] = mapped_column(String(512), default="")
    secret_enc: Mapped[str] = mapped_column(String(1024), default="")
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_status: Mapped[str] = mapped_column(String(32), default="not_configured")
    last_checked: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(256), default="")
    result: Mapped[str] = mapped_column(String(32), default="success")
    ip: Mapped[str] = mapped_column(String(64), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(256))
    message: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


Alert.incident = relationship("Incident", back_populates="alerts")
