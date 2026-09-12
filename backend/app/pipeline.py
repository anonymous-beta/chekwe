"""Ingestion → Parsing → Normalization → Enrichment → Correlation."""
import hashlib
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import or_
from . import models

FIELD_MAP = {
    "src_ip": "source_ip", "sourceip": "source_ip", "src": "source_ip",
    "dst_ip": "dest_ip", "dest": "dest_ip", "destination_ip": "dest_ip",
    "user": "username", "user_name": "username", "account": "username",
    "proc": "process", "process_name": "process", "exe": "process",
    "msg": "message", "message": "message",
}
KNOWN_FIELDS = {"timestamp", "source", "host", "source_ip", "dest_ip", "protocol", "port",
                "username", "process", "event_type", "severity", "is_synthetic"}


def _parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):  # epoch seconds
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    raise ValueError(f"unparseable timestamp: {value!r}")


def normalize(raw: dict) -> tuple[dict, str]:
    """Return (normalized, parse_error). Malformed fields never discard the event."""
    normalized: dict = {}
    error = ""
    try:
        normalized["timestamp"] = _parse_ts(raw.get("timestamp") or raw.get("time") or raw.get("@timestamp"))
    except ValueError as e:
        normalized["timestamp"] = datetime.now(timezone.utc)
        error = str(e)
    for src_key, canon in FIELD_MAP.items():
        if src_key in raw and canon not in raw:
            raw[canon] = raw[src_key]
    for f in KNOWN_FIELDS - {"timestamp"}:
        normalized[f] = raw.get(f, "" if f != "port" else None)
    try:
        if normalized["port"] not in (None, ""):
            normalized["port"] = int(normalized["port"])
    except (TypeError, ValueError):
        error = f"invalid port: {normalized['port']!r}"
        normalized["port"] = None
    normalized["message"] = raw.get("message", "")
    normalized["is_synthetic"] = bool(raw.get("is_synthetic", False))
    return normalized, error


def correlation_key(n: dict) -> str:
    basis = n.get("source_ip") or n.get("username") or n.get("host") or "unknown"
    return hashlib.sha256(f"{basis}".encode()).hexdigest()[:16]


def enrich(db: Session, n: dict) -> list[dict]:
    """IOC enrichment: match IPs/domains/hashes/process-names against the IOC DB."""
    hits = []
    candidates = []
    for f in ("source_ip", "dest_ip", "host", "process", "username"):
        v = (n.get(f) or "").strip()
        if v:
            candidates.append((f, v))
    for f, v in candidates:
        ioc = db.query(models.IOC).filter(models.IOC.value == v, models.IOC.active.is_(True)).first()
        if ioc:
            hits.append({"field": f, "value": v, "ioc_id": ioc.id, "ioc_type": ioc.type,
                         "confidence": ioc.confidence, "source": ioc.source})
            ioc.last_seen = datetime.now(timezone.utc)
    return hits


def upsert_asset(db: Session, n: dict) -> models.Asset | None:
    host = n.get("host") or ""
    ip = n.get("source_ip") or n.get("dest_ip") or ""
    if not host and not ip:
        return None
    asset = db.query(models.Asset).filter(
        or_(models.Asset.hostname == host, models.Asset.ip == ip)).first() if (host or ip) else None
    if not asset:
        asset = models.Asset(hostname=host or ip, ip=ip)
        db.add(asset)
    if host:
        asset.hostname = host
    if ip:
        asset.ip = ip
    asset.last_seen = datetime.now(timezone.utc)
    if n.get("is_synthetic"):
        asset.tags = {**asset.tags, "demo": True}
    db.flush()
    return asset


def ingest_event(db: Session, raw: dict) -> models.Event:
    """Full pipeline entry point. Never silently discards input."""
    if not isinstance(raw, dict):
        raw = {"message": str(raw), "event_type": "malformed"}
    normalized, error = normalize(raw)
    hits = enrich(db, normalized)
    n = models.Event(
        timestamp=normalized["timestamp"],
        source=str(normalized.get("source") or "unknown"),
        host=str(normalized.get("host") or ""),
        source_ip=str(normalized.get("source_ip") or ""),
        dest_ip=str(normalized.get("dest_ip") or ""),
        protocol=str(normalized.get("protocol") or ""),
        port=normalized.get("port"),
        username=str(normalized.get("username") or ""),
        process=str(normalized.get("process") or ""),
        event_type=str(normalized.get("event_type") or "unknown"),
        severity=str(normalized.get("severity") or "info"),
        correlation_id=correlation_key(normalized),
        ioc_hits=hits,
        raw=raw,
        normalized=normalized,
        is_synthetic=bool(normalized.get("is_synthetic")),
        parse_error=error,
    )
    upsert_asset(db, normalized)
    db.add(n)
    db.commit()
    db.refresh(n)
    return n
