import asyncio
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from .. import models, schemas, pipeline, detection
from ..database import get_db
from ..deps import get_current_user, require, client_ip
from ..audit import audit
from ..ws import manager
from ..config import get_settings

router = APIRouter(tags=["events"])
OPEN = Depends(get_current_user)


def _ev_dict(e: models.Event) -> dict:
    return {"id": e.id, "timestamp": e.timestamp, "source": e.source, "host": e.host,
            "source_ip": e.source_ip, "dest_ip": e.dest_ip, "protocol": e.protocol,
            "port": e.port, "username": e.username, "process": e.process,
            "event_type": e.event_type, "severity": e.severity,
            "correlation_id": e.correlation_id, "ioc_hits": e.ioc_hits,
            "is_synthetic": e.is_synthetic, "parse_error": e.parse_error}


@router.post("/events", status_code=201)
def ingest(data: schemas.EventIn, db: Session = Depends(get_db),
           user: models.User = Depends(get_current_user)):
    raw = {**data.raw, **data.model_dump(exclude={"raw"}), "source": data.source}
    ev = pipeline.ingest_event(db, raw)
    alerts = detection.run_detection(db, ev)
    out = {"event": _ev_dict(ev), "alerts_created": len(alerts)}
    try:
        asyncio.get_running_loop().create_task(manager.broadcast(
            {"type": "event", "event": _ev_dict(ev),
             "alert_count": len(alerts)}))
    except RuntimeError:
        pass
    return out


@router.get("/events")
def list_events(severity: str | None = None, source: str | None = None, host: str | None = None,
                event_type: str | None = None, search: str | None = None,
                synthetic: bool | None = None, limit: int = Query(100, le=500),
                offset: int = 0, db: Session = Depends(get_db), _: models.User = OPEN):
    q = db.query(models.Event).order_by(models.Event.timestamp.desc())
    if severity:
        q = q.filter(models.Event.severity == severity)
    if source:
        q = q.filter(models.Event.source == source)
    if host:
        q = q.filter(models.Event.host.ilike(f"%{host}%"))
    if event_type:
        q = q.filter(models.Event.event_type == event_type)
    if synthetic is not None:
        q = q.filter(models.Event.is_synthetic.is_(synthetic))
    if search:
        like = f"%{search}%"
        q = q.filter((models.Event.source_ip.ilike(like)) | (models.Event.username.ilike(like))
                     | (models.Event.process.ilike(like)) | (models.Event.host.ilike(like)))
    total = q.count()
    rows = q.offset(offset).limit(limit).all()
    return {"total": total, "events": [_ev_dict(e) for e in rows]}


@router.get("/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db), _: models.User = OPEN):
    e = db.get(models.Event, event_id)
    if not e:
        raise HTTPException(404, "Event not found")
    related = db.query(models.Event).filter(
        models.Event.correlation_id == e.correlation_id,
        models.Event.id != e.id).order_by(models.Event.timestamp.desc()).limit(25).all()
    incidents = db.query(models.Incident).join(models.IncidentEvent).filter(
        models.IncidentEvent.event_id == e.id).all()
    return {"event": {**_ev_dict(e), "raw": e.raw, "normalized": e.normalized},
            "related_events": [_ev_dict(r) for r in related],
            "related_incidents": [{"id": i.id, "title": i.title, "status": i.status,
                                   "severity": i.severity} for i in incidents]}


_DEMO_SCENARIOS = {
    "brute_force": lambda t: [{"timestamp": t - i * 30, "source": "demo-sensor", "host": "srv-auth-01",
                               "source_ip": "203.0.113.50", "username": "admin", "event_type": "auth_failure",
                               "is_synthetic": True, "message": "Failed SSH password auth"} for i in range(8)],
    "suspicious_login": lambda t: [
        {"timestamp": t - 3600, "source": "demo-sensor", "host": "wkstn-14", "source_ip": "198.51.100.9",
         "username": "j.okafor", "event_type": "auth_success", "is_synthetic": True, "message": "SSH login"},
        {"timestamp": t - 300, "source": "demo-sensor", "host": "wkstn-14", "source_ip": "203.0.113.77",
         "username": "j.okafor", "event_type": "auth_success", "is_synthetic": True, "message": "SSH login"}],
    "port_scan": lambda t: [{"timestamp": t - i * 4, "source": "demo-netflow", "host": "perimeter-fw",
                             "source_ip": "192.0.2.200", "dest_ip": "10.0.0.5", "event_type": "connection",
                             "port": 20 + i * 111, "protocol": "tcp", "is_synthetic": True} for i in range(14)],
    "ioc_match": lambda t: [{"timestamp": t, "source": "demo-sensor", "host": "wkstn-22",
                             "dest_ip": "185.220.101.4", "event_type": "connection", "port": 4444,
                             "protocol": "tcp", "process": "ncat", "is_synthetic": True,
                             "message": "outbound connection to known C2"}],
    "outbound_spike": lambda t: [{"timestamp": t - i * 2, "source": "demo-netflow", "host": "srv-db-02",
                                  "source_ip": "10.0.0.22", "dest_ip": "203.0.113.9", "event_type": "connection",
                                  "port": 8443, "protocol": "tcp", "is_synthetic": True} for i in range(240)],
}


@router.post("/demo/generate")
def generate_demo(scenario: str = "brute_force", db: Session = Depends(get_db),
                  user: models.User = Depends(require("analyst"))):
    if not get_settings().DEMO_MODE:
        raise HTTPException(403, "Demo mode is disabled")
    if scenario not in _DEMO_SCENARIOS:
        raise HTTPException(404, f"Unknown scenario. Available: {list(_DEMO_SCENARIOS)}")
    import time
    created = []
    for raw in _DEMO_SCENARIOS[scenario](time.time()):
        ev = pipeline.ingest_event(db, raw)
        detection.run_detection(db, ev)
        created.append(_ev_dict(ev))
    return {"scenario": scenario, "count": len(created), "synthetic": True, "events": created[:5]}


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db), _: models.User = OPEN):
    now = datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)

    def count(model, *filters):
        q = db.query(func.count(model.id))
        for f in filters:
            q = q.filter(f)
        return q.scalar() or 0

    events_1h = count(models.Event, models.Event.timestamp >= hour_ago)
    open_incidents = count(models.Incident, ~models.Incident.status.in_(["resolved", "closed"]))
    alerts = {sev: count(models.Alert, models.Alert.severity == sev, models.Alert.status == "open")
              for sev in ["critical", "high", "medium", "low", "info"]}
    timeline = [{"minute": (hour_ago + timedelta(minutes=m)).strftime("%H:%M"),
                 "events": count(models.Event, models.Event.timestamp >= hour_ago + timedelta(minutes=m),
                                 models.Event.timestamp < hour_ago + timedelta(minutes=m + 1))}
                for m in range(60)]
    top_rules = [{"rule": r.code, "name": r.name, "triggers": r.trigger_count}
                 for r in db.query(models.DetectionRule).order_by(
                     models.DetectionRule.trigger_count.desc()).limit(5)]
    assets = db.query(models.Asset).order_by(models.Asset.risk_score.desc()).limit(5).all()
    recent_incidents = db.query(models.Incident).order_by(
        models.Incident.created_at.desc()).limit(6).all()
    recent_actions = db.query(models.ResponseAction).order_by(
        models.ResponseAction.created_at.desc()).limit(6).all()
    ioc_hits = count(models.Event, models.Event.timestamp >= hour_ago,
                     models.Event.ioc_hits != [], models.Event.ioc_hits.isnot(None))
    threat_level = "critical" if alerts["critical"] else "high" if alerts["high"] else \
        "elevated" if (alerts["medium"] or ioc_hits) else "low"
    return {
        "events_per_second": round(events_1h / 3600, 2),
        "events_1h": events_1h,
        "open_incidents": open_incidents,
        "open_alerts": alerts,
        "hosts_monitored": db.query(func.count(models.Asset.id)).scalar() or 0,
        "sensors": count(models.Integration, models.Integration.enabled.is_(True)),
        "suspicious_ips": count(models.IOC, models.IOC.type == "ip", models.IOC.active.is_(True)),
        "detection_rate": round(count(models.Alert, models.Alert.created_at >= hour_ago) /
                                max(events_1h, 1), 4),
        "threat_level": threat_level,
        "timeline": timeline,
        "top_rules": top_rules,
        "affected_assets": [{"hostname": a.hostname, "risk": a.risk_score} for a in assets],
        "recent_incidents": [{"id": i.id, "title": i.title, "severity": i.severity,
                              "status": i.status, "created_at": i.created_at} for i in recent_incidents],
        "recent_actions": [{"id": a.id, "action_type": a.action_type, "target": a.target,
                            "status": a.status, "dry_run": a.dry_run} for a in recent_actions],
        "ai_summary": None,
    }
