from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from .. import models, schemas
from ..database import get_db
from ..deps import get_current_user, require, client_ip
from ..audit import audit

router = APIRouter(tags=["security"])
OPEN = Depends(get_current_user)
INCIDENT_FLOW = ["new", "triaged", "investigating", "contained", "remediating", "resolved", "closed"]


def _alert_dict(a: models.Alert) -> dict:
    return {"id": a.id, "title": a.title, "severity": a.severity, "confidence": a.confidence,
            "status": a.status, "rule_code": a.rule_code, "reason": a.reason,
            "evidence": a.evidence, "mitre": a.mitre,
            "recommended_response": a.recommended_response, "asset_id": a.asset_id,
            "incident_id": a.incident_id, "created_at": a.created_at}


@router.get("/alerts")
def list_alerts(status: str | None = None, severity: str | None = None,
                db: Session = Depends(get_db), _: models.User = OPEN):
    q = db.query(models.Alert).order_by(models.Alert.created_at.desc())
    if status:
        q = q.filter(models.Alert.status == status)
    if severity:
        q = q.filter(models.Alert.severity == severity)
    return [_alert_dict(a) for a in q.limit(300).all()]


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db), _: models.User = OPEN):
    a = db.get(models.Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    ev_id = (a.evidence or {}).get("event_id")
    event = db.get(models.Event, ev_id) if ev_id else None
    return {"alert": _alert_dict(a),
            "event": {"id": event.id, "timestamp": event.timestamp, "source_ip": event.source_ip,
                      "host": event.host, "username": event.username, "raw": event.raw,
                      "normalized": event.normalized, "is_synthetic": event.is_synthetic}
            if event else None}


@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, payload: dict, db: Session = Depends(get_db),
                 user: models.User = Depends(require("analyst")), request: Request = None):
    a = db.get(models.Alert, alert_id)
    if not a:
        raise HTTPException(404, "Alert not found")
    new_status = payload.get("status")
    if new_status not in ("open", "acknowledged", "resolved"):
        raise HTTPException(422, "status must be open|acknowledged|resolved")
    a.status = new_status
    db.commit()
    audit.audit(db, user.username, "alert.update", f"alert:{a.id}", detail=payload,
                ip=client_ip(request) if request else "")
    return _alert_dict(a)


def _incident_dict(i: models.Incident, db: Session) -> dict:
    return {"id": i.id, "title": i.title, "severity": i.severity, "confidence": i.confidence,
            "status": i.status, "asset_id": i.asset_id, "summary": i.summary,
            "ai_analysis": i.ai_analysis, "created_at": i.created_at, "updated_at": i.updated_at,
            "alerts": [_alert_dict(a) for a in i.alerts],
            "events": [{"id": e.id, "timestamp": e.timestamp, "event_type": e.event_type,
                        "source_ip": e.source_ip, "host": e.host, "username": e.username,
                        "is_synthetic": e.is_synthetic} for e in i.events],
            "notes": (i.ai_analysis or {}).get("notes", [])}


@router.get("/incidents")
def list_incidents(status: str | None = None, db: Session = Depends(get_db), _: models.User = OPEN):
    q = db.query(models.Incident).order_by(models.Incident.created_at.desc())
    if status:
        q = q.filter(models.Incident.status == status)
    return [_incident_dict(i, db) for i in q.limit(200).all()]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db), _: models.User = OPEN):
    i = db.get(models.Incident, incident_id)
    if not i:
        raise HTTPException(404, "Incident not found")
    return _incident_dict(i, db)


@router.patch("/incidents/{incident_id}/status")
def set_status(incident_id: int, data: schemas.IncidentStatusIn, db: Session = Depends(get_db),
               user: models.User = Depends(require("analyst")), request: Request = None):
    i = db.get(models.Incident, incident_id)
    if not i:
        raise HTTPException(404, "Incident not found")
    old = i.status
    i.status = data.status
    i.updated_at = datetime.now(timezone.utc)
    db.commit()
    audit.audit(db, user.username, "incident.status", f"incident:{i.id}",
                detail={"from": old, "to": data.status}, ip=client_ip(request) if request else "")
    return {"id": i.id, "status": i.status}


@router.post("/incidents/{incident_id}/notes")
def add_note(incident_id: int, data: schemas.NoteIn, db: Session = Depends(get_db),
             user: models.User = Depends(require("analyst")), request: Request = None):
    i = db.get(models.Incident, incident_id)
    if not i:
        raise HTTPException(404, "Incident not found")
    notes = (i.ai_analysis or {}).get("notes", [])
    notes.append({"author": user.username, "body": data.body,
                  "at": str(datetime.now(timezone.utc))})
    i.ai_analysis = {**(i.ai_analysis or {}), "notes": notes}
    db.commit()
    audit.audit(db, user.username, "incident.note", f"incident:{i.id}", ip=client_ip(request) if request else "")
    return {"ok": True, "notes": notes}


@router.post("/incidents", status_code=201)
def create_incident(payload: dict, db: Session = Depends(get_db),
                    user: models.User = Depends(require("analyst")), request: Request = None):
    i = models.Incident(title=payload.get("title", "Manual incident"),
                        severity=payload.get("severity", "medium"),
                        confidence=payload.get("confidence", 0.5),
                        summary=payload.get("summary", ""), status="new")
    db.add(i)
    db.commit()
    audit.audit(db, user.username, "incident.create", f"incident:{i.id}",
                detail={"title": i.title}, ip=client_ip(request) if request else "")
    return _incident_dict(i, db)


@router.post("/incidents/{incident_id}/link-event/{event_id}")
def link_event(incident_id: int, event_id: int, db: Session = Depends(get_db),
               user: models.User = Depends(require("analyst")), request: Request = None):
    i = db.get(models.Incident, incident_id)
    e = db.get(models.Event, event_id)
    if not i or not e:
        raise HTTPException(404, "Incident or event not found")
    if e not in i.events:
        i.events.append(e)
        db.commit()
    audit.audit(db, user.username, "incident.link_event", f"incident:{i.id}/event:{e.id}",
                ip=client_ip(request) if request else "")
    return {"ok": True}


# ---- IOCs / Threat Intel ----

@router.get("/iocs")
def list_iocs(type: str | None = None, active: bool | None = None, db: Session = Depends(get_db),
              _: models.User = OPEN):
    q = db.query(models.IOC).order_by(models.IOC.last_seen.desc())
    if type:
        q = q.filter(models.IOC.type == type)
    if active is not None:
        q = q.filter(models.IOC.active.is_(active))
    return [{"id": i.id, "type": i.type, "value": i.value, "confidence": i.confidence,
             "source": i.source, "active": i.active, "first_seen": i.first_seen,
             "last_seen": i.last_seen, "metadata": i.metadata_} for i in q.limit(500).all()]


@router.post("/iocs", status_code=201)
def create_ioc(data: schemas.IOCIn, db: Session = Depends(get_db),
               user: models.User = Depends(require("analyst")), request: Request = None):
    existing = db.query(models.IOC).filter(models.IOC.value == data.value).first()
    if existing:
        existing.confidence = data.confidence
        existing.active = True
        db.commit()
        return {"id": existing.id, "value": existing.value, "updated": True}
    ioc = models.IOC(**data.model_dump())
    db.add(ioc)
    db.commit()
    audit.audit(db, user.username, "ioc.create", data.value, ip=client_ip(request) if request else "")
    return {"id": ioc.id, "value": ioc.value}


@router.delete("/iocs/{ioc_id}")
def deactivate_ioc(ioc_id: int, db: Session = Depends(get_db),
                   user: models.User = Depends(require("analyst")), request: Request = None):
    ioc = db.get(models.IOC, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    ioc.active = False
    db.commit()
    audit.audit(db, user.username, "ioc.deactivate", ioc.value, ip=client_ip(request) if request else "")
    return {"ok": True}


@router.get("/intel")
def intel_records(feed: str | None = None, db: Session = Depends(get_db), _: models.User = OPEN):
    q = db.query(models.ThreatIntelRecord).order_by(models.ThreatIntelRecord.fetched_at.desc())
    if feed:
        q = q.filter(models.ThreatIntelRecord.feed == feed)
    return [{"id": r.id, "feed": r.feed, "type": r.type, "value": r.value,
             "confidence": r.confidence, "fetched_at": r.fetched_at} for r in q.limit(500).all()]


@router.get("/assets")
def list_assets(db: Session = Depends(get_db), _: models.User = OPEN):
    assets = db.query(models.Asset).order_by(models.Asset.risk_score.desc()).all()
    return [{"id": a.id, "hostname": a.hostname, "ip": a.ip, "os": a.os, "status": a.status,
             "agent_status": a.agent_status, "risk_score": a.risk_score,
             "last_seen": a.last_seen, "tags": a.tags,
             "open_alerts": db.query(models.Alert).filter(
                 models.Alert.asset_id == a.id, models.Alert.status == "open").count(),
             "open_incidents": db.query(models.Incident).filter(
                 models.Incident.asset_id == a.id,
                 ~models.Incident.status.in_(["resolved", "closed"])).count()}
            for a in assets]
