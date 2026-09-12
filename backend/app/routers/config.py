from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from .. import models, schemas, ai, response
from ..database import get_db
from ..deps import get_current_user, require, client_ip
from ..audit import audit
from ..detection import test_rule

router = APIRouter(tags=["config"])
OPEN = Depends(get_current_user)


@router.get("/health")
def health(db: Session = Depends(get_db)):
    checks = {}
    try:
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "failed"
    checks["detection_engine"] = "ok"
    checks["ingestion"] = "ok"
    cfg = ai.get_config(db)
    checks["ai_provider"] = ("configured" if cfg and cfg.api_key_enc else "not_configured")
    integrations = [{"name": i.name, "type": i.type, "enabled": i.enabled,
                     "status": i.last_status} for i in db.query(models.Integration).all()]
    assets = db.query(models.Asset).all()
    stale = sum(1 for a in assets if (datetime.now(timezone.utc) - a.last_seen.replace(
        tzinfo=timezone.utc) if a.last_seen.tzinfo is None else a.last_seen).total_seconds() > 86400)
    checks["sensors"] = {"total": len(assets), "stale": stale}
    checks["websocket"] = "ok"
    return {"status": "ok" if checks["database"] == "ok" else "degraded",
            "time": str(datetime.now(timezone.utc)), "checks": checks, "integrations": integrations}


@router.get("/rules")
def list_rules(db: Session = Depends(get_db), _: models.User = OPEN):
    return [{"code": r.code, "name": r.name, "description": r.description, "severity": r.severity,
             "threshold": r.threshold, "enabled": r.enabled, "mitre": r.mitre,
             "trigger_count": r.trigger_count, "last_triggered": r.last_triggered}
            for r in db.query(models.DetectionRule).all()]


@router.patch("/rules/{code}")
def update_rule(code: str, data: schemas.RuleUpdate, db: Session = Depends(get_db),
                user: models.User = Depends(require("admin", "analyst")), request: Request = None):
    r = db.query(models.DetectionRule).filter(models.DetectionRule.code == code).first()
    if not r:
        raise HTTPException(404, "Rule not found")
    changed = data.model_dump(exclude_none=True)
    for k, v in changed.items():
        setattr(r, k, v)
    db.commit()
    audit.audit(db, user.username, "rule.update", code, detail=changed,
                ip=client_ip(request) if request else "")
    return {"code": r.code, "enabled": r.enabled, "severity": r.severity, "threshold": r.threshold}


@router.post("/rules/{code}/test")
def run_test(code: str, payload: dict, db: Session = Depends(get_db), _: models.User = OPEN):
    return test_rule(db, code, payload)


# ---- Response ----

@router.get("/response/policies")
def policies(db: Session = Depends(get_db), _: models.User = OPEN):
    return [{"id": p.id, "name": p.name, "action_type": p.action_type, "mode": p.mode,
             "enabled": p.enabled, "config": p.config}
            for p in db.query(models.ResponsePolicy).all()]


@router.patch("/response/policies/{policy_id}")
def update_policy(policy_id: int, data: schemas.PolicyUpdate, db: Session = Depends(get_db),
                  user: models.User = Depends(require("admin")), request: Request = None):
    p = db.get(models.ResponsePolicy, policy_id)
    if not p:
        raise HTTPException(404, "Policy not found")
    for k, v in data.model_dump(exclude_none=True).items():
        setattr(p, k, v)
    db.commit()
    audit.audit(db, user.username, "policy.update", p.action_type,
                detail=data.model_dump(exclude_none=True), ip=client_ip(request) if request else "")
    return {"id": p.id, "mode": p.mode, "enabled": p.enabled}


@router.post("/response/actions", status_code=201)
def request_action(data: schemas.ResponseRequest, db: Session = Depends(get_db),
                   user: models.User = Depends(require("analyst")), request: Request = None):
    a = response.create_action(db, data.action_type, data.target, data.reason, user.username,
                               alert_id=data.alert_id, incident_id=data.incident_id,
                               dry_run=data.dry_run, ip=client_ip(request) if request else "")
    return action_dict(a)


@router.get("/response/actions")
def list_actions(db: Session = Depends(get_db), _: models.User = OPEN):
    return [action_dict(a) for a in db.query(models.ResponseAction).order_by(
        models.ResponseAction.created_at.desc()).limit(200).all()]


def action_dict(a: models.ResponseAction) -> dict:
    return {"id": a.id, "action_type": a.action_type, "target": a.target, "reason": a.reason,
            "alert_id": a.alert_id, "incident_id": a.incident_id, "dry_run": a.dry_run,
            "status": a.status, "result": a.result, "requested_by": a.requested_by,
            "executed_by": a.executed_by, "created_at": a.created_at, "executed_at": a.executed_at}


@router.post("/response/actions/{action_id}/approve")
def approve(action_id: int, db: Session = Depends(get_db),
            user: models.User = Depends(require("analyst")), request: Request = None):
    a = db.get(models.ResponseAction, action_id)
    if not a:
        raise HTTPException(404, "Action not found")
    if a.status != "pending":
        raise HTTPException(409, f"Action is {a.status}, cannot approve")
    a.status = "approved"
    db.commit()
    audit.audit(db, user.username, "response.approve", f"{a.action_type}:{a.target}",
                ip=client_ip(request) if request else "")
    return action_dict(response.execute(db, a, user.username, client_ip(request) if request else ""))


@router.post("/response/actions/{action_id}/reject")
def reject(action_id: int, payload: dict, db: Session = Depends(get_db),
           user: models.User = Depends(require("analyst")), request: Request = None):
    a = db.get(models.ResponseAction, action_id)
    if not a:
        raise HTTPException(404, "Action not found")
    a.status = "rejected"
    a.result = {"message": payload.get("reason", "rejected by analyst")}
    db.commit()
    audit.audit(db, user.username, "response.reject", f"{a.action_type}:{a.target}",
                ip=client_ip(request) if request else "")
    return action_dict(a)


# ---- AI ----

@router.get("/ai/config")
def ai_config(db: Session = Depends(get_db), user: models.User = Depends(require("admin", "analyst"))):
    cfg = ai.get_config(db)
    if not cfg:
        return {"provider": "openai", "endpoint": "", "model": "", "configured": False,
                "key_masked": "", "allow_auto_response": False}
    return {"provider": cfg.provider, "endpoint": cfg.endpoint, "model": cfg.model,
            "configured": bool(cfg.api_key_enc), "key_masked": ai.mask_key(cfg.api_key_enc),
            "temperature": cfg.temperature, "max_tokens": cfg.max_tokens,
            "allow_auto_response": cfg.allow_auto_response}


@router.put("/ai/config")
def ai_config_save(data: schemas.AIConfigIn, db: Session = Depends(get_db),
                   user: models.User = Depends(require("admin")), request: Request = None):
    cfg = ai.save_config(db, data.model_dump(exclude_none=True))
    audit.audit(db, user.username, "ai.config", cfg.provider,
                detail={"model": cfg.model, "endpoint": cfg.endpoint},
                ip=client_ip(request) if request else "")
    return {"ok": True, "provider": cfg.provider}


@router.post("/ai/test")
def ai_test(db: Session = Depends(get_db), _: models.User = Depends(require("admin", "analyst"))):
    return ai.test_connection(db)


@router.post("/ai/analyze-incident/{incident_id}")
def ai_analyze(incident_id: int, db: Session = Depends(get_db),
               user: models.User = Depends(require("analyst")), request: Request = None):
    i = db.get(models.Incident, incident_id)
    if not i:
        raise HTTPException(404, "Incident not found")
    analysis = ai.analyze_incident(db, i)
    i.ai_analysis = {**analysis, "notes": (i.ai_analysis or {}).get("notes", [])}
    db.commit()
    audit.audit(db, user.username, "ai.analyze", f"incident:{i.id}",
                detail={"provider": analysis["provider"]}, ip=client_ip(request) if request else "")
    return analysis


# ---- Integrations ----

@router.get("/integrations")
def list_integrations(db: Session = Depends(get_db), _: models.User = OPEN):
    return [{"id": i.id, "name": i.name, "type": i.type, "endpoint": i.endpoint,
             "config": {k: v for k, v in i.config.items() if k != "headers"},
             "has_secret": bool(i.secret_enc), "enabled": i.enabled,
             "last_status": i.last_status, "last_checked": i.last_checked}
            for i in db.query(models.Integration).all()]


@router.post("/integrations", status_code=201)
def create_integration(data: schemas.IntegrationIn, db: Session = Depends(get_db),
                       user: models.User = Depends(require("admin")), request: Request = None):
    if db.query(models.Integration).filter(models.Integration.name == data.name).first():
        raise HTTPException(409, "Integration name already exists")
    it = models.Integration(name=data.name, type=data.type, endpoint=data.endpoint,
                            config=data.config, enabled=data.enabled)
    if data.secret:
        it.secret_enc = ai.encrypt_secret(data.secret)
    db.add(it)
    db.commit()
    audit.audit(db, user.username, "integration.create", data.name,
                ip=client_ip(request) if request else "")
    return {"id": it.id, "name": it.name}


@router.patch("/integrations/{integration_id}")
def update_integration(integration_id: int, payload: dict, db: Session = Depends(get_db),
                       user: models.User = Depends(require("admin")), request: Request = None):
    it = db.get(models.Integration, integration_id)
    if not it:
        raise HTTPException(404, "Integration not found")
    if "enabled" in payload:
        it.enabled = bool(payload["enabled"])
    if "endpoint" in payload:
        it.endpoint = payload["endpoint"]
    if "config" in payload:
        it.config = payload["config"]
    if payload.get("secret"):
        it.secret_enc = ai.encrypt_secret(payload["secret"])
    db.commit()
    audit.audit(db, user.username, "integration.update", it.name, detail=payload,
                ip=client_ip(request) if request else "")
    return {"id": it.id, "enabled": it.enabled}


@router.post("/integrations/{integration_id}/test")
def test_integration(integration_id: int, db: Session = Depends(get_db),
                     _: models.User = Depends(require("admin", "analyst"))):
    import httpx
    it = db.get(models.Integration, integration_id)
    if not it:
        raise HTTPException(404, "Integration not found")
    if not it.endpoint:
        it.last_status = "not_configured"
        db.commit()
        return {"ok": False, "status": "not_configured"}
    try:
        headers = it.config.get("headers", {})
        if it.secret_enc:
            headers = {**headers, "Authorization": f"Bearer {ai.decrypt_secret(it.secret_enc)}"}
        r = httpx.post(it.endpoint, json={"type": "chekwe.healthcheck", "timestamp":
                         str(datetime.now(timezone.utc))}, headers=headers, timeout=10)
        it.last_status = "connected" if r.is_success else "connection_failed"
    except Exception:
        it.last_status = "connection_failed"
    it.last_checked = datetime.now(timezone.utc)
    db.commit()
    return {"ok": it.last_status == "connected", "status": it.last_status}


# ---- Notifications & settings ----

@router.get("/notifications")
def notifications(db: Session = Depends(get_db), _: models.User = OPEN):
    return [{"id": n.id, "kind": n.kind, "title": n.title, "message": n.message,
             "severity": n.severity, "read": n.read, "created_at": n.created_at}
            for n in db.query(models.Notification).order_by(
                models.Notification.created_at.desc()).limit(50).all()]


@router.get("/settings")
def get_settings_api(db: Session = Depends(get_db), _: models.User = OPEN):
    from ..config import get_settings as gs
    return {"demo_mode": gs().DEMO_MODE, "app": "CHEKWE", "version": "0.1.0"}


@router.put("/settings")
def put_settings(data: schemas.SettingsIn, db: Session = Depends(get_db),
                 user: models.User = Depends(require("admin")), request: Request = None):
    audit.audit(db, user.username, "settings.update", detail=data.model_dump(exclude_none=True),
                ip=client_ip(request) if request else "")
    return {"ok": True, "note": "Runtime demo-mode changes require a restart; edit .env."}
