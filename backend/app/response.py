"""Controlled response framework: policy → approval → adapter → audit.

AI never executes anything. Adapters only perform their one defined action.
"""
from datetime import datetime, timezone
import httpx
from sqlalchemy.orm import Session
from . import models, audit


class AdapterResult(dict):
    pass


def _integration_for(db: Session, type_: str) -> models.Integration | None:
    return db.query(models.Integration).filter(
        models.Integration.type == type_, models.Integration.enabled.is_(True)).first()


def _webhook(db: Session, action: models.ResponseAction, payload: dict) -> AdapterResult:
    """Generic HTTP adapter: POSTs the action payload to a configured integration endpoint."""
    it = _integration_for(db, "webhook")
    if not it:
        return AdapterResult(ok=False, status="unavailable",
                             message="No enabled webhook integration configured.")
    try:
        headers = it.config.get("headers", {})
        r = httpx.post(it.endpoint, json=payload, headers=headers, timeout=10)
        return AdapterResult(ok=r.is_success, status="executed" if r.is_success else "failed",
                             message=f"webhook {it.endpoint} -> HTTP {r.status_code}", http_status=r.status_code)
    except Exception as e:
        return AdapterResult(ok=False, status="failed", message=f"webhook error: {e}")


def act_block_ip(db: Session, action: models.ResponseAction, dry: bool) -> AdapterResult:
    if dry:
        return AdapterResult(ok=True, status="dry_run", message=f"would block IP {action.target}")
    # Real local effect: maintain an enforced blocklist table (viewable in Intel UI).
    ioc = db.query(models.IOC).filter(models.IOC.value == action.target).first()
    if not ioc:
        ioc = models.IOC(type="ip", value=action.target, source="response-engine", confidence=90)
        db.add(ioc)
    ioc.active = True
    db.commit()
    wh = _webhook(db, action, {"action": "block_ip", "ip": action.target, "reason": action.reason,
                               "alert_id": action.alert_id})
    return AdapterResult(ok=True, status="executed",
                         message=f"IP {action.target} added to enforced blocklist" +
                                 (f"; notified gateway ({wh['message']})" if wh["ok"] else ""))


def act_blocklist_ioc(db: Session, action: models.ResponseAction, dry: bool) -> AdapterResult:
    if dry:
        return AdapterResult(ok=True, status="dry_run", message=f"would add IOC {action.target} to blocklist")
    ioc = db.query(models.IOC).filter(models.IOC.value == action.target).first()
    if not ioc:
        return AdapterResult(ok=False, status="failed", message="IOC not found in database")
    ioc.active = True
    db.commit()
    return AdapterResult(ok=True, status="executed", message=f"IOC {action.target} activated as blocklist entry")


def act_terminate_process(db: Session, action: models.ResponseAction, dry: bool) -> AdapterResult:
    # Requires an EDR/agent integration; without one the action is honestly unavailable.
    if dry:
        return AdapterResult(ok=True, status="dry_run", message=f"would terminate process {action.target}")
    if not _integration_for(db, "edr"):
        return AdapterResult(ok=False, status="unavailable",
                             message="No EDR/agent integration configured — action not executed.")
    return _webhook(db, action, {"action": "terminate_process", "target": action.target, "reason": action.reason})


def act_isolate_host(db: Session, action: models.ResponseAction, dry: bool) -> AdapterResult:
    if dry:
        return AdapterResult(ok=True, status="dry_run", message=f"would isolate host {action.target}")
    if not _integration_for(db, "edr"):
        return AdapterResult(ok=False, status="unavailable",
                             message="No EDR/agent integration configured — action not executed.")
    return _webhook(db, action, {"action": "isolate_host", "host": action.target, "reason": action.reason})


def act_lock_account(db: Session, action: models.ResponseAction, dry: bool) -> AdapterResult:
    if dry:
        return AdapterResult(ok=True, status="dry_run", message=f"would lock account {action.target}")
    if not _integration_for(db, "identity"):
        return AdapterResult(ok=False, status="unavailable",
                             message="No identity integration configured — action not executed.")
    return _webhook(db, action, {"action": "lock_account", "account": action.target, "reason": action.reason})


def act_quarantine_file(db: Session, action: models.ResponseAction, dry: bool) -> AdapterResult:
    if dry:
        return AdapterResult(ok=True, status="dry_run", message=f"would quarantine file {action.target}")
    if not _integration_for(db, "edr"):
        return AdapterResult(ok=False, status="unavailable",
                             message="No EDR/agent integration configured — action not executed.")
    return _webhook(db, action, {"action": "quarantine_file", "path": action.target, "reason": action.reason})


ADAPTERS = {
    "block_ip": act_block_ip,
    "blocklist_ioc": act_blocklist_ioc,
    "terminate_process": act_terminate_process,
    "isolate_host": act_isolate_host,
    "lock_account": act_lock_account,
    "quarantine_file": act_quarantine_file,
}


def execute(db: Session, action: models.ResponseAction, actor: str, ip: str = "") -> models.ResponseAction:
    adapter = ADAPTERS.get(action.action_type)
    if not adapter:
        action.status = "failed"
        action.result = {"message": f"unknown action type {action.action_type}"}
        db.commit()
        return action
    result = adapter(db, action, dry=action.dry_run)
    action.status = result.get("status", "failed")
    action.result = dict(result)
    action.executed_by = actor
    action.executed_at = datetime.now(timezone.utc)
    db.commit()
    audit.audit(db, actor, "response.execute", f"{action.action_type}:{action.target}",
                result="success" if result.get("ok") else "failure", ip=ip,
                detail={"status": action.status, "dry_run": action.dry_run})
    return action


def create_action(db: Session, action_type: str, target: str, reason: str, actor: str,
                  alert_id: int | None = None, incident_id: int | None = None,
                  dry_run: bool = True, ip: str = "") -> models.ResponseAction:
    policy = db.query(models.ResponsePolicy).filter(
        models.ResponsePolicy.action_type == action_type,
        models.ResponsePolicy.enabled.is_(True)).first()
    mode = policy.mode if policy else "approval"  # safe default
    action = models.ResponseAction(
        policy_id=policy.id if policy else None, action_type=action_type, target=target,
        reason=reason, alert_id=alert_id, incident_id=incident_id, dry_run=dry_run,
        requested_by=actor, status="pending")
    db.add(action)
    db.commit()
    audit.audit(db, actor, "response.request", f"{action_type}:{target}", ip=ip,
                detail={"mode": mode, "dry_run": dry_run})
    if mode == "automatic" or mode == "manual":
        execute(db, action, actor=actor, ip=ip)
    return action


def seed_policies(db: Session):
    defaults = [
        ("block_ip", "approval"), ("blocklist_ioc", "approval"),
        ("terminate_process", "approval"), ("isolate_host", "approval"),
        ("lock_account", "approval"), ("quarantine_file", "approval"),
    ]
    for at, mode in defaults:
        if not db.query(models.ResponsePolicy).filter(models.ResponsePolicy.action_type == at).first():
            db.add(models.ResponsePolicy(name=f"Default {at} policy", action_type=at,
                                         mode=mode, enabled=True))
    db.commit()
