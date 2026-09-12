from sqlalchemy.orm import Session
from . import models


def audit(db: Session, actor: str, action: str, target: str = "", result: str = "success",
          ip: str = "", detail: dict | None = None) -> models.AuditLog:
    entry = models.AuditLog(actor=actor, action=action, target=target, result=result,
                            ip=ip, detail=detail or {})
    db.add(entry)
    db.commit()
    return entry
