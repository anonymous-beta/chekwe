from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from .. import models, schemas, audit
from ..database import get_db
from ..security import verify_password, create_token, hash_password
from ..deps import get_current_user, require, client_ip

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=schemas.Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db),
          request: Request = None):
    user = db.query(models.User).filter(models.User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        audit.audit(db, form.username, "auth.login", result="failure",
                    ip=client_ip(request) if request else "")
        raise HTTPException(401, "Invalid credentials")
    if not user.is_active:
        raise HTTPException(403, "Account disabled")
    audit.audit(db, user.username, "auth.login", ip=client_ip(request) if request else "")
    return schemas.Token(access_token=create_token(user.username, user.role))


@router.get("/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(get_current_user)):
    return user


@router.post("/logout")
def logout(user: models.User = Depends(get_current_user), db: Session = Depends(get_db),
           request: Request = None):
    audit.audit(db, user.username, "auth.logout", ip=client_ip(request) if request else "")
    return {"ok": True}


@router.get("/users", response_model=list[schemas.UserOut])
def list_users(db: Session = Depends(get_db), _: models.User = Depends(require("admin"))):
    return db.query(models.User).all()


@router.post("/users", response_model=schemas.UserOut, status_code=201)
def create_user(data: schemas.UserIn, db: Session = Depends(get_db),
                admin: models.User = Depends(require("admin")), request: Request = None):
    if db.query(models.User).filter(models.User.username == data.username).first():
        raise HTTPException(409, "Username already exists")
    user = models.User(username=data.username, email=data.email, role=data.role,
                       hashed_password=hash_password(data.password))
    db.add(user)
    db.commit()
    audit.audit(db, admin.username, "user.create", data.username, ip=client_ip(request) if request else "")
    return user


@router.patch("/users/{username}")
def update_user(username: str, payload: dict, db: Session = Depends(get_db),
                admin: models.User = Depends(require("admin")), request: Request = None):
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(404, "User not found")
    if "role" in payload and payload["role"] in ("admin", "analyst", "viewer"):
        user.role = payload["role"]
    if "is_active" in payload:
        user.is_active = bool(payload["is_active"])
    db.commit()
    audit.audit(db, admin.username, "user.update", username,
                detail=payload, ip=client_ip(request) if request else "")
    return {"ok": True}


@router.get("/audit")
def list_audit(limit: int = 100, db: Session = Depends(get_db),
               _: models.User = Depends(require("admin", "analyst"))):
    limit = min(limit, 500)
    rows = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(limit).all()
    return [{"id": r.id, "timestamp": r.timestamp, "actor": r.actor, "action": r.action,
             "target": r.target, "result": r.result, "ip": r.ip, "detail": r.detail} for r in rows]
