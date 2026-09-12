from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .database import get_db
from .security import decode_token
from . import models

oauth2 = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


def get_current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> models.User:
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    user = db.query(models.User).filter(models.User.username == payload["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or disabled")
    return user


def require(*roles: str):
    def checker(user: models.User = Depends(get_current_user)) -> models.User:
        if ROLE_RANK.get(user.role, 0) < max(ROLE_RANK[r] for r in roles):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient permissions")
        return user
    return checker


def client_ip(request) -> str:
    return request.client.host if request.client else ""
