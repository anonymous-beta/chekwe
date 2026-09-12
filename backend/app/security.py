from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
from .config import get_settings

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGO = "HS256"


def hash_password(p: str) -> str:
    return pwd.hash(p)


def verify_password(p: str, hashed: str) -> bool:
    return pwd.verify(p, hashed)


def create_token(sub: str, role: str) -> str:
    s = get_settings()
    exp = datetime.now(timezone.utc) + timedelta(minutes=s.ACCESS_TOKEN_TTL_MINUTES)
    return jwt.encode({"sub": sub, "role": role, "exp": exp}, s.SECRET_KEY, algorithm=ALGO)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, get_settings().SECRET_KEY, algorithms=[ALGO])
    except JWTError:
        return None
