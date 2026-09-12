from .database import SessionLocal
from . import models
from .security import hash_password
from .detection import seed_rules
from .response import seed_policies


def run_seed():
    db = SessionLocal()
    try:
        if not db.query(models.User).first():
            db.add_all([
                models.User(username="admin", email="admin@chekwe.local",
                            hashed_password=hash_password("admin123!"),
                            role="admin"),
                models.User(username="analyst", hashed_password=hash_password("analyst123!"),
                            role="analyst"),
                models.User(username="viewer", hashed_password=hash_password("viewer123!"),
                            role="viewer"),
            ])
        seed_rules(db)
        seed_policies(db)
        db.commit()
    finally:
        db.close()
