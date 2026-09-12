from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    SECRET_KEY: str = "dev-insecure-change-me"
    DATABASE_URL: str = "sqlite:///./chekwe.db"
    DEMO_MODE: bool = True
    CORS_ORIGINS: str = "http://localhost:5173"
    ACCESS_TOKEN_TTL_MINUTES: int = 480
    APP_NAME: str = "CHEKWE"

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    @property
    def fernet_key(self) -> bytes:
        import base64, hashlib
        return base64.urlsafe_b64encode(hashlib.sha256(self.SECRET_KEY.encode()).digest())


@lru_cache
def get_settings() -> Settings:
    return Settings()
