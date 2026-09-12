from datetime import datetime
from pydantic import BaseModel, Field


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8)
    email: str = ""
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")


class UserOut(BaseModel):
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


class EventIn(BaseModel):
    source: str = "api"
    host: str | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    protocol: str | None = None
    port: int | None = None
    username: str | None = None
    process: str | None = None
    event_type: str = "generic"
    severity: str = "info"
    timestamp: datetime | str | float | None = None
    is_synthetic: bool = False
    raw: dict = Field(default_factory=dict)
    message: str | None = None


class IncidentStatusIn(BaseModel):
    status: str = Field(pattern="^(new|triaged|investigating|contained|remediating|resolved|closed)$")


class NoteIn(BaseModel):
    body: str = Field(min_length=1)


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: str | None = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    threshold: dict | None = None


class IOCIn(BaseModel):
    type: str = Field(pattern="^(ip|domain|url|hash|cve)$")
    value: str = Field(min_length=2, max_length=512)
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = "manual"


class ResponseRequest(BaseModel):
    action_type: str = Field(pattern="^(block_ip|blocklist_ioc|terminate_process|isolate_host|lock_account|quarantine_file)$")
    target: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=3)
    alert_id: int | None = None
    incident_id: int | None = None
    dry_run: bool = True


class PolicyUpdate(BaseModel):
    mode: str | None = Field(default=None, pattern="^(automatic|manual|approval)$")
    enabled: bool | None = None


class AIConfigIn(BaseModel):
    provider: str | None = Field(default=None, pattern="^(openai|anthropic|google|custom)$")
    endpoint: str | None = None
    api_key: str | None = None
    model: str | None = None
    temperature: float | None = Field(default=None, ge=0, le=2)
    max_tokens: int | None = Field(default=None, ge=1, le=32000)
    allow_auto_response: bool | None = None


class IntegrationIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    type: str = Field(pattern="^(webhook|firewall|edr|identity|email|blocklist)$")
    endpoint: str = ""
    secret: str | None = None
    config: dict = Field(default_factory=dict)
    enabled: bool = False


class SettingsIn(BaseModel):
    demo_mode: bool | None = None
