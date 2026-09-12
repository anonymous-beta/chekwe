"""AI provider abstraction. The browser never talks to the AI provider directly."""
import json
import httpx
from cryptography.fernet import Fernet
from sqlalchemy.orm import Session
from .config import get_settings
from . import models

PROVIDERS = {
    "openai": {"default_endpoint": "https://api.openai.com/v1", "path": "/chat/completions"},
    "custom": {"default_endpoint": "", "path": "/chat/completions"},
    "anthropic": {"default_endpoint": "https://api.anthropic.com/v1", "path": "/messages"},
    "google": {"default_endpoint": "https://generativelanguage.googleapis.com/v1beta/openai",
               "path": "/chat/completions"},  # OpenAI-compatible surface
}


def _fernet() -> Fernet:
    return Fernet(get_settings().fernet_key)


def encrypt_secret(plain: str) -> str:
    return _fernet().encrypt(plain.encode()).decode()


def decrypt_secret(enc: str) -> str:
    try:
        return _fernet().decrypt(enc.encode()).decode()
    except Exception:
        return ""


def get_config(db: Session) -> models.AIProviderConfig | None:
    return db.query(models.AIProviderConfig).first()


def save_config(db: Session, data: dict) -> models.AIProviderConfig:
    cfg = get_config(db)
    if not cfg:
        cfg = models.AIProviderConfig(provider="openai")
        db.add(cfg)
    for field in ("provider", "endpoint", "model", "temperature", "max_tokens", "allow_auto_response"):
        if field in data:
            setattr(cfg, field, data[field])
    if data.get("api_key"):
        cfg.api_key_enc = encrypt_secret(data["api_key"])
    from datetime import datetime, timezone
    cfg.updated_at = datetime.now(timezone.utc)
    db.commit()
    return cfg


def mask_key(enc: str) -> str:
    if not enc:
        return ""
    return "••••••" + decrypt_secret(enc)[-4:] if decrypt_secret(enc) else ""


def test_connection(db: Session) -> dict:
    cfg = get_config(db)
    if not cfg or not cfg.api_key_enc or not cfg.endpoint:
        return {"ok": False, "state": "not_configured", "message": "AI provider not configured."}
    meta = PROVIDERS.get(cfg.provider, PROVIDERS["custom"])
    url = cfg.endpoint.rstrip("/") + meta["path"]
    key = decrypt_secret(cfg.api_key_enc)
    try:
        if cfg.provider == "anthropic":
            r = httpx.post(url, headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                                         "content-type": "application/json"},
                           json={"model": cfg.model, "max_tokens": 8,
                                 "messages": [{"role": "user", "content": "ping"}]}, timeout=15)
        else:
            r = httpx.post(url, headers={"Authorization": f"Bearer {key}"},
                           json={"model": cfg.model, "max_tokens": 8, "messages": [
                               {"role": "user", "content": "ping"}]}, timeout=15)
        if r.status_code == 200:
            return {"ok": True, "state": "connected", "message": f"HTTP {r.status_code}"}
        if r.status_code in (401, 403):
            return {"ok": False, "state": "invalid_credentials", "message": f"HTTP {r.status_code}"}
        return {"ok": False, "state": "connection_failed", "message": f"HTTP {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"ok": False, "state": "connection_failed", "message": str(e)[:300]}


def chat(db: Session, messages: list[dict]) -> str | None:
    """Return provider text, or None when unavailable. Callers must handle None."""
    cfg = get_config(db)
    if not cfg or not cfg.api_key_enc or not cfg.endpoint:
        return None
    meta = PROVIDERS.get(cfg.provider, PROVIDERS["custom"])
    url = cfg.endpoint.rstrip("/") + meta["path"]
    key = decrypt_secret(cfg.api_key_enc)
    try:
        if cfg.provider == "anthropic":
            r = httpx.post(url, headers={"x-api-key": key, "anthropic-version": "2023-06-01",
                                         "content-type": "application/json"},
                           json={"model": cfg.model, "max_tokens": cfg.max_tokens,
                                 "temperature": cfg.temperature, "messages": messages}, timeout=60)
            if r.status_code != 200:
                return None
            data = r.json()
            return "".join(b.get("text", "") for b in data.get("content", []))
        r = httpx.post(url, headers={"Authorization": f"Bearer {key}"},
                       json={"model": cfg.model, "temperature": cfg.temperature,
                             "max_tokens": cfg.max_tokens, "messages": messages}, timeout=60)
        if r.status_code != 200:
            return None
        return r.json()["choices"][0]["message"]["content"]
    except Exception:
        return None


def analyze_incident(db: Session, incident: models.Incident) -> dict:
    """Structured OBSERVED/INFERRED/UNKNOWN analysis. Never invents evidence."""
    alerts = db.query(models.Alert).filter(models.Alert.incident_id == incident.id).all()
    events = incident.events
    observed = [
        f"Incident severity {incident.severity}, status {incident.status}, "
        f"confidence {incident.confidence:.0%}.",
        f"{len(alerts)} related alert(s): " + "; ".join(
            f"[{a.severity}] {a.title} (rule {a.rule_code})" for a in alerts) if alerts else
        "No alerts are currently attached to this incident.",
        f"{len(events)} related event(s) in the incident timeline." +
        (f" {sum(1 for e in events if e.is_synthetic)} are tagged DEMO/SYNTHETIC." if any(
            e.is_synthetic for e in events) else ""),
    ]
    inferred, unknown = [], []
    rule_codes = {a.rule_code for a in alerts}
    if "brute_force_auth" in rule_codes:
        inferred.append("Repeated failures may indicate credential-guessing activity.")
        unknown.append("No evidence currently confirms a successful account compromise.")
    if "ioc_match" in rule_codes:
        inferred.append("At least one event matched a known malicious indicator.")
        unknown.append("The initial delivery vector is not established by current telemetry.")
    if "suspicious_process" in rule_codes:
        inferred.append("Offensive tooling on the host suggests hands-on activity, "
                        "not just network noise.")
    if not inferred:
        inferred.append("Pattern is consistent with the triggering detection rule(s); "
                        "manual scoping is recommended.")
    unknown.append("Full asset exposure and lateral movement cannot be confirmed "
                   "without endpoint telemetry review.")

    prompt = [
        {"role": "system", "content":
         "You are a defensive SOC analyst. Use ONLY the facts provided. Structure the answer "
         "with the exact headings OBSERVED:, INFERRED:, UNKNOWN:. Never invent evidence, "
         "IP addresses, or artifacts. Then give ATTACK CHAIN HYPOTHESIS:, RECOMMENDED "
         "INVESTIGATION STEPS:, and RECOMMENDED RESPONSE: (defensive actions only)."},
        {"role": "user", "content":
         f"Incident: {incident.title}\nSeverity: {incident.severity}\n"
         f"Alerts:\n" + "\n".join(f"- {a.title}: {a.reason}" for a in alerts) +
         f"\nObserved facts:\n- " + "\n- ".join(o for o in observed if o)},
    ]
    ai_text = chat(db, prompt)
    return {"observed": observed, "inferred": inferred, "unknown": unknown,
            "ai_available": ai_text is not None,
            "ai_raw": ai_text or "AI provider not configured — heuristic analysis shown.",
            "provider": (get_config(db).provider if get_config(db) else "none"),
            "generated_at": str(models.utcnow())}
