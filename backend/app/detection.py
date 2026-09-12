"""Modular rule-based detection engine. Rules are pluggable functions."""
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func
from . import models

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _recent(db: Session, minutes: int = 15):
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return db.query(models.Event).filter(models.Event.timestamp >= since)


def rule_brute_force(db: Session, ev: models.Event, t: dict):
    fails = _recent(db, t.get("window_min", 10)).filter(
        models.Event.event_type == "auth_failure",
        models.Event.source_ip == ev.source_ip).count()
    if ev.event_type == "auth_failure" and ev.source_ip and fails >= t.get("failures", 5):
        return {"title": f"Brute-force authentication from {ev.source_ip}",
                "reason": f"{fails} failed authentication attempts from {ev.source_ip} "
                          f"within {t.get('window_min', 10)}m (threshold {t.get('failures', 5)}).",
                "confidence": min(0.5 + fails * 0.05, 0.95),
                "mitre": {"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"},
                "recommended_response": "Block source IP at the perimeter and review account lockout status."}
    return None


def rule_first_seen_login(db: Session, ev: models.Event, t: dict):
    if ev.event_type != "auth_success" or not ev.username:
        return None
    known = db.query(models.Event).filter(
        models.Event.username == ev.username,
        models.Event.event_type == "auth_success",
        models.Event.source_ip != "",
        models.Event.source_ip != ev.source_ip,
        models.Event.id != ev.id).first()
    first = not db.query(models.Event).filter(
        models.Event.username == ev.username, models.Event.source_ip == ev.source_ip,
        models.Event.id != ev.id).first()
    if first and known:
        return {"title": f"First-seen login for {ev.username} from {ev.source_ip}",
                "reason": f"User '{ev.username}' authenticated from {ev.source_ip}, an address "
                          f"never observed for this account; prior logins exist from other addresses.",
                "confidence": 0.6,
                "mitre": {"tactic": "Initial Access", "technique": "T1078", "name": "Valid Accounts"},
                "recommended_response": "Verify with the user; enforce MFA; monitor subsequent activity."}
    return None


def rule_impossible_travel(db: Session, ev: models.Event, t: dict):
    if ev.event_type != "auth_success" or not ev.username or not ev.source_ip:
        return None
    since = datetime.now(timezone.utc) - timedelta(hours=t.get("window_hours", 2))
    other = db.query(models.Event).filter(
        models.Event.username == ev.username, models.Event.event_type == "auth_success",
        models.Event.source_ip != ev.source_ip, models.Event.source_ip != "",
        models.Event.timestamp >= since, models.Event.id != ev.id).first()
    if other:
        return {"title": f"Impossible-travel pattern for {ev.username}",
                "reason": f"Successful logins for '{ev.username}' from both {other.source_ip} and "
                          f"{ev.source_ip} within {t.get('window_hours', 2)}h.",
                "confidence": 0.7,
                "mitre": {"tactic": "Initial Access", "technique": "T1078", "name": "Valid Accounts"},
                "recommended_response": "Confirm legitimacy with the user; revoke sessions if unconfirmed."}
    return None


def rule_privilege_change(db: Session, ev: models.Event, t: dict):
    if ev.event_type in ("privilege_escalation", "sudo", "group_added", "role_assigned"):
        return {"title": f"Privilege change on {ev.host or ev.source_ip}",
                "reason": f"Event type '{ev.event_type}' for user '{ev.username}' "
                          f"(process {ev.process or 'n/a'}).",
                "confidence": 0.65,
                "mitre": {"tactic": "Privilege Escalation", "technique": "T1078", "name": "Valid Accounts"},
                "recommended_response": "Validate the change against change-management records."}
    return None


_SUSPICIOUS_PROCS = {"mimikatz", "psexec", "nc.exe", "ncat", "powersploit", "bloodhound",
                     "rubeus", "procdump", "credential_dump"}


def rule_suspicious_process(db: Session, ev: models.Event, t: dict):
    proc = (ev.process or "").lower()
    if proc and any(bad in proc for bad in _SUSPICIOUS_PROCS):
        return {"title": f"Suspicious process execution: {ev.process}",
                "reason": f"Process '{ev.process}' matches known offensive-tooling indicators on {ev.host}.",
                "confidence": 0.85,
                "mitre": {"tactic": "Execution", "technique": "T1059", "name": "Command and Scripting Interpreter"},
                "recommended_response": "Isolate the host via the EDR integration and capture triage artifacts."}
    return None


def rule_ioc_match(db: Session, ev: models.Event, t: dict):
    if not ev.ioc_hits:
        return None
    hit = ev.ioc_hits[0]
    return {"title": f"IOC match: {hit['value']}",
            "reason": f"Event field '{hit['field']}' matched active {hit['ioc_type']} IOC "
                      f"'{hit['value']}' (confidence {hit['confidence']}, source {hit['source']}).",
            "confidence": min(hit["confidence"] / 100 + 0.2, 0.95),
            "mitre": {"tactic": "Command and Control", "technique": "T1071", "name": "Application Layer Protocol"},
            "recommended_response": "Block the indicator and scope exposure using correlated events."}


def rule_port_scan(db: Session, ev: models.Event, t: dict):
    if not ev.source_ip:
        return None
    window = t.get("window_min", 5)
    ports = {r[0] for r in _recent(db, window).filter(
        models.Event.source_ip == ev.source_ip,
        models.Event.port.isnot(None)).values(models.Event.port)}
    if len(ports) >= t.get("distinct_ports", 10):
        return {"title": f"Port-scan indicator from {ev.source_ip}",
                "reason": f"{len(ports)} distinct destination ports contacted by {ev.source_ip} "
                          f"within {window}m (threshold {t.get('distinct_ports', 10)}).",
                "confidence": 0.75,
                "mitre": {"tactic": "Discovery", "technique": "T1046", "name": "Network Service Discovery"},
                "recommended_response": "Rate-limit or block the source; review firewall denies."}
    return None


def rule_outbound_rare_port(db: Session, ev: models.Event, t: dict):
    common = {80, 443, 53, 25, 587, 993, 995, 8080}
    if ev.event_type in ("connection", "network") and ev.dest_ip and ev.port and ev.port not in common:
        return {"title": f"Outbound connection to rare port {ev.port}",
                "reason": f"{ev.host or ev.source_ip} connected to {ev.dest_ip}:{ev.port} "
                          f"(uncommon destination port).",
                "confidence": 0.55,
                "mitre": {"tactic": "Command and Control", "technique": "T1571", "name": "Non-Standard Port"},
                "recommended_response": "Identify the owning process; verify against expected baselines."}
    return None


def rule_dns_anomaly(db: Session, ev: models.Event, t: dict):
    msg = (ev.normalized.get("message") or "")
    if ev.event_type == "dns" and len(msg) > t.get("max_query_len", 80):
        return {"title": "Suspicious DNS query length",
                "reason": f"DNS query of {len(msg)} chars (threshold {t.get('max_query_len', 80)}) "
                          f"from {ev.host or ev.source_ip} — possible tunneling/encoding.",
                "confidence": 0.6,
                "mitre": {"tactic": "Command and Control", "technique": "T1071.004", "name": "DNS"},
                "recommended_response": "Inspect the full query and the requesting process."}
    return None


def rule_traffic_spike(db: Session, ev: models.Event, t: dict):
    if not ev.source_ip:
        return None
    window = t.get("window_min", 5)
    count = _recent(db, window).filter(models.Event.source_ip == ev.source_ip).count()
    if count >= t.get("events", 200):
        return {"title": f"Traffic spike from {ev.source_ip}",
                "reason": f"{count} events from {ev.source_ip} within {window}m "
                          f"(threshold {t.get('events', 200)}).",
                "confidence": 0.6,
                "mitre": {"tactic": "Impact", "technique": "T1498", "name": "Network DoS"},
                "recommended_response": "Confirm whether this is a scan, flood, or misconfigured service."}
    return None


RULES = {
    "brute_force_auth": rule_brute_force,
    "first_seen_login": rule_first_seen_login,
    "impossible_travel": rule_impossible_travel,
    "privilege_change": rule_privilege_change,
    "suspicious_process": rule_suspicious_process,
    "ioc_match": rule_ioc_match,
    "port_scan": rule_port_scan,
    "outbound_rare_port": rule_outbound_rare_port,
    "dns_anomaly": rule_dns_anomaly,
    "traffic_spike": rule_traffic_spike,
}

RULE_METADATA = {
    "brute_force_auth": ("Repeated Authentication Failures", "Detects many failed logins from one source.", "high", {"failures": 5, "window_min": 10}),
    "first_seen_login": ("First-Seen Login Source", "Login from an address never seen for the account.", "medium", {}),
    "impossible_travel": ("Impossible-Travel Authentication", "Successful logins from distant addresses in a short window.", "high", {"window_hours": 2}),
    "privilege_change": ("Privilege Change", "Privilege escalation / group membership changes.", "medium", {}),
    "suspicious_process": ("Suspicious Process Execution", "Known offensive tooling executed on a host.", "critical", {}),
    "ioc_match": ("Known Malicious IOC Match", "Event fields matched an active threat-intel indicator.", "high", {}),
    "port_scan": ("Port Scan Indicator", "Many distinct destination ports from one source.", "medium", {"distinct_ports": 10, "window_min": 5}),
    "outbound_rare_port": ("Abnormal Outbound Connection", "Outbound connection to an uncommon port.", "low", {}),
    "dns_anomaly": ("Suspicious DNS Behavior", "Over-long DNS queries suggesting tunneling.", "medium", {"max_query_len": 80}),
    "traffic_spike": ("Abnormal Traffic Spike", "Event volume spike from a single source.", "medium", {"events": 200, "window_min": 5}),
}


def seed_rules(db: Session):
    for code, (name, desc, sev, threshold) in RULE_METADATA.items():
        if not db.query(models.DetectionRule).filter(models.DetectionRule.code == code).first():
            db.add(models.DetectionRule(code=code, name=name, description=desc,
                                        severity=sev, threshold=threshold, enabled=True))
    db.commit()


def run_detection(db: Session, ev: models.Event) -> list[models.Alert]:
    alerts = []
    rules = db.query(models.DetectionRule).filter(models.DetectionRule.enabled.is_(True)).all()
    for rule in rules:
        fn = RULES.get(rule.code)
        if not fn:
            continue
        try:
            hit = fn(db, ev, rule.threshold or {})
        except Exception:
            continue  # a broken rule must never break the pipeline
        if not hit:
            continue
        asset = db.query(models.Asset).filter(
            (models.Asset.hostname == ev.host) | (models.Asset.ip == ev.source_ip)).first()
        alert = models.Alert(
            title=hit["title"], severity=rule.severity, confidence=hit.get("confidence", 0.5),
            rule_code=rule.code, reason=hit["reason"], evidence={"event_id": ev.id, "correlation_id": ev.correlation_id},
            mitre=hit.get("mitre", {}), recommended_response=hit.get("recommended_response", ""),
            asset_id=asset.id if asset else None)
        db.add(alert)
        rule.trigger_count += 1
        rule.last_triggered = datetime.now(timezone.utc)
        alerts.append(alert)
    db.commit()
    return alerts


def test_rule(db: Session, code: str, sample: dict) -> dict:
    """Run one rule against a sample event payload without persisting."""
    from .pipeline import normalize, correlation_key
    normalized, err = normalize(sample)
    fake = models.Event(id=-1, timestamp=datetime.now(timezone.utc), correlation_id=correlation_key(normalized),
                        ioc_hits=[], normalized=normalized,
                        event_type=normalized.get("event_type", ""), source_ip=normalized.get("source_ip", ""),
                        dest_ip=normalized.get("dest_ip", ""), host=normalized.get("host", ""),
                        username=normalized.get("username", ""), process=normalized.get("process", ""),
                        port=normalized.get("port"))
    rule = db.query(models.DetectionRule).filter(models.DetectionRule.code == code).first()
    if not rule:
        return {"matched": False, "error": "rule not found"}
    fn = RULES.get(code)
    if not fn:
        return {"matched": False, "error": "rule function not registered"}
    hit = fn(db, fake, rule.threshold or {})
    return {"matched": bool(hit), "parse_error": err, "result": hit or {}}
