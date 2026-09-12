from .conftest import ingest


def _run(client, auth, events):
    for e in events:
        ingest(client, auth, **e)


def test_brute_force_alert(client, analyst):
    for i in range(6):
        ingest(client, analyst, source_ip="203.0.113.9", username="root",
               event_type="auth_failure")
    alerts = client.get("/api/v1/alerts?severity=high", headers=analyst).json()
    bf = [a for a in alerts if a["rule_code"] == "brute_force_auth"]
    assert bf and "203.0.113.9" in bf[0]["reason"]
    assert bf[0]["mitre"]["technique"] == "T1110"


def test_suspicious_process_alert(client, analyst):
    ingest(client, analyst, host="wkstn-1", process="/tmp/mimikatz.exe", event_type="process")
    alerts = client.get("/api/v1/alerts", headers=analyst).json()
    assert any(a["rule_code"] == "suspicious_process" for a in alerts)


def test_port_scan_alert(client, analyst):
    for p in range(20, 40):
        ingest(client, analyst, source_ip="192.0.2.1", dest_ip="10.0.0.2",
               event_type="connection", port=p, protocol="tcp")
    alerts = client.get("/api/v1/alerts", headers=analyst).json()
    assert any(a["rule_code"] == "port_scan" for a in alerts)


def test_ioc_match_alert(client, analyst):
    client.post("/api/v1/iocs", json={"type": "ip", "value": "185.220.101.4", "confidence": 95},
                headers=analyst)
    ingest(client, analyst, dest_ip="185.220.101.4", event_type="connection", port=4444)
    alerts = client.get("/api/v1/alerts", headers=analyst).json()
    assert any(a["rule_code"] == "ioc_match" for a in alerts)


def test_rule_disable_stops_detection(client, admin, analyst):
    client.patch("/api/v1/rules/brute_force_auth", json={"enabled": False}, headers=admin)
    for _ in range(8):
        ingest(client, analyst, source_ip="203.0.113.9", username="root", event_type="auth_failure")
    alerts = client.get("/api/v1/alerts", headers=analyst).json()
    assert not any(a["rule_code"] == "brute_force_auth" for a in alerts)


def test_rule_test_endpoint(client, analyst):
    r = client.post("/api/v1/rules/brute_force_auth/test",
                    json={"source_ip": "1.2.3.4", "username": "root", "event_type": "auth_failure"},
                    headers=analyst)
    assert r.status_code == 200
    assert "matched" in r.json()


def test_rule_threshold_update(client, admin):
    client.patch("/api/v1/rules/brute_force_auth",
                 json={"threshold": {"failures": 2, "window_min": 10}}, headers=admin)
    rules = client.get("/api/v1/rules", headers=admin).json()
    rule = [r for r in rules if r["code"] == "brute_force_auth"][0]
    assert rule["threshold"]["failures"] == 2
