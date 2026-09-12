"""End-to-end: ingest → detect → alert → incident → AI analysis →
   response recommendation → approval → execution → audit."""


def test_full_workflow(client, admin, analyst):
    # 1-4: ingest brute-force traffic → detection → alert
    for _ in range(8):
        client.post("/api/v1/events", json={
            "source": "e2e-sensor", "host": "srv-auth-01", "source_ip": "198.51.100.66",
            "username": "admin", "event_type": "auth_failure"}, headers=analyst)
    alerts = [a for a in client.get("/api/v1/alerts", headers=analyst).json()
              if a["rule_code"] == "brute_force_auth"]
    assert alerts, "expected brute-force alert"
    alert = alerts[0]
    assert alert["severity"] == "high"

    # 5-6: create incident from the alert evidence, link correlated events
    inc = client.post("/api/v1/incidents", json={
        "title": alert["title"], "severity": alert["severity"],
        "confidence": alert["confidence"], "summary": alert["reason"]}, headers=analyst).json()
    ev_id = alert["evidence"]["event_id"]
    assert client.post(f"/api/v1/incidents/{inc['id']}/link-event/{ev_id}",
                       headers=analyst).status_code == 200
    got = client.get(f"/api/v1/incidents/{inc['id']}", headers=analyst).json()
    assert len(got["events"]) == 1

    # 7: AI analysis (heuristic fallback — no provider configured in tests)
    analysis = client.post(f"/api/v1/ai/analyze-incident/{inc['id']}", headers=analyst).json()
    assert analysis["observed"] and analysis["inferred"] and analysis["unknown"]
    assert analysis["ai_available"] is False  # honestly reported

    # 8-11: response recommendation → approval → execution → audit
    act = client.post("/api/v1/response/actions", json={
        "action_type": "block_ip", "target": "198.51.100.66",
        "reason": "brute-force source confirmed by detection rule", "alert_id": alert["id"],
        "incident_id": inc["id"], "dry_run": False}, headers=analyst).json()
    assert act["status"] == "pending"  # default policy mode = approval
    done = client.post(f"/api/v1/response/actions/{act['id']}/approve", headers=analyst).json()
    assert done["status"] == "executed"

    # blocklist effect is real: the IOC now exists and is active
    iocs = client.get("/api/v1/iocs?type=ip", headers=analyst).json()
    assert any(i["value"] == "198.51.100.66" and i["active"] for i in iocs)

    logs = client.get("/api/v1/auth/audit", headers=admin).json()
    actions = {l["action"] for l in logs}
    assert {"incident.create", "ai.analyze", "response.approve", "response.execute"} <= actions


def test_dry_run_changes_nothing(client, analyst):
    act = client.post("/api/v1/response/actions", json={
        "action_type": "block_ip", "target": "10.9.9.9", "reason": "test dry run",
        "dry_run": True}, headers=analyst).json()
    done = client.post(f"/api/v1/response/actions/{act['id']}/approve", headers=analyst).json()
    assert done["status"] == "dry_run"
    iocs = client.get("/api/v1/iocs", headers=analyst).json()
    assert not any(i["value"] == "10.9.9.9" for i in iocs)


def test_edr_action_unavailable_without_integration(client, analyst):
    act = client.post("/api/v1/response/actions", json={
        "action_type": "isolate_host", "target": "wkstn-1",
        "reason": "suspicious process detected", "dry_run": False}, headers=analyst).json()
    done = client.post(f"/api/v1/response/actions/{act['id']}/approve", headers=analyst).json()
    assert done["status"] == "unavailable"  # honest, not fake success


def test_reject_action(client, analyst):
    act = client.post("/api/v1/response/actions", json={
        "action_type": "block_ip", "target": "10.1.1.1", "reason": "check first"},
        headers=analyst).json()
    r = client.post(f"/api/v1/response/actions/{act['id']}/reject",
                    json={"reason": "false positive"}, headers=analyst)
    assert r.json()["status"] == "rejected"
