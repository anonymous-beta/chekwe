from .conftest import ingest


def test_manual_incident_lifecycle(client, analyst):
    r = client.post("/api/v1/incidents",
                    json={"title": "Test", "severity": "high"}, headers=analyst)
    inc_id = r.json()["id"]
    for status in ["triaged", "investigating", "contained", "remediating", "resolved", "closed"]:
        r = client.patch(f"/api/v1/incidents/{inc_id}/status", json={"status": status},
                         headers=analyst)
        assert r.status_code == 200
    logs = client.get("/api/v1/auth/audit", headers=analyst).json()
    assert sum(1 for l in logs if l["action"] == "incident.status") == 6


def test_viewer_cannot_change_status(client, viewer):
    r = client.post("/api/v1/incidents", json={"title": "T"}, headers=viewer)
    assert r.status_code == 403


def test_notes_append(client, analyst):
    r = client.post("/api/v1/incidents", json={"title": "T"}, headers=analyst)
    iid = r.json()["id"]
    client.post(f"/api/v1/incidents/{iid}/notes", json={"body": "checked firewall"}, headers=analyst)
    inc = client.get(f"/api/v1/incidents/{iid}", headers=analyst).json()
    assert inc["ai_analysis"]["notes"][0]["body"] == "checked firewall"


def test_alert_acknowledge_and_resolve(client, analyst):
    ingest(client, analyst, source_ip="203.0.113.9", username="root", event_type="auth_failure")
    ingest(client, analyst, source_ip="203.0.113.9", username="root", event_type="auth_failure")
    alerts = client.get("/api/v1/alerts", headers=analyst).json()
    aid = alerts[0]["id"]
    r = client.patch(f"/api/v1/alerts/{aid}", json={"status": "acknowledged"}, headers=analyst)
    assert r.json()["status"] == "acknowledged"
    r = client.patch(f"/api/v1/alerts/{aid}", json={"status": "resolved"}, headers=analyst)
    assert r.json()["status"] == "resolved"
