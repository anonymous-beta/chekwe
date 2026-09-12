from .conftest import ingest


def test_event_ingested_and_normalized(client, analyst):
    r = ingest(client, analyst, source="test", host="h1", source_ip="10.0.0.1",
               event_type="auth_failure", raw={"src_ip": "10.0.0.1"})
    assert r.status_code == 201
    ev = r.json()["event"]
    assert ev["source_ip"] == "10.0.0.1"  # alias mapping worked
    assert ev["correlation_id"]


def test_malformed_event_not_discarded(client, analyst):
    r = ingest(client, analyst, source="test", raw={"timestamp": "not-a-date", "port": "abc"})
    assert r.status_code == 201
    ev = r.json()["event"]
    assert ev["parse_error"]


def test_asset_auto_created(client, analyst):
    ingest(client, analyst, host="srv-01", source_ip="10.0.0.5")
    assets = client.get("/api/v1/assets", headers=analyst).json()
    assert any(a["hostname"] == "srv-01" for a in assets)


def test_ioc_enrichment(client, analyst):
    client.post("/api/v1/iocs", json={"type": "ip", "value": "6.6.6.6", "confidence": 90},
                headers=analyst)
    r = ingest(client, analyst, dest_ip="6.6.6.6", event_type="connection", port=4444)
    assert r.json()["event"]["ioc_hits"]


def test_event_filters(client, analyst):
    ingest(client, analyst, source="a", event_type="auth_failure", severity="high")
    ingest(client, analyst, source="b", event_type="dns", severity="info")
    r = client.get("/api/v1/events?event_type=auth_failure", headers=analyst)
    assert all(e["event_type"] == "auth_failure" for e in r.json()["events"])


def test_demo_mode_flagged_synthetic(client, analyst):
    r = client.post("/api/v1/demo/generate?scenario=brute_force", headers=analyst)
    assert r.status_code == 201
    assert r.json()["synthetic"] is True
    evs = client.get("/api/v1/events?synthetic=true", headers=analyst).json()["events"]
    assert len(evs) >= 8
