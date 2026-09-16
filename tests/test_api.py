import json

import pytest
from fastapi.testclient import TestClient

from vigil.api import create_app
from vigil.runtime import Runtime


@pytest.fixture()
def client(detector, env, tmp_path):
    runtime = Runtime(detector, env, speed=60, feedback_path=tmp_path / "feedback.jsonl")
    with TestClient(create_app(runtime, start_loop=False)) as c:
        c.runtime = runtime
        c.feedback = tmp_path / "feedback.jsonl"
        yield c


def advance(runtime, sim_seconds, step=30.0):
    """Drive the engine without the background loop."""
    for _ in range(int(sim_seconds / step)):
        runtime.step(step / runtime.speed)


def test_health_and_catalog(client):
    assert client.get("/api/health").json()["status"] == "ok"
    ids = {s["id"] for s in client.get("/api/scenarios").json()}
    assert {"intrusion_chain", "benign_noise", "dns_tunnel"} <= ids


def test_unknown_resources_are_404(client):
    assert client.get("/api/alerts/AL-99999").status_code == 404
    assert client.get("/api/incidents/IN-9999").status_code == 404
    assert client.post("/api/simulations", json={"scenario": "nope"}).status_code == 404
    assert client.post("/api/simulations/RUN-999/stop").status_code == 404


def test_validation(client):
    assert client.patch("/api/settings", json={"speed": 0}).status_code == 422
    assert client.post("/api/simulations", json={"scenario": "c2_exfil", "intensity": 9}).status_code == 422
    assert client.patch("/api/alerts/AL-00001", json={"status": "deleted"}).status_code == 422


def test_simulation_flow_and_feedback(client):
    run = client.post("/api/simulations", json={"scenario": "credential_stuffing"}).json()
    assert run["status"] == "running" and run["total_events"] > 0
    advance(client.runtime, 15 * 60)
    run = next(r for r in client.get("/api/simulations").json() if r["id"] == run["id"])
    assert run["status"] == "completed"
    assert run["detected"] is True

    alerts = client.get("/api/alerts", params={"threat": "brute_force"}).json()
    assert alerts
    detail = client.get(f"/api/alerts/{alerts[0]['id']}").json()
    assert detail["explanation"] and detail["playbook"]["contain"]

    updated = client.patch(f"/api/alerts/{detail['id']}", json={"status": "false_positive", "note": "test"}).json()
    assert updated["status"] == "false_positive"
    record = json.loads(client.feedback.read_text().splitlines()[-1])
    assert record["alert_id"] == detail["id"] and record["status"] == "false_positive"

    overview = client.get("/api/overview").json()
    assert overview["events_total"] > 0 and overview["series"]


def test_stop_and_reset(client):
    run = client.post("/api/simulations", json={"scenario": "low_and_slow"}).json()
    stopped = client.post(f"/api/simulations/{run['id']}/stop").json()
    assert stopped["status"] == "stopped"
    assert all(item[2].campaign != run["campaign_id"] for item in client.runtime.pending)
    assert client.post("/api/reset").json() == {"status": "reset"}
    assert client.get("/api/simulations").json() == []


def test_ingest_accepts_raw_events(client):
    body = [{"layer": "endpoint", "kind": "auth", "src_ip": "10.20.0.10", "dst_ip": "10.10.0.10",
             "dst_port": 88, "user": "x", "outcome": "failure"}]
    assert client.post("/api/ingest", json=body).json() == {"accepted": 1}
    bad = [{"layer": "kernel", "kind": "auth", "src_ip": "a", "dst_ip": "b"}]
    assert client.post("/api/ingest", json=bad).status_code == 422
