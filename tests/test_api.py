import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.detectors.engine import DetectionEngine
from app.detectors.response import IncidentResponder


class FakeSim:
    running = False
    started = None

    def start(self, mode):
        self.started = mode
        return True

    def reset(self):
        return -1 if self.running else 3


@pytest.fixture()
def client(cfg, db, tmp_path):
    (tmp_path / "w" / "a.txt").write_text("hello")
    eng = DetectionEngine(cfg, db, responder=IncidentResponder(cfg, db), min_eval_interval=0)
    sim = FakeSim()
    c = TestClient(create_app(cfg, db, eng, sim))
    c.sim, c.engine = sim, eng
    return c


def test_health_and_status(client):
    assert client.get("/health").json()["status"] == "ok"
    s = client.get("/status").json()
    assert s["level"] == "Normal" and s["simulation_mode"] is True and "levels" in s


def test_lists_are_json_lists(client):
    for p in ("/alerts", "/events", "/incidents", "/scores", "/reports", "/top-files", "/history"):
        assert client.get(p).json() == []


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "RDRS" in r.text and "innerHTML" not in r.text.replace("never innerHTML", "")


def test_settings_update_and_validation(client):
    assert client.post("/settings", json={"thresholds": {"cpu_percent": 55}}).json()["thresholds"]["cpu_percent"] == 55
    assert client.post("/settings", json={"thresholds": {"bogus": 1}}).status_code == 422
    assert client.post("/settings", json={"levels": {"warning": 90, "critical": 80}}).status_code == 422
    assert client.post("/settings", json={"weights": {"mass_rename": -1}}).status_code == 422


def test_scan_finds_only_encrypted_looking_files(client, tmp_path):
    import os

    (tmp_path / "w" / "x.locked").write_bytes(os.urandom(5000))
    (tmp_path / "w" / "ok.zip").write_bytes(os.urandom(5000))  # expected high entropy
    r = client.post("/scan").json()
    assert r["scanned"] == 3 and r["suspicious_count"] == 1


def test_simulate_endpoints(client):
    assert client.post("/simulate/attack").json() == {"started": "attack"}
    assert client.post("/simulate/hack").status_code == 422
    assert client.post("/simulate/reset").json() == {"removed_files": 3}


def test_status_without_engine_uses_db(cfg, db):
    db.save_score(55, "Warning", "{}")
    c = TestClient(create_app(cfg, db, None, FakeSim()))
    s = c.get("/status").json()
    assert s["level"] == "Warning" and s["score"] == 55
    assert c.get("/settings").json()["levels"]["critical"] == 70
    assert c.post("/settings", json={"weights": {"mass_rename": 31}}).json()["weights"]["mass_rename"] == 31
    assert c.get("/history").json() == []


def test_data_endpoints_return_rows(client, db, incident):
    db.save_alert("Warning", 45, "msg", "{}")
    assert client.get("/alerts").json()[0]["message"] == "msg"
    assert client.get("/incidents").json()[0]["suspect_process"]["name"] == "evil.exe"
    assert len(client.get("/events?limit=3").json()) == 3
    from datetime import datetime

    from app.core.models import FileEvent

    db.save_event(FileEvent("modified", "hot.txt", ".txt", datetime.now(), entropy=3.0))
    assert client.get("/top-files").json()[0]["path"] == "hot.txt"
    assert client.get("/scores").json() == []
    assert client.get("/status").json()["counts"]["incidents"] == 1


def test_report_generation_and_download(client, incident):
    r = client.post(f"/reports/{incident.id}").json()
    assert {"json", "csv", "html"} <= {f.split(".")[-1] for f in r["files"]}
    assert client.get(f"/reports/download/incident_{incident.id}.json").status_code == 200
    assert client.get("/reports/download/../../config.yaml").status_code in (404, 422)
    assert client.get("/reports/download/nope.json").status_code == 404
    assert client.post("/reports/9999").status_code == 404
    assert client.get("/reports").json()[0]["report_files"]


def test_simulator_busy_returns_409(client):
    client.sim.running = True
    assert client.post("/simulate/reset").status_code == 409
    client.sim.running = False


def test_default_app_factory(cfg, monkeypatch):
    import app.api.main as api

    monkeypatch.setattr(api, "load_config", lambda *a, **k: cfg)
    assert TestClient(api.create_default_app()).get("/health").status_code == 200
