import socket
import sys
import time

import httpx
import pytest
import yaml

import app.main as rdrs_main
from app.api import simulator as simmod
from app.core import logger as logmod
from app.core.config import ConfigError, load_config
from app.database.db import AlertRow, IncidentRow
from app.detectors.engine import DetectionEngine
from app.detectors.response import IncidentResponder


def test_config_errors_and_env(tmp_path, monkeypatch):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("watch_paths: []\n")
    with pytest.raises(ConfigError):
        load_config(bad)
    monkeypatch.setenv("RDRS_API_HOST", "0.0.0.0")
    monkeypatch.setenv("RDRS_API_PORT", "9999")
    monkeypatch.setenv("RDRS_WATCH_PATHS", "a, b")
    c = load_config("config.yaml")
    assert c["api"] == {"enabled": True, "host": "0.0.0.0", "port": 9999} and c["watch_paths"] == ["a", "b"]


def test_logger_channels(tmp_path, monkeypatch):
    monkeypatch.setattr(logmod, "_configured", False)
    logmod.setup_logging(tmp_path / "lg")
    logmod.setup_logging(tmp_path / "lg")  # idempotent
    logmod.get_logger("alerts").warning("ALERT-LINE")
    logmod.get_logger("events").info("EVENT-LINE")
    logmod.get_logger("system").error("ERR-LINE")
    assert "ALERT-LINE" in (tmp_path / "lg" / "alerts.log").read_text()
    assert "ALERT-LINE" not in (tmp_path / "lg" / "system.log").read_text()
    assert "EVENT-LINE" in (tmp_path / "lg" / "events.log").read_text()
    assert "ERR-LINE" in (tmp_path / "lg" / "errors.log").read_text()


def test_simulator(tmp_path, monkeypatch):
    sandbox = tmp_path / "sb"
    sandbox.mkdir()
    for n in ("a.txt", "b.locked", ".gitkeep"):
        (sandbox / n).write_text("x")
    monkeypatch.setattr(simmod, "SANDBOX", sandbox)
    sim = simmod.Simulator()
    assert sim.running is False and sim.start("hack") is False
    assert sim.reset() == 2 and (sandbox / ".gitkeep").exists()

    class Proc:
        def poll(self):
            return None

    monkeypatch.setattr(simmod.subprocess, "Popen", lambda *a, **k: Proc())
    assert sim.start("normal") is True and sim.running is True
    assert sim.start("attack") is False and sim.reset() == -1


def test_main_runs_and_stops_cleanly(cfg, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(logmod, "_configured", False)
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setattr(sys, "argv", ["rdrs", "--config", str(path), "--no-api"])
    calls = {"n": 0}

    def fake_sleep(_):
        calls["n"] += 1
        if calls["n"] >= 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(rdrs_main.time, "sleep", fake_sleep)
    rdrs_main.main()
    out = capsys.readouterr().out
    assert "Watching" in out and "Level:" in out and "Stopping" in out


def test_start_api_serves_health(cfg, db):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    cfg["api"].update(enabled=True, port=port)
    engine = DetectionEngine(cfg, db)
    server = rdrs_main.start_api(cfg, db, engine)
    try:
        for _ in range(50):
            try:
                assert httpx.get(f"http://127.0.0.1:{port}/health").json()["status"] == "ok"
                break
            except httpx.TransportError:
                time.sleep(0.1)
        else:
            pytest.fail("API did not start")
    finally:
        server.should_exit = True
    cfg["api"]["enabled"] = False
    assert rdrs_main.start_api(cfg, db, engine) is None


def test_responder_extra_paths(cfg, db, tmp_path):
    cfg["response"].update(terminate_process=True, max_evidence_file_mb=0)
    resp = IncidentResponder(cfg, db, extend_interval=0)
    big = tmp_path / "w" / "big.locked"
    big.write_bytes(b"x" * 10)
    from app.core.scoring import ScoreResult

    res = ScoreResult(90, "Critical", {"rapid_encryption": {"points": 40, "reason": "r"}})
    from datetime import datetime

    from app.database.db import ProcessRow

    suspect = ProcessRow(
        pid=5,
        name="x.exe",
        exe="x",
        parent_pid=1,
        cpu_percent=1,
        memory_mb=1,
        write_bytes=0,
        write_delta=1,
        timestamp=datetime.now(),
    )
    assert resp.handle(res, {"not": "dataclass"}, [str(big), str(tmp_path / "ghost.locked")], suspect, None) == 1
    assert resp.handle(res, None, [str(big)], suspect, None) is None  # cooldown
    resp.reset()
    assert resp._cur is None


def test_db_helpers(db):
    db.update_incident(999, score=1)  # missing id is ignored
    row = db.save_incident(score=10, suspect_process="null", affected_files="[]", evidence_dir="d", summary="{}")
    db.update_incident(row.id, score=99)
    assert db.count(IncidentRow) == 1 and db.count(AlertRow) == 0
    with db.session() as s:
        assert s.get(IncidentRow, row.id).score == 99


def test_engine_throttle_and_delete(cfg, db):
    from datetime import datetime

    from app.core.models import FileEvent

    eng = DetectionEngine(cfg, db, min_eval_interval=999)
    now = datetime.now()
    eng.on_event(FileEvent("created", "a.txt", ".txt", now, entropy=4.0))
    eng.on_event(FileEvent("deleted", "a.txt", ".txt", now))
    assert eng.compute_metrics().samples == 0
