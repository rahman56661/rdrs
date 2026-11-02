"""Integration tests: fake event bursts through engine -> score -> incident."""

import os
from datetime import datetime
from pathlib import Path

import pytest

from app.core.config import load_config
from app.core.entropy import file_entropy
from app.core.models import FileEvent
from app.core.scoring import CRITICAL, NORMAL
from app.database.db import AlertRow, Database, IncidentRow, ProcessRow
from app.detectors.engine import DetectionEngine
from app.detectors.process_monitor import pick_suspect
from app.detectors.response import IncidentResponder


@pytest.fixture()
def env(tmp_path):
    cfg = load_config("config.yaml")
    cfg["response"]["quarantine_dir"] = str(tmp_path / "quarantine")
    db = Database(tmp_path / "t.db")
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    engine = DetectionEngine(cfg, db, responder=IncidentResponder(cfg, db, extend_interval=0), min_eval_interval=0)
    return cfg, db, engine, sandbox, tmp_path


def make_event(kind, path, dest=None, **kw):
    final = dest or path
    return FileEvent(
        kind,
        str(path),
        Path(final).suffix,
        datetime.now(),
        str(dest) if dest else None,
        Path(path).suffix if dest else None,
        kw.get("entropy"),
        kw.get("safe", False),
    )


def test_attack_burst_creates_critical_incident_and_evidence(env):
    _, db, engine, sandbox, _ = env
    originals = {}
    for i in range(30):
        f = sandbox / f"f{i}.txt"
        f.write_text("normal text " * 50)
        engine.on_event(make_event("created", f, entropy=file_entropy(f)))
        f.write_bytes(os.urandom(5000))
        new = f.with_suffix(".locked")
        f.rename(new)
        originals[new] = new.read_bytes()
        engine.on_event(make_event("moved", f, new, entropy=file_entropy(new)))
    assert engine.last_result.level == CRITICAL
    with db.session() as s:
        incidents = s.query(IncidentRow).all()
        assert len(incidents) == 1  # cooldown: one incident per attack
        assert s.query(AlertRow).count() >= 1
    evidence = list(Path(incidents[0].evidence_dir).glob("*.locked"))
    assert evidence  # evidence copied
    assert all(p.read_bytes() == b for p, b in originals.items())  # originals untouched
    import json

    assert len(json.loads(incidents[0].affected_files)) == 30  # incident kept growing with the attack


def test_normal_activity_stays_normal(env):
    _, _, engine, sandbox, _ = env
    for i in range(60):
        f = sandbox / f"n{i}.txt"
        f.write_text("just editing documents " * 30)
        engine.on_event(make_event("modified", f, entropy=file_entropy(f)))
    assert engine.last_result.level == NORMAL


def test_zip_files_are_not_false_positives(env):
    _, _, engine, sandbox, _ = env
    for i in range(60):
        f = sandbox / f"b{i}.zip"
        f.write_bytes(os.urandom(5000))
        engine.on_event(make_event("created", f, entropy=file_entropy(f), safe=True))
    assert engine.last_result.level == NORMAL


def test_quarantine_events_are_ignored(env):
    _, _, engine, _, tmp = env
    q = tmp / "quarantine" / "x.bin"
    engine.on_event(make_event("created", q, entropy=7.9))
    assert engine.last_metrics.samples == 0


def test_pick_suspect_prefers_untrusted_and_skips_self():
    rows = [_row(1, "svchost.exe", False, 900), _row(2, "evil.exe", False, 100), _row(3, "rdrs.exe", False, 9999)]
    assert pick_suspect(rows, {"svchost.exe"}, own_pid=3).name == "evil.exe"
    assert pick_suspect([], set()) is None


def test_stale_tail_does_not_raise_new_alert(env):
    """Old high-entropy files lingering in the window must not score once activity has stopped."""
    from app.detectors.engine import Metrics, evaluate_signals

    _, _, engine, _, _ = env
    m = Metrics(high_entropy_files=6, avg_entropy=7.9, samples=6, max_cpu=95, recent_events=0)
    fired = [s.name for s in evaluate_signals(m, engine.th, False) if s.fired]
    assert fired == []
    m.recent_events = 3
    names = {s.name for s in evaluate_signals(m, engine.th, False) if s.fired}
    assert {"high_entropy", "cpu_spike", "unknown_program"} <= names


def test_engine_reset_and_history(env):
    _, _, engine, sandbox, _ = env
    f = sandbox / "a.txt"
    f.write_text("x" * 100)
    engine.on_event(make_event("created", f, entropy=3.0))
    engine.tick()
    assert len(engine.history) == 1
    engine.reset()
    assert engine.last_metrics.samples == 0 and engine.last_result.level == NORMAL


def test_pick_suspect_prefers_process_near_watch_folder():
    rows = [_row(1, "mongod.exe", False, 5000), _row(2, "python.exe", True, 10)]
    assert pick_suspect(rows, set(), own_pid=99).name == "python.exe"


def _row(pid, name, near, wd):
    r = ProcessRow(
        pid=pid, name=name, cpu_percent=1, write_delta=wd, memory_mb=1, write_bytes=0, timestamp=datetime.now()
    )
    r.near_watch = near
    return r
