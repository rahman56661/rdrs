import os
import time
from datetime import datetime
from pathlib import Path

from watchdog.events import DirMovedEvent, FileCreatedEvent, FileDeletedEvent, FileModifiedEvent, FileMovedEvent

from app.core.models import FileEvent
from app.database.db import ProcessRow
from app.detectors import process_monitor as pm
from app.detectors.file_monitor import FileMonitor, _Handler
from app.detectors.process_monitor import ProcessMonitor, _near_watch, pick_suspect, take_snapshot


def _handler(cfg, sink):
    return _Handler([sink.append], cfg)


def test_handler_builds_events(cfg, tmp_path):
    got: list[FileEvent] = []
    h = _handler(cfg, got)
    f = tmp_path / "w" / "a.txt"
    f.write_text("hello hello hello")
    h.on_created(FileCreatedEvent(str(f)))
    h.on_modified(FileModifiedEvent(str(f)))
    new = f.with_suffix(".locked")
    f.rename(new)
    h.on_moved(FileMovedEvent(str(f), str(new)))
    h.on_deleted(FileDeletedEvent(str(new)))
    assert [e.event_type for e in got] == ["created", "modified", "moved", "deleted"]
    assert got[2].old_extension == ".txt" and got[2].extension == ".locked" and got[2].entropy is not None
    assert got[3].entropy is None


def test_handler_ignores_directories_and_survives_bad_callback(cfg, tmp_path):
    got: list[FileEvent] = []

    def bad(_):
        raise RuntimeError("boom")

    h = _Handler([bad, got.append], cfg)
    h.on_moved(DirMovedEvent(str(tmp_path), str(tmp_path / "x")))
    assert got == []
    f = tmp_path / "w" / "z.zip"
    f.write_bytes(os.urandom(100))
    h.on_created(FileCreatedEvent(str(f)))
    assert got and got[0].expected_high_entropy  # second callback still ran


def test_real_observer_sees_files(cfg, tmp_path):
    got: list[FileEvent] = []
    mon = FileMonitor(cfg["watch_paths"], cfg, [got.append])
    mon.start()
    try:
        (tmp_path / "w" / "live.txt").write_text("data")
        for _ in range(50):
            if got:
                break
            time.sleep(0.1)
    finally:
        mon.stop()
    assert any(e.path.endswith("live.txt") for e in got)


def test_snapshot_and_suspect():
    rows = take_snapshot(5, [Path.cwd()])
    assert 0 < len(rows) and all(isinstance(r, ProcessRow) for r in rows)
    mine = [r for r in rows if r.pid == os.getpid()]
    assert not mine or getattr(mine[0], "near_watch", False)
    assert pick_suspect(rows, set(), own_pid=os.getpid()) is None or isinstance(
        pick_suspect(rows, set(), own_pid=os.getpid()), ProcessRow)


def test_near_watch_rules(tmp_path):
    import psutil

    p = psutil.Process()
    assert _near_watch(p, [Path.cwd() / "data" / "sandbox"]) is True  # cwd is an ancestor of the sandbox
    assert _near_watch(p, [tmp_path / "elsewhere"]) is False


def test_process_monitor_thread_saves_rows(db):
    mon = ProcessMonitor(db, interval=0.05, top_n=3, watch_paths=["."])
    mon.start()
    deadline = time.time() + 30          # Windows needs a while to snapshot every process
    while not mon.latest and time.time() < deadline:
        time.sleep(0.1)
    mon.stop()
    mon.join(timeout=2)
    assert mon.latest and db.count(ProcessRow) > 0


def test_snapshot_tolerates_access_denied(monkeypatch):
    import psutil

    class Bad:
        pid = 1

        def oneshot(self):
            raise psutil.AccessDenied(1)

    monkeypatch.setattr(pm.psutil, "process_iter", lambda: [Bad()])
    assert take_snapshot() == []


def test_pick_suspect_handles_nothing_active():
    r = ProcessRow(
        pid=1, name="idle", cpu_percent=0, write_delta=0, memory_mb=1, write_bytes=0, timestamp=datetime.now()
    )
    assert pick_suspect([r], set(), own_pid=99) is None
