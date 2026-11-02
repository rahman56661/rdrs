"""Periodic process snapshots using psutil, plus suspect-process selection."""

from __future__ import annotations

import os
import threading
from datetime import datetime
from pathlib import Path

import psutil

from app.core.logger import get_logger
from app.database.db import Database, ProcessRow

_prev_writes: dict[int, int] = {}
_CORES = psutil.cpu_count() or 1


def _near_watch(p: psutil.Process, watch_dirs: list[Path]) -> bool:
    """True if the process runs from (or inside) a watched folder - strong attribution hint."""
    try:
        cwd = Path(p.cwd()).resolve()
    except (psutil.Error, OSError):
        return False
    return len(cwd.parts) >= 3 and any(d == cwd or cwd in d.parents or d in cwd.parents for d in watch_dirs)


def take_snapshot(top_n: int = 10, watch_dirs: list[Path] | None = None) -> list[ProcessRow]:
    """Snapshot the ``top_n`` most active processes plus any process working near the watched folders."""
    watch_dirs = watch_dirs or []
    now, rows = datetime.now(), []
    for p in psutil.process_iter():
        try:
            with p.oneshot():
                io = p.io_counters() if hasattr(p, "io_counters") else None
                written = io.write_bytes if io else 0
                rows.append(
                    ProcessRow(
                        timestamp=now,
                        pid=p.pid,
                        name=p.name(),
                        exe=p.exe() or None,
                        parent_pid=p.ppid(),
                        cpu_percent=round(p.cpu_percent(None) / _CORES, 1),  # % of TOTAL cpu (0-100)
                        memory_mb=p.memory_info().rss / 1_048_576,
                        write_bytes=written,
                        write_delta=max(0, written - _prev_writes.get(p.pid, written)),
                    )
                )
                _prev_writes[p.pid] = written
                rows[-1].near_watch = _near_watch(p, watch_dirs)  # live-only flag (not stored in DB)
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            continue  # protected / vanished process - ignore gracefully
    rows.sort(key=lambda r: (r.write_delta, r.cpu_percent), reverse=True)
    return rows[:top_n] + [r for r in rows[top_n:] if getattr(r, "near_watch", False)]


def pick_suspect(rows: list[ProcessRow], trusted: set[str], own_pid: int | None = None) -> ProcessRow | None:
    """Best-guess culprit (heuristic, not proof): processes running near the watched folder rank first,
    then untrusted programs, then by disk writes / CPU. RDRS itself is excluded."""
    own_pid = os.getpid() if own_pid is None else own_pid
    active = [r for r in rows if r.pid != own_pid and (r.write_delta > 0 or r.cpu_percent > 0)]
    return max(
        active,
        key=lambda r: (getattr(r, "near_watch", False), r.name.lower() not in trusted, r.write_delta, r.cpu_percent),
        default=None,
    )


class ProcessMonitor(threading.Thread):
    """Background thread that stores a process snapshot every N seconds."""

    def __init__(
        self, db: Database, interval: float = 2, top_n: int = 10, watch_paths: list[str] | None = None
    ) -> None:
        super().__init__(daemon=True, name="process-monitor")
        self.db, self.interval, self.top_n = db, interval, top_n
        self.watch_dirs = [Path(p).resolve() for p in (watch_paths or [])]
        self._stop_evt = threading.Event()
        self.latest: list[ProcessRow] = []

    def run(self) -> None:
        psutil.cpu_percent(None)
        take_snapshot(self.top_n, self.watch_dirs)  # prime CPU + write counters
        while not self._stop_evt.wait(self.interval):
            try:
                self.latest = take_snapshot(self.top_n, self.watch_dirs)
                self.db.save_processes(self.latest)
            except Exception as exc:
                get_logger("errors").exception(f"process snapshot failed: {exc}")

    def stop(self) -> None:
        self._stop_evt.set()
