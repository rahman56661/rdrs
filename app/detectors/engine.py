"""Detection engine: sliding window -> signals -> score -> response."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from app.core.logger import get_logger
from app.core.models import FileEvent
from app.core.scoring import CRITICAL, NORMAL, WARNING, ScoreResult, Signal, compute_score
from app.database.db import Database, ProcessRow
from app.detectors.process_monitor import pick_suspect

log = get_logger("system")
_RANK = {NORMAL: 0, WARNING: 1, CRITICAL: 2}


@dataclass(slots=True)
class Metrics:
    """Numbers computed over the sliding window."""

    files_modified_per_min: int = 0
    renames: int = 0
    extension_changes: int = 0
    high_entropy_files: int = 0
    avg_entropy: float = 0.0
    samples: int = 0
    max_cpu: float = 0.0
    recent_events: int = 0


def evaluate_signals(m: Metrics, th: dict, trusted_suspect: bool | None) -> list[Signal]:
    """Turn window metrics into signals (pure function, easy to unit-test).

    ``trusted_suspect``: True/False if a suspect process exists, None if unknown.
    CPU / unknown-program only count when file activity is already suspicious,
    so ordinary busy programs do not add noise.
    """
    rapid = m.high_entropy_files >= th["rapid_encryption_files"]
    rename = m.extension_changes >= th["extension_changes"]
    active = m.recent_events > 0
    entropy = active and m.samples >= th["min_samples"] and m.avg_entropy >= th["avg_entropy"]
    file_activity = rapid or rename or entropy
    live = file_activity and active  # no stale points once the activity has stopped
    return [
        Signal(
            "rapid_encryption",
            rapid,
            f"{m.high_entropy_files} high-entropy files (limit {th['rapid_encryption_files']})",
        ),
        Signal("mass_rename", rename, f"{m.extension_changes} extension changes (limit {th['extension_changes']})"),
        Signal(
            "high_entropy",
            entropy,
            f"avg entropy {m.avg_entropy:.2f} over {m.samples} files (limit {th['avg_entropy']})",
        ),
        Signal("cpu_spike", live and m.max_cpu >= th["cpu_percent"], f"process CPU {m.max_cpu:.0f}%"),
        Signal("unknown_program", live and trusted_suspect is False, "writer is not in the trusted process list"),
    ]


class DetectionEngine:
    """Keeps a sliding window of events and scores it on every evaluation."""

    def __init__(
        self,
        cfg: dict,
        db: Database,
        process_provider: Callable[[], list[ProcessRow]] | None = None,
        responder=None,
        min_eval_interval: float = 0.25,
    ) -> None:
        d = cfg["detection"]
        self.window = timedelta(seconds=d["window_seconds"])
        self.recent = timedelta(seconds=d.get("recent_seconds", 10))
        self.th, self.weights, self.levels = d["thresholds"], d["weights"], d["levels"]
        self.trusted = {n.lower() for n in d.get("trusted_processes", [])}
        self.quarantine = Path(cfg.get("response", {}).get("quarantine_dir", "data/quarantine")).resolve()
        self.db, self.responder = db, responder
        self.process_provider = process_provider or (lambda: [])
        self.min_eval_interval = min_eval_interval
        self._events: deque[FileEvent] = deque()
        self._files: dict[str, tuple[datetime, float]] = {}  # path -> (last time, latest entropy)
        self._lock = threading.RLock()
        self._last_eval = 0.0
        self._last_saved: tuple[int, str, float] = (-1, "", 0.0)
        self._last_level = NORMAL
        self.last_result = ScoreResult(0, NORMAL)
        self.last_metrics = Metrics()
        self.history: deque[tuple[float, int, float, float]] = deque(maxlen=600)  # for dashboard charts

    # ---- input ---------------------------------------------------------
    def on_event(self, ev: FileEvent) -> None:
        """Feed one file event (called from the monitor thread)."""
        if Path(ev.dest_path or ev.path).resolve().is_relative_to(self.quarantine):
            return  # ignore our own evidence copies
        with self._lock:
            self._ingest(ev)
            if time.monotonic() - self._last_eval >= self.min_eval_interval:
                self._evaluate()

    def tick(self) -> ScoreResult:
        """Re-evaluate without a new event so old events age out of the window."""
        with self._lock:
            res = self._evaluate()
            self.history.append(
                (time.time(), res.score, round(self.last_metrics.avg_entropy, 2), round(self.last_metrics.max_cpu, 1))
            )
            return res

    def reset(self) -> None:
        """Clear the window (used by the dashboard 'Reset' button between demos)."""
        with self._lock:
            self._events.clear()
            self._files.clear()
            self.last_result, self.last_metrics, self._last_level = ScoreResult(0, NORMAL), Metrics(), NORMAL
            if self.responder:
                self.responder.reset()

    def _ingest(self, ev: FileEvent) -> None:
        self._events.append(ev)
        final = ev.dest_path or ev.path
        if ev.event_type == "deleted":
            self._files.pop(ev.path, None)
            return
        if ev.event_type == "moved":
            self._files.pop(ev.path, None)
        if ev.entropy and not ev.expected_high_entropy:  # empty/unreadable/.zip/.jpg are skipped
            self._files[final] = (ev.timestamp, ev.entropy)

    # ---- analysis ------------------------------------------------------
    def _prune(self, now: datetime) -> None:
        while self._events and now - self._events[0].timestamp > self.window:
            self._events.popleft()
        for p in [p for p, (ts, _) in self._files.items() if now - ts > self.window]:
            del self._files[p]

    def compute_metrics(self, now: datetime | None = None) -> Metrics:
        """Recompute window metrics (also used directly by tests)."""
        now = now or datetime.now()
        self._prune(now)
        ev_val = self.th["entropy_value"]
        ents = [e for _, e in self._files.values()]
        procs = self.process_provider()
        return Metrics(
            files_modified_per_min=len({e.path for e in self._events if e.event_type in ("created", "modified")}),
            renames=sum(e.event_type == "moved" for e in self._events),
            extension_changes=sum(
                e.event_type == "moved" and e.old_extension != e.extension and not e.expected_high_entropy
                for e in self._events
            ),
            high_entropy_files=sum(e >= ev_val for e in ents),
            avg_entropy=sum(ents) / len(ents) if ents else 0.0,
            samples=len(ents),
            max_cpu=max((r.cpu_percent for r in procs), default=0.0),
            recent_events=sum(now - e.timestamp <= self.recent for e in self._events),
        )

    def _suspect(self) -> ProcessRow | None:
        return pick_suspect(self.process_provider(), self.trusted)

    def _evaluate(self) -> ScoreResult:
        self._last_eval = time.monotonic()
        m = self.compute_metrics()
        suspect = self._suspect()
        trusted = None if suspect is None else suspect.name.lower() in self.trusted
        result = compute_score(evaluate_signals(m, self.th, trusted), self.weights, self.levels)
        self.last_result, self.last_metrics = result, m
        self._record(result, m, suspect)
        return result

    # ---- output --------------------------------------------------------
    def _record(self, r: ScoreResult, m: Metrics, suspect: ProcessRow | None) -> None:
        import json

        now = time.monotonic()
        s_score, s_level, s_time = self._last_saved
        if (r.score != s_score or r.level != s_level) and (r.level != s_level or now - s_time >= 1.0):
            self.db.save_score(r.score, r.level, json.dumps(r.breakdown))  # dashboard timeline
            self._last_saved = (r.score, r.level, now)
        if _RANK[r.level] > _RANK[self._last_level]:  # alert only when the level goes UP
            msg = f"{r.level.upper()}: {r.explain()}"
            get_logger("alerts").warning(msg)
            self.db.save_alert(r.level, r.score, msg, json.dumps(r.breakdown))
        if r.level == CRITICAL and self.responder:
            ev_val = self.th["entropy_value"]
            affected = sorted(p for p, (_, e) in self._files.items() if e >= ev_val)
            started = min(
                (e.timestamp for e in self._events if (e.entropy or 0) >= ev_val and not e.expected_high_entropy),
                default=None,
            )
            self.responder.handle(r, m, affected, suspect, started)
        self._last_level = r.level
