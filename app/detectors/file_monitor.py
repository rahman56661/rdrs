"""Real-time file monitoring with watchdog."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.core.entropy import file_entropy, is_expected_high_entropy
from app.core.logger import get_logger
from app.core.models import FileEvent

EventCallback = Callable[[FileEvent], None]
log = get_logger("events")


class _Handler(FileSystemEventHandler):
    """Converts raw watchdog events into :class:`FileEvent` objects."""

    def __init__(self, callbacks: list[EventCallback], cfg: dict) -> None:
        self.callbacks = callbacks
        self.sample = cfg["entropy"]["sample_bytes"]
        self.safe_ext = cfg["entropy"]["expected_high_entropy_ext"]

    def _emit(self, ev: FileEvent) -> None:
        for cb in self.callbacks:
            try:
                cb(ev)
            except Exception as exc:  # never let one callback kill the monitor
                get_logger("errors").exception(f"callback failed: {exc}")

    def _build(self, kind: str, src: str, dest: str | None = None) -> FileEvent:
        final = dest or src
        ev = FileEvent(
            event_type=kind,
            path=src,
            dest_path=dest,
            timestamp=datetime.now(),
            extension=Path(final).suffix.lower(),
            old_extension=Path(src).suffix.lower() if dest else None,
        )
        if kind in ("created", "modified", "moved"):
            ev.entropy = file_entropy(final, self.sample)
            ev.expected_high_entropy = is_expected_high_entropy(final, self.safe_ext)
        return ev

    def _handle(self, kind: str, e: FileSystemEvent) -> None:
        if e.is_directory:
            return
        src = str(e.src_path)
        dest = str(e.dest_path) if getattr(e, "dest_path", "") else None
        ev = self._build(kind, src, dest)
        log.info(f"{kind}: {dest or src} entropy={ev.entropy}")
        self._emit(ev)

    def on_created(self, event):
        self._handle("created", event)

    def on_modified(self, event):
        self._handle("modified", event)

    def on_deleted(self, event):
        self._handle("deleted", event)

    def on_moved(self, event):
        self._handle("moved", event)


class FileMonitor:
    """Watches the configured folders and forwards events to callbacks."""

    def __init__(self, paths: list[str], cfg: dict, callbacks: list[EventCallback]) -> None:
        self.paths = paths
        self._observer = Observer()
        handler = _Handler(callbacks, cfg)
        for p in paths:
            Path(p).mkdir(parents=True, exist_ok=True)
            self._observer.schedule(handler, p, recursive=True)

    def start(self) -> None:
        self._observer.start()
        get_logger("system").info(f"Monitoring started: {self.paths}")

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join(timeout=5)
        get_logger("system").info("Monitoring stopped")
