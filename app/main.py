"""RDRS entry point:  python -m app.main --watch data/sandbox"""

from __future__ import annotations

import argparse
import threading
import time
from collections import Counter

from app.core.config import load_config
from app.core.logger import get_logger, setup_logging
from app.core.models import FileEvent
from app.database.db import Database
from app.detectors.engine import DetectionEngine
from app.detectors.file_monitor import FileMonitor
from app.detectors.process_monitor import ProcessMonitor
from app.detectors.response import IncidentResponder


def start_api(cfg: dict, db: Database, engine: DetectionEngine):
    """Run the REST API + dashboard in a background thread (shares the live engine)."""
    import uvicorn

    from app.api.main import create_app

    a = cfg.get("api", {})
    if not a.get("enabled", True):
        return None
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(cfg, db, engine), host=a.get("host", "127.0.0.1"), port=a.get("port", 8765), log_level="warning"
        )
    )
    threading.Thread(target=server.run, daemon=True, name="api").start()
    shown = a.get("host", "127.0.0.1")
    shown = "localhost" if shown in ("0.0.0.0", "::") else shown  # 0.0.0.0 is not a browsable address
    print(f"Dashboard: http://{shown}:{a.get('port', 8765)}/   (API docs: /docs)")
    return server


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Ransomware Detection and Response System")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--watch", nargs="*", help="override folders to watch")
    ap.add_argument("--no-api", action="store_true", help="do not start the API/dashboard")
    return ap


def main() -> None:
    args = build_parser().parse_args()
    cfg = load_config(args.config)
    setup_logging(cfg.get("log_dir", "logs"))
    log = get_logger("system")
    if cfg.get("simulation_mode", True):
        log.info("SIMULATION MODE ON - no process will ever be killed")

    db = Database(cfg["database_path"])
    counts: Counter[str] = Counter()
    lock = threading.Lock()

    def on_event(ev: FileEvent) -> None:
        db.save_event(ev)
        with lock:
            counts[ev.event_type] += 1

    pm_cfg = cfg.get("process_monitor", {})
    paths = args.watch or cfg["watch_paths"]
    cfg["watch_paths"] = paths
    procs = ProcessMonitor(db, pm_cfg.get("interval_seconds", 2), pm_cfg.get("top_n", 10), paths)
    engine = DetectionEngine(cfg, db, lambda: procs.latest, IncidentResponder(cfg, db))
    callbacks = [on_event, engine.on_event]
    monitor = FileMonitor(paths, cfg, callbacks)
    monitor.start()
    procs.start()
    server = None if args.no_api else start_api(cfg, db, engine)
    print(f"Watching {paths}  (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
            res = engine.tick()
            with lock:
                total = sum(counts.values())
                print(
                    f"\rEvents: {total:>5} | Level: {res.level:<8} Score: {res.score:>3}/100 | "
                    f"{res.explain()[:70]:<70}",
                    end="",
                    flush=True,
                )
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        if server:
            server.should_exit = True
        procs.stop()
        monitor.stop()
        db.close()


if __name__ == "__main__":
    main()
