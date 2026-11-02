"""REST API (FastAPI) + dashboard. All endpoints return JSON except '/' (the dashboard page)."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import desc, func, select

from app.api.simulator import Simulator
from app.core.config import load_config
from app.core.entropy import file_entropy, is_expected_high_entropy
from app.database.db import AlertRow, Database, EventRow, IncidentRow, ScoreRow
from app.reports.generator import build_report, write_reports

DASHBOARD = Path(__file__).resolve().parents[1] / "dashboard" / "index.html"
_JSON_FIELDS = ("breakdown", "affected_files", "suspect_process", "summary")


class SettingsUpdate(BaseModel):
    """Runtime tuning of thresholds / weights / level bands (keys must already exist)."""

    thresholds: dict[str, float] | None = None
    weights: dict[str, int] | None = None
    levels: dict[str, int] | None = None


def _row(r: Any) -> dict:
    out = {c.name: getattr(r, c.name) for c in r.__table__.columns}
    for k in _JSON_FIELDS:
        if k in out and isinstance(out[k], str):
            try:
                out[k] = json.loads(out[k])
            except ValueError:
                pass
    return out


def create_app(cfg: dict, db: Database, engine=None, simulator: Simulator | None = None) -> FastAPI:
    """Build the API. ``engine`` is None when the API runs standalone (status then comes from the DB)."""
    app = FastAPI(title="RDRS API", version="1.0")
    sim, started = simulator or Simulator(), time.time()

    def latest(model, limit: int) -> list[dict]:
        with db.session() as s:
            return [_row(r) for r in s.scalars(select(model).order_by(desc(model.id)).limit(limit))]

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(DASHBOARD)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "time": datetime.now().isoformat()}

    @app.get("/status")
    def status() -> dict:
        d = cfg["detection"]
        if engine:
            r, m = engine.last_result, engine.last_metrics
            core = {
                "level": r.level,
                "score": r.score,
                "explanation": r.explain(),
                "breakdown": r.breakdown,
                "metrics": asdict(m),
            }
            levels = engine.levels
        else:
            last = latest(ScoreRow, 1)
            core = {
                "level": last[0]["level"] if last else "Normal",
                "score": last[0]["score"] if last else 0,
                "explanation": "",
                "breakdown": last[0]["breakdown"] if last else {},
                "metrics": {},
            }
            levels = d["levels"]
        with db.session() as s:
            counts = {
                "events": s.scalar(select(func.count()).select_from(EventRow)),
                "alerts": s.scalar(select(func.count()).select_from(AlertRow)),
                "incidents": s.scalar(select(func.count()).select_from(IncidentRow)),
            }
        return {
            **core,
            "levels": levels,
            "counts": counts,
            "watching": cfg["watch_paths"],
            "simulation_mode": cfg.get("simulation_mode", True),
            "simulator_running": sim.running,
            "uptime_seconds": int(time.time() - started),
        }

    @app.get("/alerts")
    def alerts(limit: int = Query(50, ge=1, le=500)) -> list[dict]:
        return latest(AlertRow, limit)

    @app.get("/events")
    def events(limit: int = Query(50, ge=1, le=500)) -> list[dict]:
        return latest(EventRow, limit)

    @app.get("/incidents")
    def incidents(limit: int = Query(20, ge=1, le=200)) -> list[dict]:
        return latest(IncidentRow, limit)

    @app.get("/scores")
    def scores(minutes: int = Query(10, ge=1, le=1440)) -> list[dict]:
        with db.session() as s:
            q = select(ScoreRow).where(ScoreRow.timestamp >= datetime.now() - timedelta(minutes=minutes))
            return [_row(r) for r in s.scalars(q.order_by(ScoreRow.id))]

    @app.get("/history")
    def history() -> list[dict]:
        """Per-second samples for the dashboard charts (empty when API runs without the engine)."""
        rows = list(engine.history) if engine else []
        return [{"t": t, "score": sc, "entropy": en, "cpu": cpu} for t, sc, en, cpu in rows]

    @app.get("/top-files")
    def top_files(limit: int = Query(10, ge=1, le=50)) -> list[dict]:
        since = datetime.now() - timedelta(seconds=cfg["detection"]["window_seconds"])
        with db.session() as s:
            q = (
                select(EventRow.path, func.count().label("n"))
                .where(EventRow.timestamp >= since)
                .where(EventRow.event_type.in_(("created", "modified")))
                .group_by(EventRow.path)
                .order_by(desc("n"))
                .limit(limit)
            )
            return [{"path": p, "modifications": n} for p, n in s.execute(q)]

    @app.get("/reports")
    def reports() -> list[dict]:
        rdir = Path(cfg.get("reports_dir", "data/reports"))
        out = []
        for inc in latest(IncidentRow, 50):
            files = sorted(f.name for f in rdir.glob(f"incident_{inc['id']}.*")) if rdir.exists() else []
            out.append(
                {
                    "incident_id": inc["id"],
                    "timestamp": inc["timestamp"],
                    "score": inc["score"],
                    "evidence_dir": inc["evidence_dir"],
                    "report_files": files,
                }
            )
        return out

    @app.post("/reports/{incident_id}")
    def make_report(incident_id: int) -> dict:
        """Generate JSON / CSV / HTML / PDF reports for an incident."""
        try:
            rep = build_report(db, incident_id, cfg["detection"]["window_seconds"])
        except LookupError:
            raise HTTPException(404, f"Incident {incident_id} not found") from None
        paths = write_reports(rep, cfg.get("reports_dir", "data/reports"))
        return {"incident_id": incident_id, "files": [Path(x).name for x in paths.values()]}

    @app.get("/reports/download/{name}")
    def download_report(name: str) -> FileResponse:
        path = Path(cfg.get("reports_dir", "data/reports")) / Path(name).name  # .name blocks path traversal
        if not path.is_file():
            raise HTTPException(404, "Report not found")
        return FileResponse(path)

    @app.get("/settings")
    def get_settings() -> dict:
        d = engine if engine else None
        return {
            "thresholds": d.th if d else cfg["detection"]["thresholds"],
            "weights": d.weights if d else cfg["detection"]["weights"],
            "levels": d.levels if d else cfg["detection"]["levels"],
        }

    @app.post("/settings")
    def update_settings(body: SettingsUpdate) -> dict:
        targets = {
            "thresholds": (engine.th if engine else cfg["detection"]["thresholds"]),
            "weights": (engine.weights if engine else cfg["detection"]["weights"]),
            "levels": (engine.levels if engine else cfg["detection"]["levels"]),
        }
        for section, new in body.model_dump(exclude_none=True).items():
            unknown = set(new) - set(targets[section])
            if unknown:
                raise HTTPException(422, f"Unknown {section} keys: {sorted(unknown)}")
            if any(v < 0 for v in new.values()):
                raise HTTPException(422, "Values must be >= 0")
        lv = {**targets["levels"], **(body.levels or {})}
        if not lv["warning"] < lv["critical"] <= 100:
            raise HTTPException(422, "levels must satisfy warning < critical <= 100")
        for section, new in body.model_dump(exclude_none=True).items():
            targets[section].update(new)
        return get_settings()

    @app.post("/scan")
    def scan() -> dict:
        """One-off scan of the watched folders: lists files that currently look encrypted."""
        d = cfg["detection"]["thresholds"]
        safe, suspicious, total = cfg["entropy"]["expected_high_entropy_ext"], [], 0
        for root in cfg["watch_paths"]:
            for dirpath, _, names in os.walk(root):
                for name in names:
                    if total >= 5000:
                        break
                    total += 1
                    path = os.path.join(dirpath, name)
                    e = file_entropy(path, cfg["entropy"]["sample_bytes"])
                    if e and e >= d["entropy_value"] and not is_expected_high_entropy(path, safe):
                        suspicious.append({"path": path, "entropy": round(e, 3)})
        return {"scanned": total, "suspicious_count": len(suspicious), "suspicious": suspicious[:50]}

    @app.post("/simulate/reset")
    def simulate_reset() -> dict:
        removed = sim.reset()
        if removed < 0:
            raise HTTPException(409, "A simulation is still running")
        if engine:
            engine.reset()
        return {"removed_files": removed}

    @app.post("/simulate/{mode}")
    def simulate(mode: Literal["attack", "normal", "zip"]) -> dict:
        if not sim.start(mode):
            raise HTTPException(409, "A simulation is already running")
        return {"started": mode}

    return app


def create_default_app() -> FastAPI:
    """Standalone:  uvicorn app.api.main:create_default_app --factory  (no live engine, DB only)."""
    cfg = load_config()
    return create_app(cfg, Database(cfg["database_path"]))
