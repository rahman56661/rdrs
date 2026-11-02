"""Incident response: incident record, evidence quarantine (copy only), audit trail."""

from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path

from app.core.logger import get_logger
from app.core.scoring import CRITICAL, ScoreResult
from app.database.db import Database, ProcessRow

alerts, audit = get_logger("alerts"), get_logger("audit")


class IncidentResponder:
    """Creates ONE incident per attack (cooldown), keeps extending it while the attack continues,
    and preserves evidence safely (copy only)."""

    def __init__(self, cfg: dict, db: Database, extend_interval: float = 1.0) -> None:
        r = cfg.get("response", {})
        self.db = db
        self.quarantine = Path(r.get("quarantine_dir", "data/quarantine"))
        self.cooldown = r.get("incident_cooldown_seconds", 120)
        self.max_files = r.get("max_evidence_files", 200)
        self.max_bytes = r.get("max_evidence_file_mb", 10) * 1_048_576
        self.terminate = r.get("terminate_process", False)
        self.simulation = cfg.get("simulation_mode", True)
        self.extend_interval = extend_interval
        self.reset()

    def reset(self) -> None:
        """Forget the current incident (allows a fresh incident, e.g. next demo run)."""
        self._last_incident = -1e9
        self._cur: dict | None = None

    def handle(
        self,
        result: ScoreResult,
        metrics,
        affected: list[str],
        suspect: ProcessRow | None,
        attack_started: datetime | None,
    ) -> int | None:
        """Create an incident on Critical. During cooldown, extend the running incident instead."""
        if time.monotonic() - self._last_incident < self.cooldown:
            if self._cur and result.level == CRITICAL:
                self._extend(affected)
            return None
        self._last_incident = time.monotonic()
        detected = datetime.now()
        mttd = round((detected - attack_started).total_seconds(), 2) if attack_started else None
        info = (
            None
            if suspect is None
            else {
                "pid": suspect.pid,
                "name": suspect.name,
                "exe": suspect.exe,
                "cpu_percent": suspect.cpu_percent,
                "attribution": "runs near watched folder"
                if getattr(suspect, "near_watch", False)
                else "disk-write activity only (low confidence)",
            }
        )
        dest = self.quarantine / f"incident_{detected:%Y%m%d_%H%M%S}"
        dest.mkdir(parents=True, exist_ok=True)
        self._cur = {
            "dir": dest,
            "copied": set(),
            "manifest": [],
            "last": time.monotonic(),
            "id": None,
            "meta": {
                "detected_at": detected.isoformat(),
                "score": result.score,
                "explanation": result.explain(),
                "suspect": info,
                "mttd_seconds": mttd,
            },
        }
        self._copy_new(affected)
        self._simulate_termination(info)
        self._summary = {
            "explanation": result.explain(),
            "breakdown": result.breakdown,
            "mttd_seconds": mttd,
            "metrics": asdict(metrics) if is_dataclass(metrics) else str(metrics),
            "evidence_files_copied": len(self._cur["copied"]),
            "affected_count": len(affected),
        }
        row = self.db.save_incident(
            score=result.score,
            suspect_process=json.dumps(info),
            affected_files=json.dumps(affected),
            evidence_dir=str(dest),
            summary=json.dumps(self._summary, default=str),
        )
        self._cur["id"] = row.id
        alerts.critical(f"INCIDENT #{row.id}: {result.explain()} | affected={len(affected)} | evidence={dest}")
        audit.info(f"incident_created id={row.id} score={result.score} suspect={info} mttd={mttd}s")
        return row.id

    def _extend(self, affected: list[str]) -> None:
        """Attack still running: copy newly affected files and update the incident record."""
        cur = self._cur
        if not cur or cur["id"] is None or time.monotonic() - cur["last"] < self.extend_interval:
            return
        if not [f for f in affected if f not in cur["copied"]]:
            return
        cur["last"] = time.monotonic()
        self._copy_new(affected)
        self._summary.update(evidence_files_copied=len(cur["copied"]), affected_count=len(affected))
        self.db.update_incident(
            cur["id"], affected_files=json.dumps(affected), summary=json.dumps(self._summary, default=str)
        )

    def _copy_new(self, files: list[str]) -> None:
        """COPY files not yet preserved (originals are never modified or deleted) and rewrite the manifest."""
        cur = self._cur
        for src in files:
            if src in cur["copied"] or len(cur["copied"]) >= self.max_files:
                continue
            p = Path(src)
            try:
                if not p.is_file() or p.stat().st_size > self.max_bytes:
                    continue
                data = p.read_bytes()
                shutil.copy2(p, cur["dir"] / f"{len(cur['copied']):04d}_{p.name}")
                cur["manifest"].append({"original": str(p), "sha256": hashlib.sha256(data).hexdigest()})
                cur["copied"].add(src)
            except OSError as exc:
                get_logger("errors").warning(f"evidence copy failed for {p}: {exc}")
        (cur["dir"] / "manifest.json").write_text(
            json.dumps({**cur["meta"], "files": cur["manifest"]}, indent=2), encoding="utf-8"
        )
        audit.info(f"evidence_saved dir={cur['dir']} files={len(cur['copied'])}")

    def _simulate_termination(self, suspect: dict | None) -> None:
        """Process termination is NEVER performed. In simulation mode we only log what we would do."""
        if suspect and self.terminate:
            audit.warning(f"[SIMULATION] would terminate pid={suspect['pid']} ({suspect['name']}) - not executed")
