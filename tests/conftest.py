"""Shared fixtures."""

from datetime import datetime, timedelta

import pytest

from app.core.config import load_config
from app.database.db import Database, EventRow


@pytest.fixture(autouse=True)
def _reset_logging():
    """Keep loguru sinks from leaking between tests (captured stderr gets closed)."""
    from loguru import logger

    from app.core import logger as logmod

    yield
    logger.remove()
    logmod._configured = False


@pytest.fixture()
def cfg(tmp_path):
    """Real config.yaml, but with every path redirected into a temp folder."""
    c = load_config("config.yaml")
    c.update(
        watch_paths=[str(tmp_path / "w")],
        database_path=str(tmp_path / "t.db"),
        log_dir=str(tmp_path / "logs"),
        reports_dir=str(tmp_path / "reports"),
    )
    c["response"]["quarantine_dir"] = str(tmp_path / "quarantine")
    c["api"]["enabled"] = False
    (tmp_path / "w").mkdir()
    return c


@pytest.fixture()
def db(cfg):
    database = Database(cfg["database_path"])
    yield database
    database.close()


@pytest.fixture()
def incident(db):
    """An incident with a handful of events around it."""
    now = datetime.now()
    for i in range(5):
        db.save_event(_ev(now - timedelta(seconds=5 - i), i))
    summary = {
        "explanation": "rapid_encryption +40 | mass_rename +30 = 70/100 (Critical)",
        "breakdown": {
            "rapid_encryption": {"points": 40, "reason": "25 files"},
            "mass_rename": {"points": 30, "reason": "20 renames"},
        },
        "mttd_seconds": 1.4,
        "metrics": {"renames": 20},
        "evidence_files_copied": 3,
    }
    import json

    return db.save_incident(
        score=70,
        suspect_process=json.dumps(
            {"pid": 7, "name": "evil.exe", "exe": "C:/x/evil.exe", "attribution": "runs near watched folder"}
        ),
        affected_files=json.dumps(["a.locked", "<script>alert(1)</script>.locked"]),
        evidence_dir="data/quarantine/x",
        summary=json.dumps(summary),
    )


def _ev(ts, i):
    from app.core.models import FileEvent

    return FileEvent("moved", f"f{i}.txt", ".locked", ts, f"f{i}.locked", ".txt", 7.99)


__all__ = ["EventRow"]
