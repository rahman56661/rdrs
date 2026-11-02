import csv
import json
import sys

import pytest

from app.reports import generator
from app.reports.generator import build_report, write_reports


def test_build_report_content(db, incident):
    r = build_report(db, incident.id)
    assert r["incident"]["score"] == 70 and r["incident"]["mttd_seconds"] == 1.4
    assert r["affected_count"] == 2 and r["timeline_summary"]["events"] == 5
    assert any("evil.exe" in x for x in r["recommendations"])
    assert 0 < len(r["attack_timeline"]) <= len(r["timeline"])


def test_build_report_unknown_incident(db):
    with pytest.raises(LookupError):
        build_report(db, 12345)


def test_write_all_formats(db, incident, tmp_path):
    out = write_reports(build_report(db, incident.id), tmp_path / "out")
    assert set(out) == {"json", "csv", "html", "pdf"}
    assert json.loads(open(out["json"], encoding="utf-8").read())["incident"]["id"] == incident.id
    rows = list(csv.DictReader(open(out["csv"], encoding="utf-8")))
    assert len(rows) == 5 and rows[0]["event_type"] == "moved"
    html = open(out["html"], encoding="utf-8").read()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html  # autoescape: no XSS
    assert open(out["pdf"], "rb").read(4) == b"%PDF"


def test_report_without_suspect_or_events(db):
    row = db.save_incident(score=80, suspect_process="null", affected_files="[]", evidence_dir="x", summary="not-json")
    r = build_report(db, row.id)
    assert r["suspect_process"] is None and r["timeline"] == []
    assert "unknown" in generator._HTML.render(r=r)


def test_pdf_skipped_when_reportlab_missing(db, incident, tmp_path, monkeypatch):
    def no_reportlab(*_a):
        raise ImportError("reportlab missing")

    monkeypatch.setattr(generator, "_write_pdf", no_reportlab)
    out = write_reports(build_report(db, incident.id), tmp_path, formats=("json", "pdf"))
    assert set(out) == {"json"}


def test_cli_latest_and_empty(cfg, db, incident, monkeypatch, capsys, tmp_path):
    import yaml

    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump(cfg))
    monkeypatch.setattr(sys, "argv", ["gen", "--config", str(path), "--latest"])
    generator.main()
    assert "json" in capsys.readouterr().out
    cfg["database_path"] = str(tmp_path / "empty.db")
    path.write_text(yaml.safe_dump(cfg))
    with pytest.raises(SystemExit):
        generator.main()
