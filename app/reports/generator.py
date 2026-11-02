"""Incident reports: JSON, CSV, HTML (jinja2) and PDF (reportlab, optional).

CLI:  python -m app.reports.generator --latest
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

from jinja2 import Environment, select_autoescape
from sqlalchemy import desc, select

from app.core.config import load_config
from app.core.logger import get_logger
from app.database.db import Database, EventRow, IncidentRow

FORMATS = ("json", "csv", "html", "pdf")
TIMELINE_COLUMNS = ("timestamp", "event_type", "path", "dest_path", "extension", "entropy", "expected_high_entropy")

RECOMMENDATIONS = [
    "Isolate the affected machine from the network to stop any spread.",
    "Do not delete or modify the quarantined evidence; verify it against the SHA-256 hashes in manifest.json.",
    "Identify and review the suspect process, its parent process and its executable path.",
    "Restore the affected files from a clean, offline backup after the cause is removed.",
    "Rotate credentials that were used on this machine and review recent logins.",
    "Review file-sharing and backup tools that may legitimately create many encrypted-looking files (false positives).",
]


def _loads(value, default):
    """Parse a JSON text column; fall back to ``default`` on bad data."""
    if not isinstance(value, str):
        return default if value is None else value
    try:
        return json.loads(value)
    except ValueError:
        return default


def build_report(
    db: Database, incident_id: int, before_seconds: int = 60, after_seconds: int = 60, max_events: int = 1000
) -> dict:
    """Collect everything about one incident into a plain dictionary.

    Raises:
        LookupError: if the incident does not exist.
    """
    with db.session() as s:
        inc = s.get(IncidentRow, incident_id)
        if inc is None:
            raise LookupError(f"Incident {incident_id} not found")
        q = (
            select(EventRow)
            .where(
                EventRow.timestamp.between(
                    inc.timestamp - timedelta(seconds=before_seconds), inc.timestamp + timedelta(seconds=after_seconds)
                )
            )
            .order_by(EventRow.id)
            .limit(max_events)
        )
        events = list(s.scalars(q))
    summary = _loads(inc.summary, {})
    suspect = _loads(inc.suspect_process, None)
    affected = _loads(inc.affected_files, [])
    timeline = [
        {
            "timestamp": e.timestamp.isoformat(timespec="milliseconds"),
            "event_type": e.event_type,
            "path": e.path,
            "dest_path": e.dest_path,
            "extension": e.extension,
            "entropy": None if e.entropy is None else round(e.entropy, 3),
            "expected_high_entropy": bool(e.expected_high_entropy),
        }
        for e in events
    ]
    mttd = summary.get("mttd_seconds") or 0
    focus = inc.timestamp - timedelta(seconds=mttd + 2)  # start the story just before the first suspicious event
    attack_timeline = [row for row, e in zip(timeline, events, strict=True) if e.timestamp >= focus]
    recs = list(RECOMMENDATIONS)
    if suspect:
        recs.insert(
            2,
            f"Investigate process '{suspect.get('name')}' (pid {suspect.get('pid')}, "
            f"{suspect.get('exe')}). Attribution: {suspect.get('attribution', 'unknown')}.",
        )
    return {
        "report_version": 1,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "incident": {
            "id": inc.id,
            "detected_at": inc.timestamp.isoformat(timespec="seconds"),
            "score": inc.score,
            "level": "Critical",
            "explanation": summary.get("explanation", ""),
            "breakdown": summary.get("breakdown", {}),
            "mttd_seconds": summary.get("mttd_seconds"),
        },
        "metrics": summary.get("metrics", {}),
        "suspect_process": suspect,
        "affected_count": len(affected),
        "affected_files": affected,
        "evidence": {"dir": inc.evidence_dir, "files_copied": summary.get("evidence_files_copied", 0)},
        "timeline_summary": {
            "events": len(timeline),
            "by_type": dict(Counter(t["event_type"] for t in timeline)),
            "first": timeline[0]["timestamp"] if timeline else None,
            "last": timeline[-1]["timestamp"] if timeline else None,
        },
        "attack_timeline": attack_timeline,
        "timeline": timeline,
        "recommendations": recs,
    }


_HTML = Environment(autoescape=select_autoescape(default=True)).from_string("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>RDRS Incident #{{ r.incident.id }}</title>
<style>body{font:14px system-ui,sans-serif;max-width:980px;margin:30px auto;color:#1b2430}
h1{margin-bottom:0}.crit{color:#b91c1c;font-weight:700}table{border-collapse:collapse;width:100%;margin:8px 0 22px}
td,th{border:1px solid #d5dbe5;padding:4px 8px;text-align:left;font-size:12.5px;
word-break:break-all}th{background:#eef2f7}
code{background:#eef2f7;padding:1px 4px}</style></head><body>
<h1>Incident Report #{{ r.incident.id }}</h1><p>Generated {{ r.generated_at }} by RDRS
(defensive analysis, simulation mode)</p>
<h2>Summary</h2><table>
<tr><th>Detected at</th><td>{{ r.incident.detected_at }}</td></tr>
<tr><th>Threat score</th><td class="crit">{{ r.incident.score }}/100 ({{ r.incident.level }})</td></tr>
<tr><th>Why (explainable score)</th><td>{{ r.incident.explanation }}</td></tr>
<tr><th>Time to detect (MTTD)</th><td>{{ r.incident.mttd_seconds }} seconds</td></tr>
<tr><th>Suspect process</th><td>{% if r.suspect_process %}{{ r.suspect_process.name }}
(pid {{ r.suspect_process.pid }})<br>
{{ r.suspect_process.exe }}<br><i>{{ r.suspect_process.attribution }}</i>{% else %}unknown{% endif %}</td></tr>
<tr><th>Affected files</th><td>{{ r.affected_count }}</td></tr>
<tr><th>Evidence (copied, originals untouched)</th><td>{{ r.evidence.dir }}
({{ r.evidence.files_copied }} files)</td></tr></table>
<h2>Score breakdown (at detection time)</h2><table><tr><th>Signal</th><th>Points</th><th>Reason</th></tr>
{% for k, v in r.incident.breakdown.items() %}
<tr><td>{{ k }}</td><td>+{{ v.points }}</td>
<td>{{ v.reason }}</td></tr>{% endfor %}</table>
<h2>Recommendations</h2><ol>{% for x in r.recommendations %}<li>{{ x }}</li>{% endfor %}</ol>
<h2>Affected files (first 50 of {{ r.affected_count }})</h2><table>
{% for f in r.affected_files[:50] %}<tr><td>{{ f }}</td></tr>{% endfor %}</table>
<h2>Attack timeline (from just before the first suspicious event)</h2>
<p>{{ r.timeline_summary.events }} events in the surrounding window: {{ r.timeline_summary.by_type }}</p><table>
<tr><th>Time</th><th>Type</th><th>File</th><th>Entropy</th></tr>
{% for t in r.attack_timeline[:200] %}<tr><td>{{ t.timestamp[11:] }}</td><td>{{ t.event_type }}</td>
<td>{{ t.dest_path or t.path }}</td><td>{{ t.entropy }}</td></tr>{% endfor %}</table>
{% if r.attack_timeline|length > 200 %}<p>Showing the first 200 events.
Full timeline is in the JSON/CSV report.</p>{% endif %}
</body></html>""")


def _write_pdf(report: dict, path: Path) -> None:
    """Render a compact PDF with reportlab (imported lazily - it is an optional dependency)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    st, inc = getSampleStyleSheet(), report["incident"]
    p = lambda text, style="BodyText": Paragraph(escape(str(text)), st[style])  # noqa: E731
    sus = report["suspect_process"] or {}
    rows = [
        ["Detected at", inc["detected_at"]],
        ["Threat score", f"{inc['score']}/100 ({inc['level']})"],
        ["Explanation", inc["explanation"]],
        ["MTTD (s)", inc["mttd_seconds"]],
        ["Suspect", f"{sus.get('name', 'unknown')} (pid {sus.get('pid', '-')})"],
        ["Affected files", report["affected_count"]],
        ["Evidence dir", report["evidence"]["dir"]],
    ]
    box = TableStyle(
        [
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
        ]
    )
    story = [
        p(f"RDRS Incident Report #{inc['id']}", "Title"),
        Table([[p(a), p(b)] for a, b in rows], colWidths=[110, 380], style=box),
        Spacer(1, 10),
        p("Score breakdown (at detection time)", "Heading2"),
    ]
    story += [p(f"{k} +{v['points']} - {v['reason']}") for k, v in inc["breakdown"].items()]
    story += [Spacer(1, 8), p("Recommendations", "Heading2")]
    story += [p(f"{i}. {x}") for i, x in enumerate(report["recommendations"], 1)]
    story += [Spacer(1, 8), p(f"Attack timeline (first 40 of {len(report['attack_timeline'])} events)", "Heading2")]
    story += [
        Table(
            [
                [p(t["timestamp"][11:]), p(t["event_type"]), p(t["dest_path"] or t["path"]), p(t["entropy"])]
                for t in report["attack_timeline"][:40]
            ]
            or [[p("no events")]],
            colWidths=[85, 55, 290, 45],
            style=box,
        )
    ]
    SimpleDocTemplate(str(path), pagesize=A4, title=f"RDRS Incident {inc['id']}").build(story)


def write_reports(report: dict, out_dir: str | Path, formats: tuple[str, ...] = FORMATS) -> dict[str, str]:
    """Write the requested formats to ``out_dir`` and return {format: path}. PDF is skipped if reportlab is missing."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    base, written = out / f"incident_{report['incident']['id']}", {}
    if "json" in formats:
        (base.with_suffix(".json")).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        written["json"] = str(base.with_suffix(".json"))
    if "csv" in formats:
        with base.with_suffix(".csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=TIMELINE_COLUMNS)
            w.writeheader()
            w.writerows(report["timeline"])
        written["csv"] = str(base.with_suffix(".csv"))
    if "html" in formats:
        base.with_suffix(".html").write_text(_HTML.render(r=report), encoding="utf-8")
        written["html"] = str(base.with_suffix(".html"))
    if "pdf" in formats:
        try:
            _write_pdf(report, base.with_suffix(".pdf"))
            written["pdf"] = str(base.with_suffix(".pdf"))
        except ImportError:
            get_logger("system").warning("reportlab not installed - PDF report skipped")
    get_logger("audit").info(f"report_generated incident={report['incident']['id']} files={list(written)}")
    return written


def main() -> None:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description="Generate RDRS incident reports")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--incident", type=int, help="incident id")
    ap.add_argument("--latest", action="store_true", help="use the newest incident")
    args = ap.parse_args()
    cfg = load_config(args.config)
    db = Database(cfg["database_path"])
    iid = args.incident
    if args.latest or iid is None:
        with db.session() as s:
            iid = s.scalar(select(IncidentRow.id).order_by(desc(IncidentRow.id)).limit(1))
    if iid is None:
        raise SystemExit("No incidents found.")
    for fmt, path in write_reports(build_report(db, iid), cfg.get("reports_dir", "data/reports")).items():
        print(f"{fmt:>5}: {path}")


if __name__ == "__main__":  # pragma: no cover
    main()
