"""Rotating log files: system, events, alerts, errors, audit."""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

_CHANNELS = ("system", "events", "alerts", "errors", "audit")
_configured = False


def setup_logging(log_dir: str | Path = "logs") -> None:
    """Configure console + rotating file sinks (idempotent)."""
    global _configured
    if _configured:
        return
    out = Path(log_dir)
    out.mkdir(parents=True, exist_ok=True)
    logger.remove()
    console_fmt = "<g>{time:HH:mm:ss}</g> | <level>{level:<8}</level> | {message}"
    logger.add(
        sys.stderr, level="INFO", format=console_fmt, filter=lambda r: r["extra"].get("channel") != "events"
    )  # per-event noise goes to the file only
    fmt = "{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
    for ch in _CHANNELS:
        kwargs = {"level": "ERROR"} if ch == "errors" else {}
        logger.add(
            out / f"{ch}.log",
            rotation="5 MB",
            retention=5,
            format=fmt,
            filter=(lambda r, c=ch: r["extra"].get("channel", "system") == c) if ch != "errors" else None,
            **kwargs,
        )
    _configured = True


def get_logger(channel: str = "system"):
    """Return a logger bound to a channel (system/events/alerts/errors/audit)."""
    return logger.bind(channel=channel)
