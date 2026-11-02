"""SQLite storage (SQLAlchemy): events, processes, scores, alerts, incidents."""

from __future__ import annotations

import threading
from datetime import datetime
from pathlib import Path

from sqlalchemy import Boolean, DateTime, Float, Integer, String, Text, create_engine, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.core.models import FileEvent


class Base(DeclarativeBase):
    """Declarative base."""


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    event_type: Mapped[str] = mapped_column(String(16))
    path: Mapped[str] = mapped_column(Text)
    dest_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    extension: Mapped[str] = mapped_column(String(32))
    old_extension: Mapped[str | None] = mapped_column(String(32), nullable=True)
    entropy: Mapped[float | None] = mapped_column(Float, nullable=True)
    expected_high_entropy: Mapped[bool] = mapped_column(Boolean, default=False)


class ProcessRow(Base):
    __tablename__ = "processes"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    pid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(256))
    exe: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cpu_percent: Mapped[float] = mapped_column(Float)
    memory_mb: Mapped[float] = mapped_column(Float)
    write_bytes: Mapped[int] = mapped_column(Integer, default=0)  # cumulative
    write_delta: Mapped[int] = mapped_column(Integer, default=0)  # written since last snapshot


class ScoreRow(Base):
    __tablename__ = "scores"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    score: Mapped[int] = mapped_column(Integer)
    level: Mapped[str] = mapped_column(String(16))
    breakdown: Mapped[str] = mapped_column(Text)  # JSON: signal -> points (explainability)


class AlertRow(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    level: Mapped[str] = mapped_column(String(16))
    score: Mapped[int] = mapped_column(Integer)
    message: Mapped[str] = mapped_column(Text)
    breakdown: Mapped[str] = mapped_column(Text, default="{}")


class IncidentRow(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    score: Mapped[int] = mapped_column(Integer)
    suspect_process: Mapped[str | None] = mapped_column(Text, nullable=True)
    affected_files: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    evidence_dir: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")


class Database:
    """Thin, thread-safe wrapper around the SQLite database."""

    def __init__(self, db_path: str | Path) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False, "timeout": 30})
        self._session = sessionmaker(self.engine, expire_on_commit=False)
        self._lock = threading.Lock()  # SQLite = one writer at a time
        Base.metadata.create_all(self.engine)

    def close(self) -> None:
        """Release the SQLite connection pool (used at shutdown and in tests)."""
        self.engine.dispose()

    def session(self) -> Session:
        """Open a new session (caller closes it, e.g. ``with db.session() as s``)."""
        return self._session()

    def _add(self, row: Base) -> Base:
        with self._lock, self._session() as s:
            s.add(row)
            s.commit()
        return row

    def save_event(self, ev: FileEvent) -> None:
        """Persist a :class:`FileEvent`."""
        self._add(
            EventRow(
                timestamp=ev.timestamp,
                event_type=ev.event_type,
                path=ev.path,
                dest_path=ev.dest_path,
                extension=ev.extension,
                old_extension=ev.old_extension,
                entropy=ev.entropy,
                expected_high_entropy=ev.expected_high_entropy,
            )
        )

    def save_processes(self, rows: list[ProcessRow]) -> None:
        """Persist a batch of process snapshots."""
        with self._lock, self._session() as s:
            s.add_all(rows)
            s.commit()

    def save_score(self, score: int, level: str, breakdown_json: str) -> None:
        """Persist a score sample (used for the dashboard timeline)."""
        self._add(ScoreRow(timestamp=datetime.now(), score=score, level=level, breakdown=breakdown_json))

    def save_alert(self, level: str, score: int, message: str, breakdown_json: str) -> AlertRow:
        """Persist an alert."""
        return self._add(
            AlertRow(timestamp=datetime.now(), level=level, score=score, message=message, breakdown=breakdown_json)
        )

    def save_incident(self, **fields) -> IncidentRow:
        """Persist an incident record and return it (with its id)."""
        return self._add(IncidentRow(timestamp=datetime.now(), **fields))

    def update_incident(self, incident_id: int, **fields) -> None:
        """Update fields of an existing incident (attack still in progress)."""
        with self._lock, self._session() as s:
            row = s.get(IncidentRow, incident_id)
            if row:
                for k, v in fields.items():
                    setattr(row, k, v)
                s.commit()

    def count(self, model: type[Base]) -> int:
        """Number of rows in a table."""
        with self._session() as s:
            return s.scalar(select(func.count()).select_from(model)) or 0
