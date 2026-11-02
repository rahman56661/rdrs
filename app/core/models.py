"""Shared plain data objects passed between modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(slots=True)
class FileEvent:
    """One observed file-system change."""

    event_type: str  # created | modified | deleted | moved
    path: str
    extension: str  # extension of the (new) path
    timestamp: datetime = field(default_factory=datetime.now)
    dest_path: str | None = None  # only for moved/renamed
    old_extension: str | None = None
    entropy: float | None = None
    expected_high_entropy: bool = False  # e.g. .zip/.jpg -> not suspicious
