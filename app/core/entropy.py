"""Shannon entropy helpers (0 = predictable, 8 = random/encrypted)."""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

SAMPLE_BYTES = 64 * 1024


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy of ``data`` in bits/byte (0.0 - 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in Counter(data).values())


def file_entropy(path: str | Path, sample_bytes: int = SAMPLE_BYTES) -> float | None:
    """Entropy of the first ``sample_bytes`` of a file.

    Returns ``None`` if the file is unreadable (deleted, locked, no permission).
    """
    try:
        with open(path, "rb") as fh:
            return shannon_entropy(fh.read(sample_bytes))
    except (OSError, PermissionError):
        return None


def is_expected_high_entropy(path: str | Path, extensions: list[str]) -> bool:
    """True for file types that are naturally high-entropy (zip, jpg, ...).

    Used to cut false positives: a zip file is random-looking but harmless.
    """
    return Path(path).suffix.lower() in {e.lower() for e in extensions}
