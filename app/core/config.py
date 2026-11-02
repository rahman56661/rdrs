"""Configuration loader for RDRS (reads config.yaml)."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATH = Path("config.yaml")


class ConfigError(Exception):
    """Raised when the configuration file is missing or invalid."""


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load and minimally validate the YAML configuration.

    Args:
        path: Location of the YAML config file.

    Returns:
        The configuration as a dictionary.
    """
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"Config file not found: {p.resolve()}")
    with p.open("r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    for key in ("watch_paths", "database_path", "entropy", "detection"):
        if key not in cfg:
            raise ConfigError(f"Missing required config key: '{key}'")
    return _apply_env_overrides(cfg)


def _apply_env_overrides(cfg: dict[str, Any]) -> dict[str, Any]:
    """Allow Docker / CI to override a few settings via environment variables."""
    if host := os.getenv("RDRS_API_HOST"):
        cfg.setdefault("api", {})["host"] = host
    if port := os.getenv("RDRS_API_PORT"):
        cfg.setdefault("api", {})["port"] = int(port)
    if paths := os.getenv("RDRS_WATCH_PATHS"):
        cfg["watch_paths"] = [p.strip() for p in paths.split(",") if p.strip()]
    return cfg
