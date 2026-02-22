"""Config loading and initialization."""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from typing import Any

import yaml

from clownpeanuts.config.schema import AppConfig, parse_config


DEFAULT_CONFIG_PATH = Path(__file__).with_name("defaults.yml")
_ENV_TOKEN_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-(.*?))?\}")


def load_config(path: Path) -> AppConfig:
    if not path.exists():
        raise FileNotFoundError(f"config file does not exist: {path}")
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    raw = _interpolate_env(raw)
    return parse_config(raw)


def initialize_config(path: Path, force: bool = False) -> Path:
    if path.exists() and not force:
        raise FileExistsError(f"config already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(DEFAULT_CONFIG_PATH, path)
    return path


def _interpolate_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _interpolate_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(item) for item in value]
    if isinstance(value, str):
        return _interpolate_string(value)
    return value


def _interpolate_string(value: str) -> str:
    if "${" not in value:
        return value

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        default = match.group(2)
        resolved = os.environ.get(name)
        if resolved is not None:
            return resolved
        if default is not None:
            return default
        token = match.group(0)
        raise ValueError(f"missing required environment variable '{name}' referenced by '{token}'")

    return _ENV_TOKEN_RE.sub(_replace, value)
