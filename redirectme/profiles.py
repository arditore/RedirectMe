"""Saving and loading named scan profiles."""
from __future__ import annotations

import json
import re
from dataclasses import asdict
from pathlib import Path

from redirectme.config import AppConfig

PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class InvalidProfileNameError(ValueError):
    """Raised when a profile name contains disallowed characters."""


class ProfileNotFoundError(FileNotFoundError):
    """Raised when the requested profile does not exist."""


def _profile_path(name: str, profiles_dir: str = "profiles") -> Path:
    if not PROFILE_NAME_RE.match(name):
        raise InvalidProfileNameError(f"Invalid profile name: {name!r}")
    return Path(profiles_dir) / f"{name}.json"


def save_profile(name: str, config: AppConfig, profiles_dir: str = "profiles") -> Path:
    path = _profile_path(name, profiles_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
    return path


def load_profile(name: str, profiles_dir: str = "profiles") -> AppConfig:
    path = _profile_path(name, profiles_dir)
    if not path.exists():
        raise ProfileNotFoundError(f"Profile not found: {name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    return AppConfig(**data)


def list_profiles(profiles_dir: str = "profiles") -> list[str]:
    directory = Path(profiles_dir)
    if not directory.exists():
        return []
    return sorted(p.stem for p in directory.glob("*.json"))
