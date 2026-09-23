"""Chargement et sauvegarde de la configuration RedirectMe (config.ini)."""
from __future__ import annotations

import configparser
from dataclasses import dataclass
from pathlib import Path

VALID_REPORT_FORMATS = {"txt", "json", "csv", "html"}


class ConfigError(ValueError):
    """Levée quand config.ini contient une valeur invalide."""


@dataclass
class AppConfig:
    external_url: str = "https://evil.example.com"
    max_pages: int = 100
    timeout: int = 5
    min_delay: float = 0.2
    max_delay: float = 0.8
    max_workers: int = 5
    use_bypass_payloads: bool = True
    respect_robots: bool = False
    report_format: str = "html"
    report_output_dir: str = "reports"


def _to_parser(config: AppConfig) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser["general"] = {
        "external_url": config.external_url,
        "max_pages": str(config.max_pages),
        "timeout": str(config.timeout),
        "min_delay": str(config.min_delay),
        "max_delay": str(config.max_delay),
        "max_workers": str(config.max_workers),
    }
    parser["scan"] = {
        "use_bypass_payloads": str(config.use_bypass_payloads).lower(),
        "respect_robots": str(config.respect_robots).lower(),
    }
    parser["report"] = {
        "default_format": config.report_format,
        "output_dir": config.report_output_dir,
    }
    return parser


def save_config(config: AppConfig, path: str = "config.ini") -> None:
    parser = _to_parser(config)
    with open(path, "w", encoding="utf-8") as f:
        parser.write(f)


def load_config(path: str = "config.ini") -> AppConfig:
    config_path = Path(path)
    if not config_path.exists():
        default = AppConfig()
        save_config(default, path)
        return default

    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")

    try:
        general = parser["general"]
        scan = parser["scan"]
        report = parser["report"]
        config = AppConfig(
            external_url=general.get("external_url", AppConfig.external_url),
            max_pages=general.getint("max_pages"),
            timeout=general.getint("timeout"),
            min_delay=general.getfloat("min_delay"),
            max_delay=general.getfloat("max_delay"),
            max_workers=general.getint("max_workers"),
            use_bypass_payloads=scan.getboolean("use_bypass_payloads"),
            respect_robots=scan.getboolean("respect_robots"),
            report_format=report.get("default_format", AppConfig.report_format),
            report_output_dir=report.get("output_dir", AppConfig.report_output_dir),
        )
    except (KeyError, ValueError) as exc:
        raise ConfigError(f"config.ini invalide ({path}) : {exc}") from exc

    if config.report_format not in VALID_REPORT_FORMATS:
        raise ConfigError(
            f"Format de rapport invalide dans config.ini : {config.report_format!r} "
            f"(attendu : {sorted(VALID_REPORT_FORMATS)})"
        )

    return config
