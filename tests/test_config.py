import pytest

from redirectme.config import AppConfig, ConfigError, load_config, save_config


def test_load_config_creates_default_file(tmp_path):
    config_path = tmp_path / "config.ini"
    config = load_config(str(config_path))
    assert config == AppConfig()
    assert config_path.exists()


def test_save_and_load_round_trip(tmp_path):
    config_path = tmp_path / "config.ini"
    custom = AppConfig(
        external_url="https://attacker.test",
        max_pages=42,
        max_workers=3,
        report_format="json",
        last_target="https://example.com",
    )
    save_config(custom, str(config_path))
    loaded = load_config(str(config_path))
    assert loaded == custom


def test_load_config_defaults_last_target_when_absent(tmp_path):
    """config.ini files written before last_target was added must still load fine."""
    config_path = tmp_path / "config.ini"
    config_path.write_text(
        "[general]\nexternal_url = https://evil.example.com\nmax_pages = 10\n"
        "timeout = 5\nmin_delay = 0.2\nmax_delay = 0.8\nmax_workers = 5\n"
        "[scan]\nuse_bypass_payloads = true\nrespect_robots = false\n"
        "[report]\ndefault_format = html\noutput_dir = reports\n",
        encoding="utf-8",
    )
    config = load_config(str(config_path))
    assert config.last_target == ""


def test_load_config_rejects_invalid_int(tmp_path):
    config_path = tmp_path / "config.ini"
    config_path.write_text(
        "[general]\nexternal_url = https://evil.example.com\nmax_pages = abc\n"
        "timeout = 5\nmin_delay = 2.0\nmax_delay = 5.0\nmax_workers = 5\n"
        "[scan]\nuse_bypass_payloads = true\nrespect_robots = false\n"
        "[report]\ndefault_format = html\noutput_dir = reports\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(str(config_path))


def test_load_config_rejects_invalid_report_format(tmp_path):
    config_path = tmp_path / "config.ini"
    config_path.write_text(
        "[general]\nexternal_url = https://evil.example.com\nmax_pages = 10\n"
        "timeout = 5\nmin_delay = 2.0\nmax_delay = 5.0\nmax_workers = 5\n"
        "[scan]\nuse_bypass_payloads = true\nrespect_robots = false\n"
        "[report]\ndefault_format = pdf\noutput_dir = reports\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_config(str(config_path))
