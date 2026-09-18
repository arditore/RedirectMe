import pytest

from redirectme.config import AppConfig
from redirectme.profiles import (
    InvalidProfileNameError,
    ProfileNotFoundError,
    list_profiles,
    load_profile,
    save_profile,
)


def test_save_and_load_profile_round_trip(tmp_path):
    profiles_dir = tmp_path / "profiles"
    config = AppConfig(external_url="https://attacker.test", max_pages=25)
    save_profile("rapide", config, str(profiles_dir))
    loaded = load_profile("rapide", str(profiles_dir))
    assert loaded == config


def test_list_profiles_returns_sorted_names(tmp_path):
    profiles_dir = tmp_path / "profiles"
    save_profile("b-profile", AppConfig(), str(profiles_dir))
    save_profile("a-profile", AppConfig(), str(profiles_dir))
    assert list_profiles(str(profiles_dir)) == ["a-profile", "b-profile"]


def test_list_profiles_on_missing_dir_returns_empty(tmp_path):
    assert list_profiles(str(tmp_path / "missing")) == []


def test_invalid_profile_name_rejected(tmp_path):
    with pytest.raises(InvalidProfileNameError):
        save_profile("../evil", AppConfig(), str(tmp_path / "profiles"))


def test_load_missing_profile_raises(tmp_path):
    with pytest.raises(ProfileNotFoundError):
        load_profile("ghost", str(tmp_path / "profiles"))
