"""Foundation and configuration unit tests."""

from pathlib import Path

from apisec.config.settings import Settings, settings


def test_default_settings() -> None:
    """Verify default configuration attributes and types."""
    assert settings.app_name == "API Security Testing Lab"
    assert settings.app_version == "0.1.0"
    assert settings.request_timeout_seconds == 5.0
    assert settings.api_port == 8087
    assert settings.lab_port == 8888


def test_custom_settings(temp_dir: Path) -> None:
    """Verify overridden settings correctly generate database path in temp dir."""
    custom = Settings(base_data_dir=temp_dir, db_name="custom_api.db", api_port=9099)
    assert custom.api_port == 9099
    assert custom.db_path == temp_dir / "custom_api.db"
    assert custom.db_path.parent.exists()
