"""Runtime configuration settings for API Security Testing Lab."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings and defaults for apisec."""

    app_name: str = "API Security Testing Lab"
    app_version: str = "0.1.0"
    debug: bool = False

    # Base data directory & database
    base_data_dir: Path = Path.home() / ".apisec"
    db_name: str = "apisec.db"

    # HTTP client behavior
    request_timeout_seconds: float = 5.0
    max_redirects: int = 5
    default_concurrency: int = 5
    rate_limit_delay_seconds: float = 0.05

    # API control plane
    api_host: str = "127.0.0.1"
    api_port: int = 8087

    # Vulnerable Mock Lab
    lab_host: str = "127.0.0.1"
    lab_port: int = 8888

    model_config = SettingsConfigDict(
        env_prefix="APISEC_",
        env_file=".env",
        extra="ignore",
    )

    @property
    def db_path(self) -> Path:
        """Return resolved path to SQLite database."""
        self.base_data_dir.mkdir(parents=True, exist_ok=True)
        return self.base_data_dir / self.db_name


settings = Settings()
