"""
Central configuration, loaded from environment / .env.
This is the only module allowed to read os.environ directly (see
10-NETWORK-TUNNEL-ARCHITECTURE.md / platform abstraction principle).
"""
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


_default_data_dir = Path(__file__).resolve().parent.parent / "data"
_default_db_file = _default_data_dir / "pretweb.db"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=[str(Path(__file__).resolve().parent.parent / ".env"), ".env"],
        extra="ignore",
    )

    # Defaults to SQLite so the project runs with zero external services.
    # Point DATABASE_URL at Postgres for larger/shared deployments.
    database_url: str = f"sqlite:///{_default_db_file.as_posix()}"

    secret_key: str = "562c54c111bfd41422a83d9d745da5bb73fed7ef32e04e2a5e5199c636b34971"
    access_token_expire_minutes: int = 60 * 8

    pretweb_admin_user: str = "admin"
    pretweb_admin_password: str = "Flame@123"

    # Bind address: LAN-only by default. Do NOT set to 0.0.0.0 on a
    # machine with any public/WAN interface. See 05-SECURITY-ARCHITECTURE.md.
    bind_host: str = "0.0.0.0"
    bind_port: int = 8443

    # Root dir for vendored, UNMODIFIED upstream PRET checkout.
    pret_dir: Path = Path(__file__).resolve().parent.parent.parent / "pret"

    # Per-job hard wall-clock timeout (seconds). The job runner enforces
    # this independently of PRET's own socket timeout.
    job_timeout_seconds: int = 90

    # Max concurrent jobs. See 07-DATA-MODEL-AND-MEMORY.md §5.
    max_concurrent_jobs: int = 4

    data_dir: Path = Path(__file__).resolve().parent.parent / "data"
    job_tmp_dir: Path = Path(__file__).resolve().parent.parent / "data" / "jobs"
    test_mode: bool = False


settings = Settings()
settings.data_dir.mkdir(parents=True, exist_ok=True)
settings.job_tmp_dir.mkdir(parents=True, exist_ok=True)
