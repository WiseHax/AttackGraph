"""Application configuration via environment variables.

All configuration is read from environment variables.
No secrets are hardcoded. See .env.example for the template.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """AttackGraph application settings.

    All values are sourced from environment variables.
    """

    # Database
    database_url: str = Field(
        ...,
        description="SQLAlchemy async database URL",
    )

    # Application
    secret_key: str = Field(
        ...,
        description="Application secret key for cryptographic operations",
        min_length=16,
    )

    # Test database (optional, used only by integration tests)
    test_database_url: str | None = Field(
        default=None,
        description="SQLAlchemy async database URL for integration tests",
    )

    # App metadata
    app_name: str = "AttackGraph"
    debug: bool = False

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


def get_settings() -> Settings:
    """Create and return application settings from environment."""
    return Settings()
