from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables / .env file.

    All settings are loaded from the .env file. No hardcoded defaults.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Application
    app_name: str
    app_env: Literal["development", "staging", "production"]
    debug: bool
    api_v1_prefix: str

    # Database
    database_url: str

    # Security
    secret_key: str
    api_key_header: str

    # Analysis settings
    max_ciphertext_length: int
    default_timeout_seconds: int
    max_parallel_engines: int

    # AI Services (Gemini)
    gemini_api_key: str
    gemini_model: str
    enable_ai_formatting: bool

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def GEMINI_API_KEY(self) -> str:
        """Alias for consistency."""
        return self.gemini_api_key


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
