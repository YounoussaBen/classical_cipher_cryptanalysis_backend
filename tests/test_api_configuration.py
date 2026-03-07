from app.api.v1.router import api_router
from app.core.config import Settings


def test_history_routes_removed() -> None:
    paths = {route.path for route in api_router.routes}

    assert "/history" not in paths
    assert "/{analysis_id}" not in paths


def test_settings_no_longer_require_database_url() -> None:
    assert "database_url" not in Settings.model_fields


def test_settings_ignore_legacy_database_url(monkeypatch) -> None:
    env = {
        "APP_NAME": "Cryptanalysis Platform",
        "APP_ENV": "development",
        "DEBUG": "true",
        "API_V1_PREFIX": "/api/v1",
        "SECRET_KEY": "test-secret",
        "API_KEY_HEADER": "X-API-Key",
        "MAX_CIPHERTEXT_LENGTH": "100000",
        "DEFAULT_TIMEOUT_SECONDS": "30",
        "MAX_PARALLEL_ENGINES": "4",
        "GEMINI_API_KEY": "test-key",
        "GEMINI_MODEL": "gemini-2.5-flash-lite",
        "ENABLE_AI_FORMATTING": "false",
        "DATABASE_URL": "sqlite+aiosqlite:///./cryptanalysis.db",
    }

    for key, value in env.items():
        monkeypatch.setenv(key, value)

    settings = Settings(_env_file=None)

    assert settings.api_v1_prefix == "/api/v1"
