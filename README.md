# Cryptanalysis Platform - Backend

Classical cipher analysis, detection, and decryption.

## Quick Start

```bash
# Install dependencies
uv sync

# Copy environment config
cp .env.example .env

# Run the server
uv run uvicorn app.main:app --reload

# Run tests
uv run pytest
```

The API will be available at:
- **API**: http://localhost:8000/api/v1
- **Docs**: http://localhost:8000/api/v1/docs
- **ReDoc**: http://localhost:8000/api/v1/redoc

## Project Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI application entry point
│   ├── dependencies.py      # Dependency injection
│   ├── api/v1/              # API version 1
│   │   ├── router.py        # Main API router
│   │   └── endpoints/       # Individual endpoint modules
│   ├── core/                # Core configuration
│   │   ├── config.py        # Settings management
│   │   └── exceptions.py    # Custom exceptions
│   ├── models/              # Data models
│   │   ├── database.py      # SQLAlchemy ORM models
│   │   └── schemas.py       # Pydantic schemas
│   ├── db/                  # Database layer
│   │   └── session.py       # Async session management
│   └── services/            # Business logic
│       ├── preprocessing/   # Text normalization
│       ├── analysis/        # Statistical analysis
│       ├── detection/       # Cipher detection
│       ├── engines/         # Cipher implementations
│       ├── optimization/    # Scoring & optimization
│       └── explanation/     # Human-readable output
├── tests/                   # Test suite
├── alembic/                 # Database migrations
└── docs/                    # Documentation
```

## Tech Stack

- **Framework**: FastAPI
- **Database**: SQLite (async via aiosqlite)
- **ORM**: SQLAlchemy 2.0 (async)
- **Validation**: Pydantic v2
- **Migrations**: Alembic

## Documentation

See the [docs/](docs/) folder for detailed documentation:
- [API Reference](docs/api-reference.md) - Complete endpoint documentation

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_NAME` | Application name | Cryptanalysis Platform |
| `APP_ENV` | Environment (development/staging/production) | development |
| `DEBUG` | Enable debug mode | true |
| `DATABASE_URL` | SQLite database URL | sqlite+aiosqlite:///./cryptanalysis.db |
| `SECRET_KEY` | Secret key for security | (change in production) |
| `MAX_CIPHERTEXT_LENGTH` | Maximum input length | 100000 |
| `DEFAULT_TIMEOUT_SECONDS` | Engine timeout | 30 |

## Development

```bash
# Run with auto-reload
uv run uvicorn app.main:app --reload

# Run tests with coverage
uv run pytest --cov=app

# Type checking
uv run mypy app

# Linting
uv run ruff check app
```

## Adding New Cipher Engines

1. Create a new file in `app/services/engines/<family>/`
2. Implement the `CipherEngine` base class
3. Decorate with `@EngineRegistry.register`

Example:
```python
from app.services.engines.base import CipherEngine
from app.services.engines.registry import EngineRegistry

@EngineRegistry.register
class MyCipherEngine(CipherEngine):
    name = "My Cipher"
    cipher_type = CipherType.MY_CIPHER
    cipher_family = CipherFamily.MONOALPHABETIC
    # ... implement abstract methods
```

## License

MIT
