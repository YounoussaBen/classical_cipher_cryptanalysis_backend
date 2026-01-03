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


## Tech Stack

- **Framework**: FastAPI
- **Database**: SQLite (async via aiosqlite)
- **ORM**: SQLAlchemy 2.0 (async)
- **Validation**: Pydantic v2
- **Migrations**: Alembic

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
