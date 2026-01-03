# AI-Powered Cryptanalysis of Classical Ciphers – Backend

AI-powered cryptanalysis and decryption of classical ciphers.

## Requirements

* **Python**: 3.11 or newer
* **uv**: Python package manager and virtual environment tool

Python must be installed before proceeding.

## Environment Setup

### 1. Install `uv`

```bash
pip install uv
```

Or via standalone installer if preferred:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Create and activate virtual environment

```bash
uv venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
uv sync
```

### 4. Configure environment variables

```bash
cp .env.example .env
```

## Running the Application

```bash
uv run uvicorn app.main:app --reload
```

## Running Tests

```bash
uv run pytest
```

## API Access

* **API**: [http://localhost:8000/api/v1](http://localhost:8000/api/v1)
* **Docs**: [http://localhost:8000/api/v1/docs](http://localhost:8000/api/v1/docs)
* **ReDoc**: [http://localhost:8000/api/v1/redoc](http://localhost:8000/api/v1/redoc)

## Tech Stack

* **Framework**: FastAPI
* **Database**: SQLite (async via aiosqlite)
* **ORM**: SQLAlchemy 2.0 (async)
* **Validation**: Pydantic v2
* **Migrations**: Alembic

## Development Commands

```bash
# Auto-reload server
uv run uvicorn app.main:app --reload

# Tests with coverage
uv run pytest --cov=app

# Static type checking
uv run mypy app

# Linting
uv run ruff check app
```

---
