# Repository Guidelines

## Project Structure & Module Organization
- `api/`: FastAPI service (`app/` with `routers/`, `models/`, `services/`, `utils/`).
- `event_generators/`: Scripts that emit sample/security events.
- `parsers/`: Parser definitions and metadata.
- `scenarios/`: Scenario configs used in validation and demos.
- `testing/`: Validation utilities and comprehensive generator tests.
- `docs/`: Project docs and guides.

## Build, Test, and Development
- Setup (recommended):
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -r api/requirements.txt`
- Run API locally:
  - `python api/start_api.py` (http://localhost:8000)
  - Or: `cd api && uvicorn app.main:app --reload`
- Docker:
  - `docker-compose up --build` (uses `api/Dockerfile`)
  - Manual: `docker build -t jarvis-api -f api/Dockerfile . && docker run -p 8000:8000 jarvis-api`

## Coding Style & Naming Conventions
- Python 3.10+; 4‑space indentation; prefer type hints.
- Use tools pinned in `api/requirements.txt`:
  - Format: `black api`
  - Lint: `flake8 api`
  - Types: `mypy api/app`
- Naming: `snake_case` for files/functions, `PascalCase` for classes, module/package names in lowercase.

## Testing Guidelines
- Framework: `pytest` (+ `pytest-asyncio`, `pytest-cov`).
- Location: `api/tests/` and root‑level `api/test_*.py`.
- Naming: files `test_*.py`, tests `test_*` functions.
- Run: `cd api && pytest tests/`
- Coverage: `pytest tests/ --cov=app --cov-report=html` (HTML at `api/htmlcov/`).

## Commit & Pull Request Guidelines
- Commit style: follow Conventional Commits when possible (`feat:`, `fix:`, `docs:`, `chore:`). Keep messages imperative and scoped.
- Branches: short, hyphenated names (e.g., `feat/parser-download-retries`).
- PRs must include:
  - Clear description and rationale; link issues (e.g., `Closes #123`).
  - Scope of changes (files/areas touched) and testing notes.
  - For API changes, include curl examples and screenshots of `/api/v1/docs` if relevant.

## Security & Configuration
- Never commit secrets. Use `api/.env` (copy from `api/.env.example` via `cp api/.env.example api/.env`).
- Key vars: `DISABLE_AUTH`, `API_KEYS_*`, `SECRET_KEY`, `DATABASE_URL`.
- In Docker, data persists under `api/data/` (mounted to `/app/data`).
- Production: keep `DISABLE_AUTH=false`, use strong keys, configure CORS appropriately.

