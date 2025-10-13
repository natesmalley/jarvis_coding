# Repository Guidelines

## Project Structure & Module Organization
- `./` (this folder): Scenario scripts, validators, and utilities (e.g., `attack_scenario_orchestrator.py`, `enterprise_scenario_validator.py`, `scenario_hec_sender.py`).
- `configs/`: JSON configs, samples, and reports used by validators and generators.
- `api/app/`: Python package scaffolding (`core/`, `routers/`, `services/`, `models/`, `utils/`) reserved for future API endpoints.
- Tests and tooling: Script-style tests live at repo root (e.g., `star_trek_integration_test.py`, `test_hec_connection.py`). Note: Some tests reference the parent project (e.g., `../event_generators`).

## Build, Test, and Development Commands
- Run a quick scenario: `python3 quick_scenario.py`
- Orchestrate scenarios: `python3 attack_scenario_orchestrator.py`
- Validate enterprise config: `python3 enterprise_scenario_validator.py`
- Validate event format: `python3 format_validator.py`
- Star Trek integration sweep: `python3 star_trek_integration_test.py` (writes `star_trek_integration_results.json`)
- HEC connection diagnostics: `S1_HEC_TOKEN=... python3 test_hec_connection.py`
- Env loading: place secrets in `.env` (see `.env.example`). Scripts auto-load `.env` and require `S1_HEC_TOKEN`.

## Coding Style & Naming Conventions
- Python 3; follow PEP 8. Use 4-space indentation and `snake_case` for files, functions, and variables.
- Prefer type hints and module-level docstrings.
- Keep secrets/config out of code; load via env vars (e.g., `S1_HEC_TOKEN`) or JSON under `configs/` when appropriate.

## Testing Guidelines
- Tests are executable scripts named `test_*.py`. Run via `python3 <file>`.
- Prefer deterministic output; mock network calls where feasible. If network is required (e.g., HEC tests), guard with env vars and document prerequisites.
- When adding generators referenced by tests, ensure ISO8601 timestamps and optional `overrides` dict are supported by the log function.

## Commit & Pull Request Guidelines
- Use clear, imperative commit messages (e.g., "feat: add vpc dns scenario", "fix: correct timestamp parsing").
- PRs should include: purpose/summary, key changes, how to run/validate (commands), config changes (`configs/*`), and screenshots/log snippets when relevant.
- Link related issues. Keep changes scoped; avoid unrelated refactors.

## Security & Configuration Tips
- Never commit secrets. Use env vars or local config files excluded from VCS.
- Avoid `verify=False` outside diagnostics; if used in tests, note it clearly and provide a secure alternative.
 - `.gitignore` excludes `.env*` and local AI config dirs. If already tracked, run `git rm -r --cached .claude` and commit.
 - Sample tokens in `configs/*.json` are fictional for storyline realism. Do not reuse them for real credentials.
