# Repository Guidelines

## Project Structure & Module Organization
Core scripts live at the repo root: `get_comments.py` and `get_user.py` drive comment harvesting and user-profile pulls, while `utils.py` bundles crawler logic, HTTP helpers, and logging. All hard-coded configuration, including device headers and cookie placeholders, sits in `constants.py`. Generated payloads write to the `json/` directory; keep large artifacts out of version control. `README_SCROLL.md` documents the Chrome DevTools scroll helper that complements the crawler.

## Build, Test, and Development Commands
Create an isolated environment before hacking:
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install httpx pydantic gmssl
```
Use `python3 get_comments.py` to fetch sample comment pages and `python3 get_user.py` for a profile snapshot. Both scripts log to `logs/` as configured and emit JSON files under `json/`. Adjust hard-coded IDs and pagination constants inside each script when exercising new scenarios.

## Coding Style & Naming Conventions
Follow standard Python style: 4-space indentation, lower_snake_case for variables and functions, UpperCamelCase for classes, and meaningful module-level constants in UPPER_SNAKE_CASE. Preserve the existing bilingual docstrings and logging messages when extending functionality. Prefer type hints and helper methods in `utils.py` rather than duplicating request logic in the entry scripts.

## Testing Guidelines
No automated suite exists today, so at minimum run the target script, inspect the JSON payloads, and confirm `has_more` and cursor fields progress as expected. When adding reusable utilities, sketch lightweight unit tests under `tests/` using `pytest` and run them with `pytest -q`. Mock network calls where possible to avoid triggering Douyin rate limits.

## Commit & Pull Request Guidelines
History is compact and imperative (`init`). Continue with concise, present-tense messages such as `Add cursor retry logic` or `Refine comment serializer`. Pull requests should link the motivating issue, describe configuration changes (notably cookie edits), list manual verification steps, and attach sample output diffs when behavior changes.

## Security & Configuration Tips
`constants.py` ships with placeholder cookies and tokens—replace them locally before running and never commit real credentials. Consider moving secrets to environment variables or `.env.local` ignored by git. Document any proxy requirements in the PR so reviewers can reproduce the crawl safely.
