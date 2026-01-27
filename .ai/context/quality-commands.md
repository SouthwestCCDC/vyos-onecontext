# Quality Commands

Quality checks use `uv run` and `just` for consistent Python environment.

## Commands

| Command | Purpose |
|---------|---------|
| `just check` | Run all quality checks (ruff check + mypy + pytest) |
| `uv run pytest tests/ -v --tb=short` | Run tests |
| `uv run ruff check src/ tests/` | Lint Python code |
| `uv run ruff format src/ tests/` | Format Python code |
| `uv run mypy src/` | Type checking |

## Pre-Push Checklist

Before pushing any changes:

```bash
just check
```

This runs ruff check, mypy, and pytest. All must pass before creating or updating a PR.

## Individual Commands

```bash
# Tests only
uv run pytest tests/ -v --tb=short

# Linting only
uv run ruff check src/ tests/
uv run ruff format src/ tests/

# Type checking only
uv run mypy src/
```

## CI Verification

After pushing, verify CI passes:

```bash
gh pr checks {N} --repo SouthwestCCDC/vyos-onecontext
```

---
*Generated with Claude Code assistance.*
