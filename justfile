# vyos-onecontext - VyOS configuration integration with OpenNebula contextualization
#
# This justfile defines common development tasks for the vyos-onecontext project.
# All commands use `uv run` to execute within the project's virtual environment.

# Show available recipes
default:
    @just --list

# === Quality Checks ===

# Run linting checks with ruff
lint:
    uv run ruff check src/ tests/

# Run type checking with mypy
typecheck:
    uv run mypy src/

# Run tests with pytest
test:
    uv run pytest

# Run all checks (lint, typecheck, test) - CI gate
check: lint typecheck test
    @echo "All checks passed!"

# === Formatting ===

# Format code with ruff
fmt:
    uv run ruff format src/ tests/

# Check formatting without making changes
fmt-check:
    uv run ruff format --check src/ tests/

# === Development ===

# Install dependencies
install:
    uv sync

# Update dependencies
update:
    uv lock --upgrade
