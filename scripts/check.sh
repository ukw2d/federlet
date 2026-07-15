#!/usr/bin/env sh
# Local quality gate — mirrors .github/workflows/ci.yml exactly so a green run
# here means CI will be green too. Run before committing/pushing:
#
#     sh scripts/check.sh
#
# The pre-push hook runs this automatically. Bypass once with:
#
#     SKIP_QUALITY_GATE=1 git push
set -e

echo "▶ ruff check (lint)"
uv run ruff check

echo "▶ ruff format --check"
uv run ruff format --check

echo "▶ mypy src"
uv run mypy src

echo "▶ pytest"
uv run pytest -q

echo "✓ local quality gate passed — safe to push"
