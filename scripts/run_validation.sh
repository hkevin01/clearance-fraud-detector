#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ -f ".venv/bin/activate" ]]; then
  source .venv/bin/activate
fi

echo "[validation] running smoke tests"
python -m pytest tests/test_validation_smoke.py -q

echo "[validation] running full suite"
python -m pytest tests/ -q

echo "[validation] complete"
