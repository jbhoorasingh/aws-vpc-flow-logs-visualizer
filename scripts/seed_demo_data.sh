#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR/backend"

poetry run python manage.py seed_demo_data \
  --reset \
  --source "${SOURCE:-demo-seed}" \
  --seed "${SEED:-20260301}" \
  --days "${DAYS:-14}" \
  --flow-pairs "${FLOW_PAIRS:-2200}"
