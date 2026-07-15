#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if ! command -v cargo >/dev/null 2>&1; then
  printf 'BLOCKED: cargo is required for mode-switch E2E\n' >&2
  exit 2
fi
if [[ "${AMG_SKIP_MODE_SWITCH_E2E:-0}" == "1" ]]; then
  printf 'SKIPPED: AMG_SKIP_MODE_SWITCH_E2E=1\n'
  exit 0
fi

# Simulates maintenance-isolated adapter -> proxy -> adapter transitions with
# one schema-v2 SQLite database and no overlapping gateway task. Physical Acorn
# maintenance/FRP changes remain a deployment smoke prerequisite.
cargo test --manifest-path "$ROOT_DIR/Cargo.toml" --test proxy_integration \
  adapter_proxy_adapter_mode_switch_reuses_state_without_exposing_the_app -- --nocapture
printf 'Fail-closed adapter/proxy mode-switch drill passed.\n'
