#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if ! command -v cargo >/dev/null 2>&1; then
  printf 'BLOCKED: cargo is required for proxy-mode E2E\n' >&2
  exit 2
fi
if [[ "${AMG_SKIP_PROXY_E2E:-0}" == "1" ]]; then
  printf 'SKIPPED: AMG_SKIP_PROXY_E2E=1\n'
  exit 0
fi

# This repository-local harness uses ephemeral loopback gateway/upstream/TLS
# fixtures. It never prints cookies, tokens, or cookie secrets. The separate
# real-auth harness remains the gate for the pinned external auth-mini checkout.
cargo test --manifest-path "$ROOT_DIR/Cargo.toml" --test proxy_integration -- --nocapture
printf 'Direct proxy-mode integration E2E passed.\n'
