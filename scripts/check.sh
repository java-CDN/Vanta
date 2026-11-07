#!/usr/bin/env bash
# Quality gates (Master Plan v3). Fails on the first problem.
#
# The Tauri shell (apps/desktop/src-tauri, crate vanta-desktop) is excluded from the Rust
# gates here: it links WebView2 on Windows and webkit2gtk elsewhere, and needs the built UI.
# Windows CI (.github/workflows/ci.yml, job "desktop") runs clippy and `tauri build` for it.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all --check
cargo clippy --workspace --exclude vanta-desktop --all-targets -- -D warnings
cargo test --workspace --exclude vanta-desktop
cargo check --workspace --exclude vanta-desktop --target x86_64-pc-windows-gnu
bash scripts/no-telemetry.sh
# Desktop UI: typecheck, unit tests, both builds, bundle budget, headless smoke (mock build).
if command -v npm >/dev/null; then
  (
    cd apps/desktop
    [ -d node_modules ] || npm ci
    npm test
    npm run build
    npm run size
    npm run build:mock
    npm run smoke
  )
else
  echo "npm not found: desktop UI gates skipped" >&2
fi
echo "ALL GATES PASSED"
