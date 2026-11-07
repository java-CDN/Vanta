#!/usr/bin/env bash
# Quality gates (Master Plan v3). Fails on the first problem.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check --workspace --target x86_64-pc-windows-gnu
bash scripts/no-telemetry.sh
echo "ALL GATES PASSED"
