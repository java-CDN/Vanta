#!/usr/bin/env bash
# Fails if source code references known telemetry/analytics endpoints or SDKs.
set -euo pipefail
cd "$(dirname "$0")/.."
pattern='google-analytics|googletagmanager|sentry\.io|segment\.(io|com)|mixpanel|amplitude\.com|posthog|datadoghq|app-measurement|telemetry\.(send|post)'
if grep -RInE "$pattern" --include='*.rs' --include='*.ts' --include='*.tsx' --include='*.mjs' --include='*.toml' --include='*.json' --include='*.html' \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=dist-mock --exclude-dir=target --exclude=package-lock.json \
  crates apps 2>/dev/null | grep -v 'no-telemetry'; then
  echo "telemetry reference found" >&2; exit 1
fi
# The desktop app ships no updater and loads nothing remote: the only URLs allowed in its
# config are the local dev server and Tauri's own IPC origin.
desk="apps/desktop/src-tauri/tauri.conf.json apps/desktop/src-tauri/Cargo.toml apps/desktop/ui/index.html"
if grep -nE 'tauri-plugin-updater|"updater"' $desk; then
  echo "updater in the desktop app" >&2; exit 1
fi
remote=$(grep -ohE 'https?://[^ "'"'"';]+' $desk | grep -vE '^https?://(127\.0\.0\.1:1420|ipc\.localhost)$' || true)
if [ -n "$remote" ]; then
  echo "remote URL in the desktop app config: $remote" >&2; exit 1
fi
echo "no-telemetry: ok"
