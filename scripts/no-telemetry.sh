#!/usr/bin/env bash
# Fails if source code references known telemetry/analytics endpoints or SDKs.
set -euo pipefail
cd "$(dirname "$0")/.."
pattern='google-analytics|googletagmanager|sentry\.io|segment\.(io|com)|mixpanel|amplitude\.com|posthog|datadoghq|app-measurement|telemetry\.(send|post)'
if grep -RInE "$pattern" --include='*.rs' --include='*.ts' --include='*.tsx' --include='*.toml' --include='*.json' crates app 2>/dev/null | grep -v 'no-telemetry'; then
  echo "telemetry reference found" >&2; exit 1
fi
echo "no-telemetry: ok"
