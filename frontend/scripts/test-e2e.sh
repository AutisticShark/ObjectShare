#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
: "${OBJECTSHARE_E2E_ALLOW_SETUP:?Set to 1 only for an empty disposable test installation}"
if [[ "$OBJECTSHARE_E2E_ALLOW_SETUP" != 1 ]]; then
  printf '%s\n' 'A disposable-install opt-in is required.' >&2
  exit 1
fi
mkdir -p "$root/.tmp"
work=$(mktemp -d "$root/.tmp/frontend-e2e.XXXXXXXX")
: > "$work/app.log"
pid=''
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  if [[ "${failed:-1}" != 0 ]]; then
    printf '%s\n' 'Application diagnostics:'
    node -e 'const fs=require("node:fs"); process.stdout.write(fs.readFileSync(process.argv[1],"utf8"))' "$work/app.log"
  fi
  rm -rf "$work"
}
trap cleanup EXIT

go build -o "$work/object-share" .
export OBJECTSHARE_ADDRESS=127.0.0.1:8192
export OBJECTSHARE_E2E_ORIGIN=http://127.0.0.1:8192
export OBJECTSHARE_STORAGE_SERVICE=filesystem OBJECTSHARE_STORAGE_PATH="$work/objects"
export OBJECTSHARE_RATE_LIMIT_ENABLED=false OBJECTSHARE_SECURE_COOKIES=false
export OBJECTSHARE_REDIS_URL=''
export OBJECTSHARE_JWT_SECRET="$(openssl rand -hex 48)"
export OBJECTSHARE_SETTINGS_KEY="$(openssl rand -hex 48)"
"$work/object-share" > "$work/app.log" 2>&1 &
pid=$!
node --input-type=module -e '
  const endpoint = process.env.OBJECTSHARE_E2E_ORIGIN + "/health/ready";
  for (let i = 0; i < 60; i++) {
    try { if ((await fetch(endpoint)).ok) process.exit(0); } catch {}
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error("Disposable application did not become ready.");
'
npm --prefix frontend run test:e2e
failed=0
