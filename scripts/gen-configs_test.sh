#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

OUT="$TMPDIR/out"

bash "$ROOT/scripts/gen-configs.sh" \
  --config "$ROOT/scripts/testdata/generator.env" \
  --output-dir "$OUT"

test -f "$OUT/server/privatekey"
test -f "$OUT/server/publickey"
test -f "$OUT/server/server.conf"
test -f "$OUT/server/up.sh"
test -f "$OUT/server/clients/win1.peer.conf"
test -f "$OUT/server/clients/linux1.peer.conf"

test -f "$OUT/clients/win1/privatekey"
test -f "$OUT/clients/win1/publickey"
test -f "$OUT/clients/win1/client.conf"
test -f "$OUT/clients/win1/linux-up.sh"
test -f "$OUT/clients/win1/windows-up.ps1"

test -f "$OUT/clients/linux1/privatekey"
test -f "$OUT/clients/linux1/publickey"
test -f "$OUT/clients/linux1/client.conf"
test -f "$OUT/clients/linux1/linux-up.sh"
test -f "$OUT/clients/linux1/windows-up.ps1"

grep -Eq '^[0-9a-f]{64}$' "$OUT/server/privatekey"
grep -Eq '^[0-9a-f]{130}$' "$OUT/server/publickey"
grep -q 'listen_port=51820' "$OUT/server/server.conf"
grep -q 'allowed_ip=10.10.0.2/32' "$OUT/server/server.conf"
grep -q 'allowed_ip=10.10.0.3/32' "$OUT/server/server.conf"
grep -q 'endpoint=203.0.113.10:51820' "$OUT/clients/win1/client.conf"
grep -q 'allowed_ip=10.10.0.1/32' "$OUT/clients/win1/client.conf"
grep -q 'persistent_keepalive_interval=25' "$OUT/clients/win1/client.conf"
grep -q 'endpoint=203.0.113.10:51820' "$OUT/clients/linux1/client.conf"
grep -q 'allowed_ip=10.10.0.1/32' "$OUT/clients/linux1/client.conf"
