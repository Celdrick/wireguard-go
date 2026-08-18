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
