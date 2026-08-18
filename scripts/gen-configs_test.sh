#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
BIN="$TMPDIR/bin"
mkdir -p "$BIN"
GO_BIN="$(command -v go || true)"
if [[ -z "$GO_BIN" ]]; then
  for candidate in /home/ubuntu/.local/go/go/bin/go /usr/local/go/bin/go; do
    [[ -x "$candidate" ]] && { GO_BIN="$candidate"; break; }
  done
fi
[[ -n "$GO_BIN" ]] || { echo "go is required to build wg-gm" >&2; exit 1; }
# go build needs the module root as its working directory, so this harness works
# no matter where it is invoked from.
(cd "$ROOT" && "$GO_BIN" build -o "$BIN/wg-gm" ./cmd/wg-gm)
PATH="$BIN:$PATH"

# device/uapi.go treats a blank line as "end of set operation", and every other
# line must be key=value. A config violating either rule is silently truncated or
# rejected by wg-gm setconf, so assert the shape of everything we generate.
assert_setconf_safe() {
  local file="$1" lineno=0 line
  while IFS= read -r line || [[ -n "$line" ]]; do
    lineno=$((lineno + 1))
    if [[ -z "$line" ]]; then
      echo "$file:$lineno: blank line truncates wg-gm setconf" >&2
      exit 1
    fi
    if [[ ! "$line" =~ ^[a-z_]+=.+$ ]]; then
      echo "$file:$lineno: not a UAPI key=value line: $line" >&2
      exit 1
    fi
  done < "$file"
  ((lineno > 0)) || { echo "$file: empty config" >&2; exit 1; }
}

assert_tree_setconf_safe() {
  local root="$1" file
  while IFS= read -r file; do
    assert_setconf_safe "$file"
  done < <(find "$root" -name '*.conf' -type f | sort)
}

assert_mode() {
  local file="$1" want="$2" got
  got="$(stat -c '%a' "$file")"
  [[ "$got" == "$want" ]] || { echo "$file: mode $got, want $want" >&2; exit 1; }
}

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

assert_tree_setconf_safe "$OUT"
# Both peers must survive the whole file; a stray blank line would hide the second.
[[ "$(grep -c '^public_key=' "$OUT/server/server.conf")" == 2 ]]

assert_mode "$OUT/server/privatekey" 600
assert_mode "$OUT/server/server.conf" 600
assert_mode "$OUT/clients/win1/privatekey" 600
assert_mode "$OUT/clients/win1/client.conf" 600
assert_mode "$OUT/server/clients/win1.peer.conf" 600

BLANK_LINE_CONF="$TMPDIR/blank-line.conf"
printf 'private_key=%064d\n\npublic_key=%0130d\n' 0 0 > "$BLANK_LINE_CONF"
if (assert_setconf_safe "$BLANK_LINE_CONF") >/dev/null 2>&1; then
  echo "expected blank-line detection to fail" >&2
  exit 1
fi

grep -q 'wireguard-go-gm -f wg0' "$OUT/server/up.sh"
grep -q 'wg-gm setconf wg0 server.conf' "$OUT/server/up.sh"
grep -q 'ip addr add 10.10.0.1/24 dev wg0' "$OUT/server/up.sh"
grep -q 'wireguard-go-gm -f wg0' "$OUT/clients/win1/linux-up.sh"
grep -q 'wg-gm setconf wg0 client.conf' "$OUT/clients/win1/linux-up.sh"
grep -q 'New-NetIPAddress' "$OUT/clients/win1/windows-up.ps1"
grep -q 'wg-gm.exe setconf wg0 client.conf' "$OUT/clients/win1/windows-up.ps1"

PSK_OUT="$TMPDIR/out-psk"
bash "$ROOT/scripts/gen-configs.sh" \
  --config "$ROOT/scripts/testdata/generator.env" \
  --output-dir "$PSK_OUT" \
  --preshared-key true \
  --server-endpoint 198.51.100.7

grep -Eq '^[0-9a-f]{64}$' "$PSK_OUT/server/preshared_key"
grep -q 'preshared_key=' "$PSK_OUT/server/server.conf"
grep -q 'preshared_key=' "$PSK_OUT/clients/win1/client.conf"
grep -q 'endpoint=198.51.100.7:51820' "$PSK_OUT/clients/win1/client.conf"
assert_tree_setconf_safe "$PSK_OUT"
assert_mode "$PSK_OUT/server/preshared_key" 600

if bash "$ROOT/scripts/gen-configs.sh" \
  --config "$ROOT/scripts/testdata/generator.env" \
  --output-dir "$OUT" >/dev/null 2>&1; then
  echo "expected overwrite protection failure" >&2
  exit 1
fi

CUSTOM_OUT="$TMPDIR/custom"
bash "$ROOT/scripts/gen-configs.sh" \
  --config "$ROOT/scripts/testdata/generator.env" \
  --server-tun-ip 192.0.2.10/29 \
  --clients alpha,beta \
  --output-dir "$CUSTOM_OUT"

grep -q 'allowed_ip=192.0.2.11/32' "$CUSTOM_OUT/server/server.conf"
grep -q 'allowed_ip=192.0.2.12/32' "$CUSTOM_OUT/server/server.conf"
grep -q 'allowed_ip=192.0.2.10/32' "$CUSTOM_OUT/clients/alpha/client.conf"
assert_tree_setconf_safe "$CUSTOM_OUT"

# Helper scripts must follow the derived server IP, not a hardcoded 10.10.0.1.
grep -q 'ip addr add 192.0.2.10/29 dev wg0' "$CUSTOM_OUT/server/up.sh"
grep -q 'ip route add 192.0.2.10/32 dev wg0' "$CUSTOM_OUT/clients/alpha/linux-up.sh"
grep -q 'DestinationPrefix "192.0.2.10/32"' "$CUSTOM_OUT/clients/alpha/windows-up.ps1"
grep -q 'ip addr add 192.0.2.11/32 dev wg0' "$CUSTOM_OUT/clients/alpha/linux-up.sh"
! grep -q '10\.10\.0\.1' "$CUSTOM_OUT/clients/alpha/linux-up.sh"
! grep -q '10\.10\.0\.1' "$CUSTOM_OUT/clients/alpha/windows-up.ps1"

DUPLICATE_OUT="$TMPDIR/duplicate"
if bash "$ROOT/scripts/gen-configs.sh" \
  --config "$ROOT/scripts/testdata/generator.env" \
  --clients 'dup, dup' \
  --output-dir "$DUPLICATE_OUT" >/dev/null 2>&1; then
  echo "expected duplicate client name failure" >&2
  exit 1
fi
test ! -e "$DUPLICATE_OUT"

INVALID_NAME_OUT="$TMPDIR/invalid-name"
if bash "$ROOT/scripts/gen-configs.sh" \
  --config "$ROOT/scripts/testdata/generator.env" \
  --clients '../escape' \
  --output-dir "$INVALID_NAME_OUT" >/dev/null 2>&1; then
  exit 1
fi
test ! -e "$INVALID_NAME_OUT"

OVERFLOW_OUT="$TMPDIR/overflow"
if bash "$ROOT/scripts/gen-configs.sh" \
  --config "$ROOT/scripts/testdata/generator.env" \
  --server-tun-ip 10.20.30.1/30 \
  --clients one,two \
  --output-dir "$OVERFLOW_OUT" >/dev/null 2>&1; then
  exit 1
fi
test ! -e "$OVERFLOW_OUT"

BAD_BIN="$TMPDIR/bad-bin"
BAD_STATE="$TMPDIR/bad-state"
mkdir -p "$BAD_BIN"
cat > "$BAD_BIN/wg-gm" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case "$1" in
genkey)
  if [[ "${BAD_MODE:-}" == "client" ]]; then
    count=0
    [[ -f "$WG_GM_STATE" ]] && count="$(<"$WG_GM_STATE")"
    count=$((count + 1))
    printf '%s\n' "$count" > "$WG_GM_STATE"
    [[ "$count" == 2 ]] && { printf 'invalid\n'; exit 0; }
  fi
  printf '%064d\n' 0
  ;;
pubkey)
  read -r _
  printf '%0130d\n' 0
  ;;
genpsk)
  [[ "${BAD_MODE:-}" == "psk" ]] && { printf 'invalid\n'; exit 0; }
  printf '%064d\n' 0
  ;;
esac
EOF
chmod +x "$BAD_BIN/wg-gm"

BAD_CLIENT_OUT="$TMPDIR/bad-client"
if PATH="$BAD_BIN:$PATH" BAD_MODE=client WG_GM_STATE="$BAD_STATE" \
  bash "$ROOT/scripts/gen-configs.sh" \
    --config "$ROOT/scripts/testdata/generator.env" \
    --clients badclient \
    --output-dir "$BAD_CLIENT_OUT" >/dev/null 2>&1; then
  exit 1
fi
test ! -f "$BAD_CLIENT_OUT/clients/badclient/privatekey"

BAD_PSK_OUT="$TMPDIR/bad-psk"
if PATH="$BAD_BIN:$PATH" BAD_MODE=psk \
  bash "$ROOT/scripts/gen-configs.sh" \
    --config "$ROOT/scripts/testdata/generator.env" \
    --preshared-key true \
    --output-dir "$BAD_PSK_OUT" >/dev/null 2>&1; then
  exit 1
fi
test ! -e "$BAD_PSK_OUT"
