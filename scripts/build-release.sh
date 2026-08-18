#!/usr/bin/env bash
# Cross-build wireguard-go-gm (daemon) and wg-gm (CLI) for release artifacts.
#
# Requires github.com/emmansun/gmsm at ../gmsm (see go.mod replace).
#
# Usage:
#   bash scripts/build-release.sh
#   TARGETS=linux-amd64 bash scripts/build-release.sh
#   VERSION=0.2.0-gm DIST=./dist bash scripts/build-release.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${DIST:-$ROOT/dist}"
VERSION="${VERSION:-0.1.0-gm}"
TARGETS="${TARGETS:-linux-amd64 linux-arm64 windows-amd64 windows-arm64}"

if [[ ! -f "$ROOT/../gmsm/go.mod" ]]; then
	echo "ERROR: expected gmsm at ../gmsm (go.mod replace); clone https://github.com/emmansun/gmsm.git there" >&2
	exit 1
fi

mkdir -p "$DIST"
cd "$ROOT"

build_one() {
	local spec=$1
	local os=${spec%-*}
	local arch=${spec#*-}
	local ext=""

	if [[ "$os" == "windows" ]]; then
		ext=".exe"
	fi

	local out="$DIST/${os}-${arch}"
	mkdir -p "$out"

	echo "==> building ${os}/${arch}..."
	env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
		go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
		-o "$out/wireguard-go-gm${ext}" ./

	env CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
		go build -trimpath -ldflags "-s -w" \
		-o "$out/wg-gm${ext}" ./cmd/wg-gm

	local tarball="$DIST/wireguard-gm-${VERSION}-${os}-${arch}.tar.gz"
	if [[ "$os" == "windows" ]]; then
		tar -C "$out" -czf "$tarball" \
			"wireguard-go-gm${ext}" "wg-gm${ext}"
	else
		tar -C "$out" -czf "$tarball" \
			"wireguard-go-gm${ext}" "wg-gm${ext}"
	fi
	echo "    -> $tarball"
}

for spec in $TARGETS; do
	build_one "$spec"
done

echo ""
echo "Builds written to $DIST/"
