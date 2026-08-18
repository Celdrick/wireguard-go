#!/usr/bin/env bash
set -euo pipefail

SERVER_ENDPOINT=""
SERVER_PORT="51820"
SERVER_IFACE="wg0"
SERVER_TUN_IP="10.10.0.1/24"
CLIENTS=""
OUTPUT_DIR=""
PRESHARED_KEY="false"
CONFIG_FILE=""

usage() {
	cat <<'EOF'
Usage: scripts/gen-configs.sh [--config FILE] [--server-endpoint HOST] [--server-port PORT] [--server-iface IFACE] [--server-tun-ip CIDR] [--clients a,b,c] [--output-dir DIR] [--preshared-key true|false]
EOF
}

load_config() {
	[[ -z "${CONFIG_FILE}" ]] && return 0
	# shellcheck disable=SC1090
	source "${CONFIG_FILE}"
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--config) CONFIG_FILE="$2"; shift 2 ;;
		--server-endpoint) SERVER_ENDPOINT="$2"; shift 2 ;;
		--server-port) SERVER_PORT="$2"; shift 2 ;;
		--server-iface) SERVER_IFACE="$2"; shift 2 ;;
		--server-tun-ip) SERVER_TUN_IP="$2"; shift 2 ;;
		--clients) CLIENTS="$2"; shift 2 ;;
		--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
		--preshared-key) PRESHARED_KEY="$2"; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) printf 'unknown argument: %s\n' "$1" >&2; exit 1 ;;
		esac
	done
}

client_ip() {
	local index="$1"
	printf '10.10.0.%d' "$((index + 2))"
}

require_hex_file() {
	local path="$1" regex="$2"
	grep -Eq "$regex" "$path" || {
		printf 'invalid generated key at %s\n' "$path" >&2
		exit 1
	}
}

main() {
	parse_args "$@"
	load_config
	parse_args "$@"

	[[ -n "${SERVER_ENDPOINT}" ]] || { printf 'SERVER_ENDPOINT is required\n' >&2; exit 1; }
	[[ -n "${CLIENTS}" ]] || { printf 'CLIENTS is required\n' >&2; exit 1; }
	[[ -n "${OUTPUT_DIR}" ]] || { printf 'OUTPUT_DIR is required\n' >&2; exit 1; }
	[[ ! -e "${OUTPUT_DIR}" ]] || { printf 'output directory already exists: %s\n' "${OUTPUT_DIR}" >&2; exit 1; }
	[[ "${PRESHARED_KEY}" == "true" || "${PRESHARED_KEY}" == "false" ]] || {
		printf 'PRESHARED_KEY must be true or false\n' >&2
		exit 1
	}
	command -v wg-gm >/dev/null || {
		printf 'wg-gm is required but was not found in PATH\n' >&2
		exit 1
	}

	mkdir -p "${OUTPUT_DIR}/server/clients" "${OUTPUT_DIR}/clients"

	local server_private server_public psk=""
	server_private="$(wg-gm genkey)"
	server_public="$(printf '%s\n' "${server_private}" | wg-gm pubkey)"
	printf '%s\n' "${server_private}" > "${OUTPUT_DIR}/server/privatekey"
	printf '%s\n' "${server_public}" > "${OUTPUT_DIR}/server/publickey"

	if [[ "${PRESHARED_KEY}" == "true" ]]; then
		psk="$(wg-gm genpsk)"
		printf '%s\n' "${psk}" > "${OUTPUT_DIR}/server/preshared_key"
	fi

	require_hex_file "${OUTPUT_DIR}/server/privatekey" '^[0-9a-f]{64}$'
	require_hex_file "${OUTPUT_DIR}/server/publickey" '^[0-9a-f]{130}$'

	local server_conf="${OUTPUT_DIR}/server/server.conf"
	{
		printf 'private_key=%s\n' "${server_private}"
		printf 'listen_port=%s\n' "${SERVER_PORT}"
		printf '\n'
	} > "${server_conf}"
	: > "${OUTPUT_DIR}/server/up.sh"

	IFS=',' read -r -a client_names <<< "${CLIENTS}"
	local idx=0
	for raw_name in "${client_names[@]}"; do
		local name
		name="$(printf '%s' "${raw_name}" | tr -d '[:space:]')"
		[[ -n "${name}" ]] || continue

		local cip cdir cpriv cpub cconf peerconf
		cip="$(client_ip "${idx}")"
		cdir="${OUTPUT_DIR}/clients/${name}"
		mkdir -p "${cdir}"
		cpriv="$(wg-gm genkey)"
		cpub="$(printf '%s\n' "${cpriv}" | wg-gm pubkey)"
		printf '%s\n' "${cpriv}" > "${cdir}/privatekey"
		printf '%s\n' "${cpub}" > "${cdir}/publickey"

		cconf="${cdir}/client.conf"
		{
			printf 'private_key=%s\n' "${cpriv}"
			printf 'public_key=%s\n' "${server_public}"
			[[ -n "${psk}" ]] && printf 'preshared_key=%s\n' "${psk}"
			printf 'endpoint=%s:%s\n' "${SERVER_ENDPOINT}" "${SERVER_PORT}"
			printf 'allowed_ip=10.10.0.1/32\n'
			printf 'persistent_keepalive_interval=25\n'
		} > "${cconf}"

		peerconf="${OUTPUT_DIR}/server/clients/${name}.peer.conf"
		{
			printf 'public_key=%s\n' "${cpub}"
			[[ -n "${psk}" ]] && printf 'preshared_key=%s\n' "${psk}"
			printf 'allowed_ip=%s/32\n' "${cip}"
		} > "${peerconf}"

		{
			printf '\npublic_key=%s\n' "${cpub}"
			[[ -n "${psk}" ]] && printf 'preshared_key=%s\n' "${psk}"
			printf 'allowed_ip=%s/32\n' "${cip}"
		} >> "${server_conf}"
		: > "${cdir}/linux-up.sh"
		: > "${cdir}/windows-up.ps1"

		idx=$((idx + 1))
	done
}

main "$@"
