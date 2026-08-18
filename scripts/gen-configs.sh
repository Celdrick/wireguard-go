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
TUNNEL_SERVER_IP=""
TUNNEL_SERVER_INT=0
TUNNEL_BROADCAST_INT=0

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
	integer_to_ip "$((TUNNEL_SERVER_INT + index + 1))"
}

ip_to_integer() {
	local ip="$1" octet
	local -a octets

	[[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
	IFS='.' read -r -a octets <<< "$ip"
	for octet in "${octets[@]}"; do
		((10#$octet <= 255)) || return 1
	done
	printf '%d' "$(((10#${octets[0]} << 24) + (10#${octets[1]} << 16) + (10#${octets[2]} << 8) + 10#${octets[3]}))"
}

integer_to_ip() {
	local ip="$1"
	printf '%d.%d.%d.%d' \
		"$(((ip >> 24) & 255))" "$(((ip >> 16) & 255))" \
		"$(((ip >> 8) & 255))" "$((ip & 255))"
}

parse_tunnel_cidr() {
	local ip prefix extra mask network

	IFS='/' read -r ip prefix extra <<< "$SERVER_TUN_IP"
	[[ -n "$ip" && -n "$prefix" && -z "$extra" && "$prefix" =~ ^[0-9]+$ ]] || {
		printf 'SERVER_TUN_IP must be an IPv4 CIDR\n' >&2
		exit 1
	}
	((10#$prefix <= 30)) || {
		printf 'SERVER_TUN_IP prefix must be between 0 and 30\n' >&2
		exit 1
	}
	TUNNEL_SERVER_INT="$(ip_to_integer "$ip")" || {
		printf 'SERVER_TUN_IP must be an IPv4 CIDR\n' >&2
		exit 1
	}
	mask=$(((0xFFFFFFFF << (32 - 10#$prefix)) & 0xFFFFFFFF))
	network=$((TUNNEL_SERVER_INT & mask))
	TUNNEL_BROADCAST_INT=$((network | ((~mask) & 0xFFFFFFFF)))
	((TUNNEL_SERVER_INT > network && TUNNEL_SERVER_INT < TUNNEL_BROADCAST_INT)) || {
		printf 'SERVER_TUN_IP must use a usable host address\n' >&2
		exit 1
	}
	TUNNEL_SERVER_IP="$(integer_to_ip "$TUNNEL_SERVER_INT")"
}

require_hex_value() {
	local label="$1" value="$2" regex="$3"
	[[ "$value" =~ $regex ]] || {
		printf 'invalid generated key: %s\n' "$label" >&2
		exit 1
	}
}

write_server_up() {
	cat > "${OUTPUT_DIR}/server/up.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
sudo LOG_LEVEL=verbose ./wireguard-go-gm -f ${SERVER_IFACE} &
echo "Run in a second terminal: sudo ./wg-gm setconf ${SERVER_IFACE} server.conf"
echo "Then configure the interface address:"
echo "  sudo ip addr add ${SERVER_TUN_IP} dev ${SERVER_IFACE}"
echo "  sudo ip link set ${SERVER_IFACE} up"
wait
EOF
	chmod +x "${OUTPUT_DIR}/server/up.sh"
}

write_client_linux_up() {
	local path="$1" ip="$2"
	cat > "${path}/linux-up.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
sudo LOG_LEVEL=verbose ./wireguard-go-gm -f ${SERVER_IFACE} &
sleep 1
sudo ./wg-gm setconf ${SERVER_IFACE} client.conf
sudo ip addr add ${ip}/32 dev ${SERVER_IFACE}
sudo ip link set ${SERVER_IFACE} up
sudo ip route add 10.10.0.1/32 dev ${SERVER_IFACE}
wait
EOF
	chmod +x "${path}/linux-up.sh"
}

write_client_windows_up() {
	local path="$1" ip="$2"
	cat > "${path}/windows-up.ps1" <<EOF
\$ErrorActionPreference = "Stop"
Start-Process -FilePath ".\\wireguard-go-gm.exe" -ArgumentList "${SERVER_IFACE}"
Start-Sleep -Seconds 1
.\\wg-gm.exe setconf ${SERVER_IFACE} client.conf
New-NetIPAddress -InterfaceAlias "${SERVER_IFACE}" -IPAddress "${ip}" -PrefixLength 32
New-NetRoute -InterfaceAlias "${SERVER_IFACE}" -DestinationPrefix "10.10.0.1/32"
EOF
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
	parse_tunnel_cidr
	command -v wg-gm >/dev/null || {
		printf 'wg-gm is required but was not found in PATH\n' >&2
		exit 1
	}

	IFS=',' read -r -a client_names <<< "${CLIENTS}"
	local name raw_name client_count=0 available_clients
	for raw_name in "${client_names[@]}"; do
		name="$(printf '%s' "${raw_name}" | tr -d '[:space:]')"
		[[ -n "${name}" ]] || continue
		[[ "${name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || {
			printf 'invalid client name: %s\n' "${name}" >&2
			exit 1
		}
		client_count=$((client_count + 1))
	done
	((client_count > 0)) || { printf 'CLIENTS is required\n' >&2; exit 1; }
	available_clients=$((TUNNEL_BROADCAST_INT - TUNNEL_SERVER_INT - 1))
	((client_count <= available_clients)) || {
		printf 'CLIENTS exceeds available tunnel addresses\n' >&2
		exit 1
	}

	local server_private server_public psk=""
	server_private="$(wg-gm genkey)"
	server_public="$(printf '%s\n' "${server_private}" | wg-gm pubkey)"
	require_hex_value "server private key" "${server_private}" '^[0-9a-f]{64}$'
	require_hex_value "server public key" "${server_public}" '^[0-9a-f]{130}$'

	if [[ "${PRESHARED_KEY}" == "true" ]]; then
		psk="$(wg-gm genpsk)"
		require_hex_value "preshared key" "${psk}" '^[0-9a-f]{64}$'
	fi

	mkdir -p "${OUTPUT_DIR}/server/clients" "${OUTPUT_DIR}/clients"
	printf '%s\n' "${server_private}" > "${OUTPUT_DIR}/server/privatekey"
	printf '%s\n' "${server_public}" > "${OUTPUT_DIR}/server/publickey"
	[[ -n "${psk}" ]] && printf '%s\n' "${psk}" > "${OUTPUT_DIR}/server/preshared_key"

	local server_conf="${OUTPUT_DIR}/server/server.conf"
	{
		printf 'private_key=%s\n' "${server_private}"
		printf 'listen_port=%s\n' "${SERVER_PORT}"
		printf '\n'
	} > "${server_conf}"
	write_server_up

	local idx=0
	for raw_name in "${client_names[@]}"; do
		name="$(printf '%s' "${raw_name}" | tr -d '[:space:]')"
		[[ -n "${name}" ]] || continue

		local cip cdir cpriv cpub cconf peerconf
		cip="$(client_ip "${idx}")"
		cdir="${OUTPUT_DIR}/clients/${name}"
		mkdir -p "${cdir}"
		cpriv="$(wg-gm genkey)"
		cpub="$(printf '%s\n' "${cpriv}" | wg-gm pubkey)"
		require_hex_value "${name} private key" "${cpriv}" '^[0-9a-f]{64}$'
		require_hex_value "${name} public key" "${cpub}" '^[0-9a-f]{130}$'
		printf '%s\n' "${cpriv}" > "${cdir}/privatekey"
		printf '%s\n' "${cpub}" > "${cdir}/publickey"

		cconf="${cdir}/client.conf"
		{
			printf 'private_key=%s\n' "${cpriv}"
			printf 'public_key=%s\n' "${server_public}"
			[[ -n "${psk}" ]] && printf 'preshared_key=%s\n' "${psk}"
			printf 'endpoint=%s:%s\n' "${SERVER_ENDPOINT}" "${SERVER_PORT}"
			printf 'allowed_ip=%s/32\n' "${TUNNEL_SERVER_IP}"
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
		write_client_linux_up "${cdir}" "${cip}"
		write_client_windows_up "${cdir}" "${cip}"

		idx=$((idx + 1))
	done
}

main "$@"
