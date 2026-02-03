#!/bin/bash
# shellcheck disable=SC1091,SC2034
# SC1091: Not following /etc/os-release (sourced dynamically)
# SC2034: Variables used indirectly or exported for subprocesses

# Secure OpenVPN server installer for Debian, Ubuntu, CentOS, Amazon Linux 2023, Fedora, Oracle Linux, Arch Linux, Rocky Linux and AlmaLinux.
# https://github.com/angristan/openvpn-install

# Configuration constants
readonly DEFAULT_CERT_VALIDITY_DURATION_DAYS=3650 # 10 years
readonly DEFAULT_CRL_VALIDITY_DURATION_DAYS=5475  # 15 years
readonly EASYRSA_VERSION="3.2.5"
readonly EASYRSA_SHA256="662ee3b453155aeb1dff7096ec052cd83176c460cfa82ac130ef8568ec4df490"

# =============================================================================
# Logging Configuration
# =============================================================================
# Set VERBOSE=1 to see command output, VERBOSE=0 (default) for quiet mode
# Set LOG_FILE to customize log location (default: openvpn-install.log in current dir)
# Set LOG_FILE="" to disable file logging
VERBOSE=${VERBOSE:-0}
LOG_FILE=${LOG_FILE:-openvpn-install.log}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-table} # table or json - json suppresses log output

# Color definitions (disabled if not a terminal, unless FORCE_COLOR=1)
if [[ -t 1 ]] || [[ $FORCE_COLOR == "1" ]]; then
	readonly COLOR_RESET='\033[0m'
	readonly COLOR_RED='\033[0;31m'
	readonly COLOR_GREEN='\033[0;32m'
	readonly COLOR_YELLOW='\033[0;33m'
	readonly COLOR_BLUE='\033[0;34m'
	readonly COLOR_CYAN='\033[0;36m'
	readonly COLOR_DIM='\033[0;90m'
	readonly COLOR_BOLD='\033[1m'
else
	readonly COLOR_RESET=''
	readonly COLOR_RED=''
	readonly COLOR_GREEN=''
	readonly COLOR_YELLOW=''
	readonly COLOR_BLUE=''
	readonly COLOR_CYAN=''
	readonly COLOR_DIM=''
	readonly COLOR_BOLD=''
fi

# Write to log file (no colors, with timestamp)
_log_to_file() {
	if [[ -n "$LOG_FILE" ]]; then
		echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >>"$LOG_FILE"
	fi
}

# Logging functions
log_info() {
	[[ $OUTPUT_FORMAT == "json" ]] && return
	echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"
	_log_to_file "[INFO] $*"
}

log_warn() {
	[[ $OUTPUT_FORMAT == "json" ]] && return
	echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"
	_log_to_file "[WARN] $*"
}

log_error() {
	echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
	_log_to_file "[ERROR] $*"
	if [[ -n "$LOG_FILE" ]]; then
		echo -e "${COLOR_YELLOW}        详见日志: ${LOG_FILE}${COLOR_RESET}" >&2
	fi
}

log_fatal() {
	echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
	_log_to_file "[FATAL] $*"
	if [[ -n "$LOG_FILE" ]]; then
		echo -e "${COLOR_YELLOW}        详见日志: ${LOG_FILE}${COLOR_RESET}" >&2
		_log_to_file "脚本因错误退出"
	fi
	exit 1
}

log_success() {
	[[ $OUTPUT_FORMAT == "json" ]] && return
	echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $*"
	_log_to_file "[OK] $*"
}

log_debug() {
	if [[ $VERBOSE -eq 1 && $OUTPUT_FORMAT != "json" ]]; then
		echo -e "${COLOR_DIM}[DEBUG]${COLOR_RESET} $*"
	fi
	_log_to_file "[DEBUG] $*"
}

log_prompt() {
	# For user-facing prompts/questions (no prefix, just cyan)
	# Skip display in non-interactive mode
	if [[ $NON_INTERACTIVE_INSTALL != "y" ]]; then
		echo -e "${COLOR_CYAN}$*${COLOR_RESET}"
	fi
	_log_to_file "[PROMPT] $*"
}

log_header() {
	# For section headers
	# Skip display in non-interactive mode
	if [[ $NON_INTERACTIVE_INSTALL != "y" ]]; then
		echo ""
		echo -e "${COLOR_BOLD}${COLOR_BLUE}=== $* ===${COLOR_RESET}"
		echo ""
	fi
	_log_to_file "=== $* ==="
}

log_menu() {
	# For menu options - only show in interactive mode
	if [[ $NON_INTERACTIVE_INSTALL != "y" ]]; then
		echo "$@"
	fi
}

# Run a command with optional output suppression
# Usage: run_cmd "description" command [args...]
run_cmd() {
	local desc="$1"
	shift
	# Display the command being run
	echo -e "${COLOR_DIM}> $*${COLOR_RESET}"
	_log_to_file "[CMD] $*"
	if [[ $VERBOSE -eq 1 ]]; then
		if [[ -n "$LOG_FILE" ]]; then
			"$@" 2>&1 | tee -a "$LOG_FILE"
		else
			"$@"
		fi
	else
		if [[ -n "$LOG_FILE" ]]; then
			"$@" >>"$LOG_FILE" 2>&1
		else
			"$@" >/dev/null 2>&1
		fi
	fi
	local ret=$?
	if [[ $ret -eq 0 ]]; then
		log_debug "$desc completed successfully"
	else
		log_error "$desc failed with exit code $ret"
	fi
	return $ret
}

# Run a command that must succeed, exit on failure
# Usage: run_cmd_fatal "description" command [args...]
run_cmd_fatal() {
	local desc="$1"
	shift
	if ! run_cmd "$desc" "$@"; then
		log_fatal "$desc failed"
	fi
}

# =============================================================================
# CLI Configuration
# =============================================================================
readonly SCRIPT_NAME="openvpn-install"

# =============================================================================
# Help Text Functions
# =============================================================================
show_help() {
	cat <<-EOF
		OpenVPN 安装与管理脚本

		用法: $SCRIPT_NAME [命令] [选项]

		无命令时默认进入交互模式：未安装则进入安装，已安装则进入管理菜单。

		命令:
			install       安装并配置 OpenVPN 服务端
			uninstall     卸载 OpenVPN 服务端
			client        管理客户端证书
			server        服务端管理
			fix           修复 OpenVPN systemd 服务（WorkingDirectory 等，经典布局）
			interactive   启动交互式菜单（与无命令时行为相同）

		全局选项:
			--verbose     显示详细输出
			--log <路径>  日志文件路径（默认: openvpn-install.log）
			--no-log      关闭文件日志
			--no-color    关闭彩色输出
			-h, --help    显示帮助

		使用 '$SCRIPT_NAME <命令> --help' 查看各命令的详细帮助。
	EOF
}

show_install_help() {
	cat <<-EOF
		安装并配置 OpenVPN 服务端

		用法: $SCRIPT_NAME install [选项]

		选项:
			-i, --interactive     运行交互式安装向导

		网络选项:
			--endpoint <主机>     客户端连接用的公网 IP 或主机名（自动检测）
			--endpoint-type <4|6> 端点 IP 版本: 4 或 6（默认: 4）
			--ip <地址>           服务端监听 IP（自动检测）
			--client-ipv4         为 VPN 客户端启用 IPv4（默认: 启用）
			--no-client-ipv4      禁用 VPN 客户端 IPv4
			--client-ipv6         为 VPN 客户端启用 IPv6
			--no-client-ipv6      禁用 VPN 客户端 IPv6（默认）
			--subnet-ipv4 <x.x.x.0>  IPv4 VPN 网段（默认: 10.8.0.0）
			--subnet-ipv6 <前缀>     IPv6 VPN 网段（默认: fd42:42:42:42::）
			--port <端口>          OpenVPN 端口（默认: 1194）
			--port-random         使用随机端口（49152-65535）
			--protocol <协议>     协议: udp 或 tcp（默认: udp）
			--mtu <大小>          隧道 MTU（默认: 1500）

		DNS 选项:
			--dns <提供商>       DNS 提供商（默认: adguard）
				可选: system, unbound, cloudflare, quad9, quad9-uncensored,
				fdn, dnswatch, opendns, google, yandex, adguard, nextdns, custom
			--dns-primary <ip>    自定义主 DNS（需配合 --dns custom）
			--dns-secondary <ip>  自定义备用 DNS（可选）

		安全选项:
			--cipher <算法>       数据通道加密（默认: AES-128-GCM）
				可选: AES-128-GCM, AES-192-GCM, AES-256-GCM, AES-128-CBC,
				AES-192-CBC, AES-256-CBC, CHACHA20-POLY1305
			--cert-type <类型>    证书类型: ecdsa 或 rsa（默认: ecdsa）
			--cert-curve <曲线>   ECDSA 曲线（默认: prime256v1）
				可选: prime256v1, secp384r1, secp521r1
			--rsa-bits <位数>     RSA 密钥长度: 2048, 3072, 4096（默认: 2048）
			--cc-cipher <算法>    控制通道加密（自动选择）
			--tls-version-min <版本>  最低 TLS 版本: 1.2 或 1.3（默认: 1.2）
			--tls-ciphersuites <列表>  TLS 1.3 加密套件，冒号分隔
			--tls-groups <列表>   密钥交换组，冒号分隔
				（默认: prime256v1）
			--hmac <算法>         HMAC 算法: SHA256, SHA384, SHA512（默认: SHA256）
			--tls-sig <模式>      TLS 模式: crypt-v2, crypt, auth（默认: crypt）
			--auth-mode <模式>    认证模式: pki, fingerprint（默认: pki）
				fingerprint 需 OpenVPN 2.6+
			--server-cert-days <天数>  服务端证书有效期（默认: 3650）

		其他选项:
			--multi-client        允许同一证书在多个设备使用

		初始客户端选项:
			--client <名称>       首个客户端名称（默认: client）
			--client-password [密码]  为首个客户端设置密码（不填则自动生成并在安装完成后显示）
			--client-cert-days <天数>  客户端证书有效期（默认: 3650）
			--no-client           跳过创建首个客户端

		示例:
			$SCRIPT_NAME install
			$SCRIPT_NAME install --port 443 --protocol tcp
			$SCRIPT_NAME install --dns quad9 --cipher AES-256-GCM
			$SCRIPT_NAME install -i
	EOF
}

show_uninstall_help() {
	cat <<-EOF
		卸载 OpenVPN 服务端

		用法: $SCRIPT_NAME uninstall [选项]

		选项:
			-f, --force   跳过确认提示

		示例:
			$SCRIPT_NAME uninstall
			$SCRIPT_NAME uninstall --force
	EOF
}

show_client_help() {
	cat <<-EOF
		管理客户端证书

		用法: $SCRIPT_NAME client <子命令> [选项]

		子命令:
			add <名称>     添加新客户端
			list           列出所有客户端
			revoke <名称>  吊销客户端证书
			renew <名称>   续期客户端证书

		使用 '$SCRIPT_NAME client <子命令> --help' 查看详细帮助。
	EOF
}

show_client_add_help() {
	cat <<-EOF
		添加新的 VPN 客户端

		用法: $SCRIPT_NAME client add <名称> [选项]

		选项:
			--password [密码]   为客户端设置密码（不填则提示输入）
			--cert-days <天数>  证书有效期（默认: 3650）
			--output <路径>     .ovpn 文件输出路径（默认: ~/<名称>.ovpn）

		示例:
			$SCRIPT_NAME client add alice
			$SCRIPT_NAME client add bob --password
			$SCRIPT_NAME client add charlie --cert-days 365 --output /tmp/charlie.ovpn
	EOF
}

show_client_list_help() {
	cat <<-EOF
		列出所有客户端证书

		用法: $SCRIPT_NAME client list [选项]

		选项:
			--format <格式>  输出格式: table 或 json（默认: table）

		示例:
			$SCRIPT_NAME client list
			$SCRIPT_NAME client list --format json
	EOF
}

show_client_revoke_help() {
	cat <<-EOF
		吊销客户端证书

		用法: $SCRIPT_NAME client revoke <名称> [选项]

		选项:
			-f, --force   跳过确认提示

		示例:
			$SCRIPT_NAME client revoke alice
			$SCRIPT_NAME client revoke bob --force
	EOF
}

show_client_renew_help() {
	cat <<-EOF
		续期客户端证书

		用法: $SCRIPT_NAME client renew <名称> [选项]

		选项:
			--cert-days <天数>  新证书有效期（默认: 3650）

		示例:
			$SCRIPT_NAME client renew alice
			$SCRIPT_NAME client renew bob --cert-days 365
	EOF
}

show_server_help() {
	cat <<-EOF
		服务端管理

		用法: $SCRIPT_NAME server <子命令> [选项]

		子命令:
			status   列出当前已连接的客户端
			renew    续期服务端证书

		使用 '$SCRIPT_NAME server <子命令> --help' 查看详细帮助。
	EOF
}

show_server_status_help() {
	cat <<-EOF
		列出当前已连接的客户端

		说明: OpenVPN 约每 60 秒更新一次客户端数据。

		用法: $SCRIPT_NAME server status [选项]

		选项:
			--format <格式>  输出格式: table 或 json（默认: table）

		示例:
			$SCRIPT_NAME server status
			$SCRIPT_NAME server status --format json
	EOF
}

show_server_renew_help() {
	cat <<-EOF
		续期服务端证书

		用法: $SCRIPT_NAME server renew [选项]

		选项:
			--cert-days <天数>  新证书有效期（默认: 3650）
			-f, --force         跳过确认/警告

		示例:
			$SCRIPT_NAME server renew
			$SCRIPT_NAME server renew --cert-days 1825
	EOF
}

# =============================================================================
# CLI Command Handlers
# =============================================================================

# Check if OpenVPN server is installed by THIS script (uses /etc/openvpn/ layout)
isOpenVPNInstalled() {
	[[ -e /etc/openvpn/server.conf ]]
}

# Check if any OpenVPN server config exists（经典布局 /etc/openvpn/server.conf）
hasAnyOpenVPNServerConfig() {
	[[ -e /etc/openvpn/server.conf ]]
}

# Require OpenVPN to be installed
requireOpenVPN() {
	if ! isOpenVPNInstalled; then
		log_fatal "OpenVPN 未安装。请先执行 '$SCRIPT_NAME install' 进行安装。"
	fi
}

# Require OpenVPN to NOT be installed (no conflict with any existing server)
requireNoOpenVPN() {
	if [[ -e /etc/openvpn/server.conf ]]; then
		log_fatal "检测到已有 OpenVPN 服务器配置：/etc/openvpn/server.conf。请使用 '$SCRIPT_NAME client' 管理客户端，或 '$SCRIPT_NAME uninstall' 卸载。"
	fi
}

# 本脚本统一使用 openvpn-server@server 作为服务名（经典布局 /etc/openvpn/server.conf）
getOpenVPNServiceUnit() {
	echo "openvpn-server@server"
}

# Parse DNS provider string to DNS number
parse_dns_provider() {
	case "$1" in
	system | unbound | cloudflare | quad9 | quad9-uncensored | fdn | dnswatch | opendns | google | yandex | adguard | nextdns | custom)
		DNS="$1"
		;;
	*) log_fatal "无效的 DNS 提供商: $1。请使用 '$SCRIPT_NAME install --help' 查看可选值。" ;;
	esac
}

# Parse cipher string
parse_cipher() {
	case "$1" in
	AES-128-GCM | AES-192-GCM | AES-256-GCM | AES-128-CBC | AES-192-CBC | AES-256-CBC | CHACHA20-POLY1305)
		CIPHER="$1"
		;;
	*) log_fatal "无效的加密算法: $1。请使用 '$SCRIPT_NAME install --help' 查看可选值。" ;;
	esac
}

# Parse curve string
parse_curve() {
	case "$1" in
	prime256v1 | secp384r1 | secp521r1) echo "$1" ;;
	*) log_fatal "Invalid curve: $1. Valid curves: prime256v1, secp384r1, secp521r1" ;;
	esac
}

# =============================================================================
# Configuration Constants
# =============================================================================
# Protocol options
readonly PROTOCOLS=("udp" "tcp")

# DNS providers (use string names)
readonly DNS_PROVIDERS=("system" "unbound" "cloudflare" "quad9" "quad9-uncensored" "fdn" "dnswatch" "opendns" "google" "yandex" "adguard" "nextdns" "custom")

# Cipher options
readonly CIPHERS=("AES-128-GCM" "AES-192-GCM" "AES-256-GCM" "AES-128-CBC" "AES-192-CBC" "AES-256-CBC" "CHACHA20-POLY1305")

# Certificate types (use strings)
readonly CERT_TYPES=("ecdsa" "rsa")

# ECDSA curves
readonly CERT_CURVES=("prime256v1" "secp384r1" "secp521r1")

# RSA key sizes
readonly RSA_KEY_SIZES=("2048" "3072" "4096")

# TLS versions
readonly TLS_VERSIONS=("1.2" "1.3")

# TLS signature modes (use strings)
readonly TLS_SIG_MODES=("crypt-v2" "crypt" "auth")

# Authentication modes: pki (CA-based) or fingerprint (peer-fingerprint, OpenVPN 2.6+)
readonly AUTH_MODES=("pki" "fingerprint")

# HMAC algorithms
readonly HMAC_ALGS=("SHA256" "SHA384" "SHA512")

# TLS 1.3 cipher suite options
readonly TLS13_OPTIONS=("all" "aes-256-only" "aes-128-only" "chacha20-only")

# TLS groups options
readonly TLS_GROUPS_OPTIONS=("all" "x25519-only" "nist-only")

# =============================================================================
# Set Installation Defaults
# =============================================================================
# Centralized function to set all defaults - called before configuration
set_installation_defaults() {
	# Network
	ENDPOINT_TYPE="${ENDPOINT_TYPE:-4}"
	CLIENT_IPV4="${CLIENT_IPV4:-y}"
	# 若有 IPv6 连通性则默认开启客户端 IPv6（双栈）
	_has_ipv6="n"
	if type ping6 >/dev/null 2>&1; then
		ping6 -c1 -W2 ipv6.google.com >/dev/null 2>&1 && _has_ipv6="y"
	elif type ping >/dev/null 2>&1; then
		ping -6 -c1 -W2 ipv6.google.com >/dev/null 2>&1 && _has_ipv6="y"
	fi
	CLIENT_IPV6="${CLIENT_IPV6:-$_has_ipv6}"
	VPN_SUBNET_IPV4="${VPN_SUBNET_IPV4:-10.8.0.0}"
	VPN_SUBNET_IPV6="${VPN_SUBNET_IPV6:-fd42:42:42:42::}"
	PORT="${PORT:-random}"
	PROTOCOL="${PROTOCOL:-tcp}"

	# DNS (use string name)
	DNS="${DNS:-adguard}"

	# Multi-client
	MULTI_CLIENT="${MULTI_CLIENT:-n}"

	# Encryption
	CIPHER="${CIPHER:-AES-128-GCM}"
	CERT_TYPE="${CERT_TYPE:-ecdsa}"
	CERT_CURVE="${CERT_CURVE:-prime256v1}"
	RSA_KEY_SIZE="${RSA_KEY_SIZE:-2048}"
	TLS_VERSION_MIN="${TLS_VERSION_MIN:-1.2}"
	TLS13_CIPHERSUITES="${TLS13_CIPHERSUITES:-TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256}"
	TLS_GROUPS="${TLS_GROUPS:-prime256v1}"
	HMAC_ALG="${HMAC_ALG:-SHA256}"
	TLS_SIG="${TLS_SIG:-crypt}"
	AUTH_MODE="${AUTH_MODE:-pki}"

	# Derive CC_CIPHER from CERT_TYPE if not set
	if [[ -z $CC_CIPHER ]]; then
		if [[ $CERT_TYPE == "ecdsa" ]]; then
			CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		else
			CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
		fi
	fi

	# Client
	CLIENT="${CLIENT:-client}"
	PASS="${PASS:-2}"
	CLIENT_CERT_DURATION_DAYS="${CLIENT_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}"
	SERVER_CERT_DURATION_DAYS="${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}"

	# 性能优化默认高吞吐
	PERF_OPT="${PERF_OPT:-2}"

	# Auto-detect local LAN subnet as default for PUSH_ROUTES (走 VPN 的网段) when not set
	if [[ -z $PUSH_ROUTES ]]; then
		_dnic=$(ip -4 route ls 2>/dev/null | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
		if [[ -n $_dnic ]]; then
			_dsub=$(ip -4 route show dev "$_dnic" 2>/dev/null | awk '/scope link/ {print $1}' | head -1)
			if [[ -n $_dsub ]] && echo "$_dsub" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
				PUSH_ROUTES="$_dsub"
			fi
		fi
	fi

	# Note: Gateway values (VPN_GATEWAY_IPV4, VPN_GATEWAY_IPV6) and IPV6_SUPPORT
	# are computed in prepare_network_config() which is called after validation
}

# Version comparison: returns 0 if version1 >= version2
version_ge() {
	local ver1="$1" ver2="$2"
	# Use sort -V for version comparison
	[[ "$(printf '%s\n%s' "$ver1" "$ver2" | sort -V | head -n1)" == "$ver2" ]]
}

# Get installed OpenVPN version (e.g., "2.6.12")
get_openvpn_version() {
	openvpn --version 2>/dev/null | head -1 | awk '{print $2}'
}

# GitHub mirror base URLs (prepended to original URL when primary download fails)
# Format: mirror_base + original_url = mirror_url, e.g. https://ghproxy.com/ + https://github.com/...
readonly GITHUB_MIRRORS=(
	"https://ghproxy.com/"
	"https://mirror.ghproxy.com/"
	"https://ghps.cc/"
)

# Download URL to file with mirror fallback. On failure after trying primary and all mirrors, calls log_fatal.
# Usage: download_with_mirror_fallback "url" "output_file" "description"
download_with_mirror_fallback() {
	local url="$1"
	local output_file="$2"
	local description="${3:-下载}"
	local try_mirror

	log_info "正在下载 ${description}..."
	if curl -fL --retry 5 --retry-delay 2 -o "$output_file" "$url" 2>/dev/null; then
		return 0
	fi
	log_warn "从 GitHub 直接下载失败，正在尝试使用镜像站..."
	for try_mirror in "${GITHUB_MIRRORS[@]}"; do
		local mirror_url="${try_mirror}${url}"
		log_info "尝试镜像: ${try_mirror%%/}"
		if curl -fL --retry 3 --retry-delay 2 -o "$output_file" "$mirror_url" 2>/dev/null; then
			log_success "镜像站下载成功。"
			return 0
		fi
	done
	rm -f "$output_file"
	log_fatal "${description} 失败：GitHub 与所有镜像站均无法下载。请检查网络或稍后重试。"
}

# Validation functions
validate_port() {
	local port="$1"
	if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
		log_fatal "Invalid port: $port. Must be a number between 1 and 65535."
	fi
}

validate_subnet_ipv4() {
	local subnet="$1"
	# Check format: x.x.x.0 where x is 0-255
	if ! [[ "$subnet" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.0$ ]]; then
		log_fatal "Invalid IPv4 subnet: $subnet. Must be in format x.x.x.0 (e.g., 10.8.0.0)"
	fi
	local octet1="${BASH_REMATCH[1]}"
	local octet2="${BASH_REMATCH[2]}"
	local octet3="${BASH_REMATCH[3]}"
	# Validate each octet is 0-255
	if [[ "$octet1" -gt 255 ]] || [[ "$octet2" -gt 255 ]] || [[ "$octet3" -gt 255 ]]; then
		log_fatal "Invalid IPv4 subnet: $subnet. Octets must be 0-255."
	fi
	# Check for RFC1918 private address ranges
	if ! { [[ "$octet1" -eq 10 ]] ||
		[[ "$octet1" -eq 172 && "$octet2" -ge 16 && "$octet2" -le 31 ]] ||
		[[ "$octet1" -eq 192 && "$octet2" -eq 168 ]]; }; then
		log_fatal "Invalid IPv4 subnet: $subnet. Must be a private network (10.x.x.0, 172.16-31.x.0, or 192.168.x.0)."
	fi
}

validate_subnet_ipv6() {
	local subnet="$1"
	# Accept format: IPv6 address ending with :: (prefix only, no CIDR notation here)
	# We expect formats like: fd42:42:42:42:: or fdxx:xxxx:xxxx:xxxx::
	# The script will append /112 for the server directive

	# IPv6 ULA validation (fd00::/8 range with at least /48 prefix)
	# ULA format: fdxx:xxxx:xxxx:: or fdxx:xxxx:xxxx:xxxx:: where x is hex
	if ! [[ "$subnet" =~ ^fd[0-9a-fA-F]{2}(:[0-9a-fA-F]{1,4}){2,5}::$ ]]; then
		log_fatal "Invalid IPv6 subnet: $subnet. Must be a ULA address with at least a /48 prefix, ending with :: (e.g., fd42:42:42::)"
	fi
}

# Convert CIDR prefix (1-32) to dotted decimal netmask for OpenVPN push "route"
cidr_to_netmask() {
	local cidr="$1"
	if ! [[ "$cidr" =~ ^[0-9]+$ ]] || [[ "$cidr" -lt 1 ]] || [[ "$cidr" -gt 32 ]]; then
		echo "" && return 1
	fi
	local mask=$((0xffffffff << (32 - cidr) & 0xffffffff))
	printf "%d.%d.%d.%d" $((mask >> 24)) $(((mask >> 16) & 255)) $(((mask >> 8) & 255)) $((mask & 255))
}

# Parse one IPv4 CIDR (e.g. 192.168.1.0/24) to "network netmask" for OpenVPN push "route"
parse_push_route_ipv4() {
	local cidr_str="$1"
	local ip cidr
	if [[ "$cidr_str" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)$ ]]; then
		ip="${BASH_REMATCH[1]}"
		cidr="${BASH_REMATCH[2]}"
	else
		echo "" && return 1
	fi
	[[ "$cidr" -lt 1 ]] || [[ "$cidr" -gt 32 ]] && echo "" && return 1
	local mask_dotted
	mask_dotted=$(cidr_to_netmask "$cidr") || { echo "" && return 1; }
	local o1 o2 o3 o4
	IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
	[[ "$o1" -ge 0 ]] && [[ "$o1" -le 255 ]] && [[ "$o2" -ge 0 ]] && [[ "$o2" -le 255 ]] && [[ "$o3" -ge 0 ]] && [[ "$o3" -le 255 ]] && [[ "$o4" -ge 0 ]] && [[ "$o4" -le 255 ]] || { echo "" && return 1; }
	local m1 m2 m3 m4
	IFS='.' read -r m1 m2 m3 m4 <<< "$mask_dotted"
	printf "%d.%d.%d.%d %s" $((o1 & m1)) $((o2 & m2)) $((o3 & m3)) $((o4 & m4)) "$mask_dotted"
}

validate_positive_int() {
	local value="$1"
	local name="$2"
	if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 1 ]]; then
		log_fatal "Invalid $name: $value. Must be a positive integer."
	fi
}

validate_mtu() {
	local mtu="$1"
	if ! [[ "$mtu" =~ ^[0-9]+$ ]] || [[ "$mtu" -lt 576 ]] || [[ "$mtu" -gt 65535 ]]; then
		log_fatal "Invalid MTU: $mtu. Must be between 576 and 65535."
	fi
}

# Maximum length for client names (OpenSSL CN limit)
readonly MAX_CLIENT_NAME_LENGTH=64

# Check if client name is valid (non-fatal, returns true/false)
is_valid_client_name() {
	local name="$1"
	[[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] && [[ ${#name} -le $MAX_CLIENT_NAME_LENGTH ]]
}

# Validate client name and exit with error if invalid
validate_client_name() {
	local name="$1"
	if [[ -z "$name" ]]; then
		log_fatal "Client name cannot be empty."
	fi
	if ! [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
		log_fatal "Invalid client name: $name. Only alphanumeric characters, underscores, and hyphens are allowed."
	fi
	if [[ ${#name} -gt $MAX_CLIENT_NAME_LENGTH ]]; then
		log_fatal "Client name too long: ${#name} characters. Maximum is $MAX_CLIENT_NAME_LENGTH characters (OpenSSL CN limit)."
	fi
}

# Validate all configuration values (catches invalid env vars in non-interactive mode)
validate_configuration() {
	# Validate PROTOCOL
	case "$PROTOCOL" in
	udp | tcp) ;;
	*) log_fatal "Invalid protocol: $PROTOCOL. Must be 'udp' or 'tcp'." ;;
	esac

	# Validate DNS
	case "$DNS" in
	system | unbound | cloudflare | quad9 | quad9-uncensored | fdn | dnswatch | opendns | google | yandex | adguard | nextdns | custom) ;;
	*) log_fatal "Invalid DNS provider: $DNS. Valid providers: system, unbound, cloudflare, quad9, quad9-uncensored, fdn, dnswatch, opendns, google, yandex, adguard, nextdns, custom" ;;
	esac

	# Validate CERT_TYPE
	case "$CERT_TYPE" in
	ecdsa | rsa) ;;
	*) log_fatal "Invalid cert type: $CERT_TYPE. Must be 'ecdsa' or 'rsa'." ;;
	esac

	# Validate TLS_SIG
	case "$TLS_SIG" in
	crypt-v2 | crypt | auth) ;;
	*) log_fatal "Invalid TLS signature mode: $TLS_SIG. Must be 'crypt-v2', 'crypt', or 'auth'." ;;
	esac

	# Validate AUTH_MODE
	case "$AUTH_MODE" in
	pki | fingerprint) ;;
	*) log_fatal "Invalid auth mode: $AUTH_MODE. Must be 'pki' or 'fingerprint'." ;;
	esac

	# Fingerprint mode requires OpenVPN 2.6+
	if [[ $AUTH_MODE == "fingerprint" ]]; then
		local openvpn_ver
		openvpn_ver=$(get_openvpn_version)
		if [[ -n "$openvpn_ver" ]] && ! version_ge "$openvpn_ver" "2.6.0"; then
			log_fatal "Fingerprint mode requires OpenVPN 2.6.0 or later. Installed version: $openvpn_ver"
		fi
	fi

	# Validate PORT
	if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
		log_fatal "Invalid port: $PORT. Must be a number between 1 and 65535."
	fi

	# Validate CLIENT_IPV4/CLIENT_IPV6
	if [[ $CLIENT_IPV4 != "y" ]] && [[ $CLIENT_IPV6 != "y" ]]; then
		log_fatal "At least one of CLIENT_IPV4 or CLIENT_IPV6 must be 'y'"
	fi

	# Validate ENDPOINT_TYPE
	case "$ENDPOINT_TYPE" in
	4 | 6) ;;
	*) log_fatal "Invalid endpoint type: $ENDPOINT_TYPE. Must be '4' or '6'." ;;
	esac

	# Validate CIPHER
	case "$CIPHER" in
	AES-128-GCM | AES-192-GCM | AES-256-GCM | AES-128-CBC | AES-192-CBC | AES-256-CBC | CHACHA20-POLY1305) ;;
	*) log_fatal "Invalid cipher: $CIPHER. Valid ciphers: AES-128-GCM, AES-192-GCM, AES-256-GCM, AES-128-CBC, AES-192-CBC, AES-256-CBC, CHACHA20-POLY1305" ;;
	esac

	# Validate CERT_CURVE (only if ECDSA)
	if [[ $CERT_TYPE == "ecdsa" ]]; then
		case "$CERT_CURVE" in
		prime256v1 | secp384r1 | secp521r1) ;;
		*) log_fatal "Invalid cert curve: $CERT_CURVE. Must be 'prime256v1', 'secp384r1', or 'secp521r1'." ;;
		esac
	fi

	# Validate RSA_KEY_SIZE (only if RSA)
	if [[ $CERT_TYPE == "rsa" ]]; then
		case "$RSA_KEY_SIZE" in
		2048 | 3072 | 4096) ;;
		*) log_fatal "Invalid RSA key size: $RSA_KEY_SIZE. Must be 2048, 3072, or 4096." ;;
		esac
	fi

	# Validate TLS_VERSION_MIN
	case "$TLS_VERSION_MIN" in
	1.2 | 1.3) ;;
	*) log_fatal "Invalid TLS version: $TLS_VERSION_MIN. Must be '1.2' or '1.3'." ;;
	esac

	# Validate HMAC_ALG
	case "$HMAC_ALG" in
	SHA256 | SHA384 | SHA512) ;;
	*) log_fatal "Invalid HMAC algorithm: $HMAC_ALG. Must be SHA256, SHA384, or SHA512." ;;
	esac

	# Validate MTU if set
	if [[ -n $MTU ]]; then
		if ! [[ "$MTU" =~ ^[0-9]+$ ]] || [[ "$MTU" -lt 576 ]] || [[ "$MTU" -gt 65535 ]]; then
			log_fatal "Invalid MTU: $MTU. Must be a number between 576 and 65535."
		fi
	fi

	# Validate custom DNS if selected
	if [[ $DNS == "custom" ]] && [[ -z $DNS1 ]]; then
		log_fatal "Custom DNS selected but DNS1 (primary DNS) is not set. Use --dns-primary to specify."
	fi

	# Validate VPN subnets using the dedicated validation functions
	# These check format, octet ranges, and RFC1918/ULA compliance
	if [[ -n $VPN_SUBNET_IPV4 ]]; then
		validate_subnet_ipv4 "$VPN_SUBNET_IPV4"
	fi

	if [[ $CLIENT_IPV6 == "y" ]] && [[ -n $VPN_SUBNET_IPV6 ]]; then
		validate_subnet_ipv6 "$VPN_SUBNET_IPV6"
	fi
}

# =============================================================================
# Interactive Helper Functions
# =============================================================================
# Generic select-from-menu function for arrays
# Usage: select_from_array "prompt" array_name "default_value" result_var
# Note: Uses namerefs (-n) for arrays
select_from_array() {
	local prompt="$1"
	local -n _options_ref="$2"
	local default="$3"
	local -n _result_ref="$4"

	# If already set (non-interactive mode), just return
	if [[ -n $_result_ref ]]; then
		return
	fi

	# Find default index (1-based for display)
	local default_idx=1
	for i in "${!_options_ref[@]}"; do
		if [[ "${_options_ref[$i]}" == "$default" ]]; then
			default_idx=$((i + 1))
			break
		fi
	done

	# Display menu
	local count=${#_options_ref[@]}
	for i in "${!_options_ref[@]}"; do
		log_menu "   $((i + 1))) ${_options_ref[$i]}"
	done

	# Read selection
	local choice
	until [[ $choice =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= count)); do
		read -rp "$prompt [1-$count]: " -e -i "$default_idx" choice
	done

	_result_ref="${_options_ref[$((choice - 1))]}"
}

# Select with custom labels (for menu items that need different display text)
# Usage: select_with_labels "prompt" labels_array values_array "default_value" result_var
select_with_labels() {
	local prompt="$1"
	local -n _labels_ref="$2"
	local -n _values_ref="$3"
	local default="$4"
	local -n _result_ref="$5"

	# If already set (non-interactive mode), just return
	if [[ -n $_result_ref ]]; then
		return
	fi

	# Find default index
	local default_idx=1
	for i in "${!_values_ref[@]}"; do
		if [[ "${_values_ref[$i]}" == "$default" ]]; then
			default_idx=$((i + 1))
			break
		fi
	done

	# Display menu
	local count=${#_labels_ref[@]}
	for i in "${!_labels_ref[@]}"; do
		log_menu "   $((i + 1))) ${_labels_ref[$i]}"
	done

	# Read selection
	local choice
	until [[ $choice =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= count)); do
		read -rp "$prompt [1-$count]: " -e -i "$default_idx" choice
	done

	_result_ref="${_values_ref[$((choice - 1))]}"
}

# Prompt for yes/no with default
# Usage: prompt_yes_no "prompt" "default" result_var
prompt_yes_no() {
	local prompt="$1"
	local default="$2"
	local -n _result_ref="$3"

	# If already set, just return
	if [[ $_result_ref =~ ^[yn]$ ]]; then
		return
	fi

	until [[ $_result_ref =~ ^[yn]$ ]]; do
		read -rp "$prompt [y/n]: " -e -i "$default" _result_ref
	done
}

# Prompt for a value with validation function
# Usage: prompt_validated "prompt" "validator_func" "default" result_var
# The validator should return 0 for valid, non-0 for invalid
prompt_validated() {
	local prompt="$1"
	local validator="$2"
	local default="$3"
	local -n _result_ref="$4"

	# If already set and valid, return
	if [[ -n $_result_ref ]] && $validator "$_result_ref" 2>/dev/null; then
		return
	fi

	_result_ref=""
	until [[ -n $_result_ref ]] && $validator "$_result_ref" 2>/dev/null; do
		read -rp "$prompt: " -e -i "$default" _result_ref
	done
}

# Non-fatal port validator (returns 0/1)
is_valid_port() {
	local port="$1"
	[[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535))
}

# Non-fatal MTU validator (returns 0/1)
is_valid_mtu() {
	local mtu="$1"
	[[ "$mtu" =~ ^[0-9]+$ ]] && ((mtu >= 576 && mtu <= 65535))
}

# Handle install command
cmd_install() {
	local interactive=false
	local no_client=false
	local client_password_flag=false
	local client_password_value=""

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-i | --interactive)
			interactive=true
			shift
			;;
		--endpoint)
			[[ -z "${2:-}" ]] && log_fatal "--endpoint requires an argument"
			ENDPOINT="$2"
			shift 2
			;;
		--ip)
			[[ -z "${2:-}" ]] && log_fatal "--ip requires an argument"
			IP="$2"
			APPROVE_IP=y
			shift 2
			;;
		--endpoint-type)
			[[ -z "${2:-}" ]] && log_fatal "--endpoint-type requires an argument"
			case "$2" in
			4) ENDPOINT_TYPE="4" ;;
			6) ENDPOINT_TYPE="6" ;;
			*) log_fatal "Invalid endpoint type: $2. Use '4' or '6'." ;;
			esac
			shift 2
			;;
		--client-ipv4)
			CLIENT_IPV4=y
			shift
			;;
		--no-client-ipv4)
			CLIENT_IPV4=n
			shift
			;;
		--client-ipv6)
			CLIENT_IPV6=y
			shift
			;;
		--no-client-ipv6)
			CLIENT_IPV6=n
			shift
			;;
		--ipv6)
			# Legacy flag: enable IPv6 for clients (backward compatibility)
			CLIENT_IPV6=y
			shift
			;;
		--subnet-ipv4)
			[[ -z "${2:-}" ]] && log_fatal "--subnet-ipv4 requires an argument"
			validate_subnet_ipv4 "$2"
			VPN_SUBNET_IPV4="$2"
			shift 2
			;;
		--subnet-ipv6)
			[[ -z "${2:-}" ]] && log_fatal "--subnet-ipv6 requires an argument"
			validate_subnet_ipv6 "$2"
			VPN_SUBNET_IPV6="$2"
			shift 2
			;;
		--subnet)
			# Legacy flag: --subnet now maps to --subnet-ipv4
			[[ -z "${2:-}" ]] && log_fatal "--subnet requires an argument"
			validate_subnet_ipv4 "$2"
			VPN_SUBNET_IPV4="$2"
			shift 2
			;;
		--port)
			[[ -z "${2:-}" ]] && log_fatal "--port requires an argument"
			validate_port "$2"
			PORT="$2"
			shift 2
			;;
		--port-random)
			PORT="random"
			shift
			;;
		--protocol)
			[[ -z "${2:-}" ]] && log_fatal "--protocol requires an argument"
			case "$2" in
			udp | tcp)
				PROTOCOL="$2"
				;;
			*) log_fatal "Invalid protocol: $2. Use 'udp' or 'tcp'." ;;
			esac
			shift 2
			;;
		--mtu)
			[[ -z "${2:-}" ]] && log_fatal "--mtu requires an argument"
			validate_mtu "$2"
			MTU="$2"
			shift 2
			;;
		--dns)
			[[ -z "${2:-}" ]] && log_fatal "--dns requires an argument"
			parse_dns_provider "$2"
			shift 2
			;;
		--dns-primary)
			[[ -z "${2:-}" ]] && log_fatal "--dns-primary requires an argument"
			DNS1="$2"
			shift 2
			;;
		--dns-secondary)
			[[ -z "${2:-}" ]] && log_fatal "--dns-secondary requires an argument"
			DNS2="$2"
			shift 2
			;;
		--multi-client)
			MULTI_CLIENT=y
			shift
			;;
		--cipher)
			[[ -z "${2:-}" ]] && log_fatal "--cipher requires an argument"
			parse_cipher "$2"
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--cert-type)
			[[ -z "${2:-}" ]] && log_fatal "--cert-type requires an argument"
			case "$2" in
			ecdsa | rsa) CERT_TYPE="$2" ;;
			*) log_fatal "Invalid cert-type: $2. Use 'ecdsa' or 'rsa'." ;;
			esac
			shift 2
			;;
		--cert-curve)
			[[ -z "${2:-}" ]] && log_fatal "--cert-curve requires an argument"
			CERT_CURVE=$(parse_curve "$2")
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--rsa-bits)
			[[ -z "${2:-}" ]] && log_fatal "--rsa-bits requires an argument"
			case "$2" in
			2048 | 3072 | 4096) RSA_KEY_SIZE="$2" ;;
			*) log_fatal "Invalid RSA key size: $2. Use 2048, 3072, or 4096." ;;
			esac
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--cc-cipher)
			[[ -z "${2:-}" ]] && log_fatal "--cc-cipher requires an argument"
			CC_CIPHER="$2"
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--tls-ciphersuites)
			[[ -z "${2:-}" ]] && log_fatal "--tls-ciphersuites requires an argument"
			TLS13_CIPHERSUITES="$2"
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--tls-version-min)
			[[ -z "${2:-}" ]] && log_fatal "--tls-version-min requires an argument"
			case "$2" in
			1.2 | 1.3) TLS_VERSION_MIN="$2" ;;
			*) log_fatal "Invalid TLS version: $2. Use '1.2' or '1.3'." ;;
			esac
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--tls-groups)
			[[ -z "${2:-}" ]] && log_fatal "--tls-groups requires an argument"
			TLS_GROUPS="$2"
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--hmac)
			[[ -z "${2:-}" ]] && log_fatal "--hmac requires an argument"
			case "$2" in
			SHA256 | SHA384 | SHA512) HMAC_ALG="$2" ;;
			*) log_fatal "Invalid HMAC algorithm: $2. Use SHA256, SHA384, or SHA512." ;;
			esac
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--tls-sig)
			[[ -z "${2:-}" ]] && log_fatal "--tls-sig requires an argument"
			case "$2" in
			crypt-v2 | crypt | auth) TLS_SIG="$2" ;;
			*) log_fatal "Invalid TLS mode: $2. Use 'crypt-v2', 'crypt', or 'auth'." ;;
			esac
			shift 2
			;;
		--auth-mode)
			[[ -z "${2:-}" ]] && log_fatal "--auth-mode requires an argument"
			case "$2" in
			pki | fingerprint) AUTH_MODE="$2" ;;
			*) log_fatal "Invalid auth mode: $2. Use 'pki' or 'fingerprint'." ;;
			esac
			shift 2
			;;
		--server-cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--server-cert-days requires an argument"
			validate_positive_int "$2" "server-cert-days"
			SERVER_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		--client)
			[[ -z "${2:-}" ]] && log_fatal "--client requires an argument"
			validate_client_name "$2"
			CLIENT="$2"
			shift 2
			;;
		--client-password)
			client_password_flag=true
			# Check if next arg is a value or another flag
			if [[ -n "${2:-}" ]] && [[ ! "$2" =~ ^- ]]; then
				client_password_value="$2"
				shift
			fi
			shift
			;;
		--client-cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--client-cert-days requires an argument"
			validate_positive_int "$2" "client-cert-days"
			CLIENT_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		--no-client)
			no_client=true
			shift
			;;
		-h | --help)
			show_install_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请使用 '$SCRIPT_NAME install --help' 查看用法。"
			;;
		esac
	done

	# Validate custom DNS settings
	if [[ -n "${DNS1:-}" || -n "${DNS2:-}" ]] && [[ "${DNS:-}" != "custom" ]]; then
		log_fatal "--dns-primary and --dns-secondary require --dns custom"
	fi

	# Check if already installed
	requireNoOpenVPN

	if [[ $interactive == true ]]; then
		# Set defaults so e.g. PASS=2 (generate password for first client)
		set_installation_defaults
		# Run interactive installer
		installQuestions
	else
		# Non-interactive mode - set flags and defaults
		NON_INTERACTIVE_INSTALL=y
		APPROVE_INSTALL=y
		APPROVE_IP=${APPROVE_IP:-y}
		CONTINUE=y

		# 默认使用随机端口（未指定 --port 时）
		PORT="${PORT:-random}"
		# Handle random port
		if [[ $PORT == "random" ]]; then
			PORT=$(shuf -i 49152-65535 -n1)
			log_info "随机端口: $PORT"
		fi

		# Client setup
		if [[ $no_client == true ]]; then
			NEW_CLIENT=n
		else
			NEW_CLIENT=y
			if [[ $client_password_flag == true ]]; then
				PASS=2
				if [[ -n "$client_password_value" ]]; then
					PASSPHRASE="$client_password_value"
				fi
			fi
		fi

		# Set all defaults for any unset values
		set_installation_defaults

		# Validate configuration values (catches invalid env vars)
		validate_configuration

		# Detect IPs and set up network config (interactive mode does this in installQuestions)
		detect_server_ips
	fi

	# Prepare derived network configuration (gateways, etc.)
	prepare_network_config

	installOpenVPN
}

# Handle uninstall command
cmd_uninstall() {
	local force=false

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-f | --force)
			force=true
			shift
			;;
		-h | --help)
			show_uninstall_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请使用 '$SCRIPT_NAME uninstall --help' 查看用法。"
			;;
		esac
	done

	requireOpenVPN

	if [[ $force == true ]]; then
		REMOVE=y
	fi

	removeOpenVPN
}

# Handle client command
cmd_client() {
	local subcmd="${1:-}"
	shift || true

	case "$subcmd" in
	"" | "-h" | "--help")
		show_client_help
		exit 0
		;;
	add)
		cmd_client_add "$@"
		;;
	list)
		cmd_client_list "$@"
		;;
	revoke)
		cmd_client_revoke "$@"
		;;
	renew)
		cmd_client_renew "$@"
		;;
	*)
		log_fatal "未知的 client 子命令: $subcmd。请使用 '$SCRIPT_NAME client --help' 查看用法。"
		;;
	esac
}

# Handle client add command
cmd_client_add() {
	local client_name=""
	local password_flag=false
	local password_value=""

	# First non-flag argument is the client name
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--password)
			password_flag=true
			# Check if next arg is a value or another flag
			if [[ -n "${2:-}" ]] && [[ ! "$2" =~ ^- ]]; then
				password_value="$2"
				shift
			fi
			shift
			;;
		--cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--cert-days requires an argument"
			validate_positive_int "$2" "cert-days"
			CLIENT_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		--output)
			[[ -z "${2:-}" ]] && log_fatal "--output requires an argument"
			CLIENT_FILEPATH="$2"
			shift 2
			;;
		-h | --help)
			show_client_add_help
			exit 0
			;;
		-*)
			log_fatal "未知选项: $1。请使用 '$SCRIPT_NAME client add --help' 查看用法。"
			;;
		*)
			if [[ -z "$client_name" ]]; then
				client_name="$1"
			else
				log_fatal "Unexpected argument: $1"
			fi
			shift
			;;
		esac
	done

	[[ -z "$client_name" ]] && log_fatal "请指定客户端名称。使用 '$SCRIPT_NAME client add --help' 查看用法。"
	validate_client_name "$client_name"

	requireOpenVPN

	# Set up variables for newClient function
	CLIENT="$client_name"
	CLIENT_CERT_DURATION_DAYS=${CLIENT_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}

	if [[ $password_flag == true ]]; then
		PASS=2
		if [[ -n "$password_value" ]]; then
			PASSPHRASE="$password_value"
		fi
	else
		PASS=1
	fi

	newClient
	exit 0
}

# Handle client list command
cmd_client_list() {
	local format="table"

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--format)
			[[ -z "${2:-}" ]] && log_fatal "--format requires an argument"
			case "$2" in
			table | json) format="$2" ;;
			*) log_fatal "Invalid format: $2. Use 'table' or 'json'." ;;
			esac
			shift 2
			;;
		-h | --help)
			show_client_list_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请使用 '$SCRIPT_NAME client list --help' 查看用法。"
			;;
		esac
	done

	requireOpenVPN

	OUTPUT_FORMAT="$format" listClients
}

# Handle client revoke command
cmd_client_revoke() {
	local client_name=""
	local force=false

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-f | --force)
			force=true
			shift
			;;
		-h | --help)
			show_client_revoke_help
			exit 0
			;;
		-*)
			log_fatal "未知选项: $1。请使用 '$SCRIPT_NAME client revoke --help' 查看用法。"
			;;
		*)
			if [[ -z "$client_name" ]]; then
				client_name="$1"
			else
				log_fatal "Unexpected argument: $1"
			fi
			shift
			;;
		esac
	done

	[[ -z "$client_name" ]] && log_fatal "请指定客户端名称。使用 '$SCRIPT_NAME client revoke --help' 查看用法。"

	requireOpenVPN

	CLIENT="$client_name"
	if [[ $force == true ]]; then
		REVOKE_CONFIRM=y
	fi

	revokeClient
}

# Handle client renew command
cmd_client_renew() {
	local client_name=""

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--cert-days requires an argument"
			validate_positive_int "$2" "cert-days"
			CLIENT_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		-h | --help)
			show_client_renew_help
			exit 0
			;;
		-*)
			log_fatal "未知选项: $1。请使用 '$SCRIPT_NAME client renew --help' 查看用法。"
			;;
		*)
			if [[ -z "$client_name" ]]; then
				client_name="$1"
			else
				log_fatal "Unexpected argument: $1"
			fi
			shift
			;;
		esac
	done

	[[ -z "$client_name" ]] && log_fatal "请指定客户端名称。使用 '$SCRIPT_NAME client renew --help' 查看用法。"

	requireOpenVPN

	CLIENT="$client_name"
	CLIENT_CERT_DURATION_DAYS=${CLIENT_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}

	renewClient
}

# Handle server command
cmd_server() {
	local subcmd="${1:-}"
	shift || true

	case "$subcmd" in
	"" | "-h" | "--help")
		show_server_help
		exit 0
		;;
	status)
		cmd_server_status "$@"
		;;
	renew)
		cmd_server_renew "$@"
		;;
	*)
		log_fatal "未知的 server 子命令: $subcmd。请使用 '$SCRIPT_NAME server --help' 查看用法。"
		;;
	esac
}

# Handle server status command
cmd_server_status() {
	local format="table"

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--format)
			[[ -z "${2:-}" ]] && log_fatal "--format requires an argument"
			case "$2" in
			table | json) format="$2" ;;
			*) log_fatal "Invalid format: $2. Use 'table' or 'json'." ;;
			esac
			shift 2
			;;
		-h | --help)
			show_server_status_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请使用 '$SCRIPT_NAME server status --help' 查看用法。"
			;;
		esac
	done

	requireOpenVPN

	OUTPUT_FORMAT="$format" listConnectedClients
}

# Handle server renew command
cmd_server_renew() {
	local force=false

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--cert-days requires an argument"
			validate_positive_int "$2" "cert-days"
			SERVER_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		-f | --force)
			force=true
			shift
			;;
		-h | --help)
			show_server_renew_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请使用 '$SCRIPT_NAME server renew --help' 查看用法。"
			;;
		esac
	done

	requireOpenVPN

	SERVER_CERT_DURATION_DAYS=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
	if [[ $force == true ]]; then
		CONTINUE=y
	fi

	renewServer
}

# Handle interactive command (legacy menu)
cmd_interactive() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-h | --help)
			echo "启动 OpenVPN 交互式管理菜单"
			echo ""
			echo "用法: $SCRIPT_NAME interactive"
			exit 0
			;;
		*)
			log_fatal "Unknown option: $1"
			;;
		esac
	done

	if isOpenVPNInstalled; then
		manageMenu
	else
		installQuestions
		installOpenVPN
	fi
}

# Ensure UTF-8 locale for correct display of Chinese and other characters
ensure_utf8_locale() {
	local loc
	# If any of LANG, LC_ALL, LC_CTYPE already indicates UTF-8, leave as is
	if [[ "${LANG:-}" == *[Uu][Tt][Ff]*8* ]] || [[ "${LC_ALL:-}" == *[Uu][Tt][Ff]*8* ]] || [[ "${LC_CTYPE:-}" == *[Uu][Tt][Ff]*8* ]]; then
		return 0
	fi
	# Try common UTF-8 locales in order of preference
	for loc in C.UTF-8 en_US.UTF-8 zh_CN.UTF-8; do
		if locale -a 2>/dev/null | grep -qxi "${loc}"; then
			export LANG="$loc"
			export LC_ALL="$loc"
			return 0
		fi
	done
	# Fallback: set C.UTF-8 anyway (may not be available on all systems)
	export LANG=C.UTF-8
	export LC_ALL=C.UTF-8
}

# Main argument parser
parse_args() {
	ensure_utf8_locale
	# Parse global options first
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--verbose)
			VERBOSE=1
			shift
			;;
		--log)
			[[ -z "${2:-}" ]] && log_fatal "--log requires an argument"
			LOG_FILE="$2"
			shift 2
			;;
		--no-log)
			LOG_FILE=""
			shift
			;;
		--no-color)
			# Colors already set at script start, but we can unset them
			COLOR_RESET=''
			COLOR_RED=''
			COLOR_GREEN=''
			COLOR_YELLOW=''
			COLOR_BLUE=''
			COLOR_CYAN=''
			COLOR_DIM=''
			COLOR_BOLD=''
			shift
			;;
		-h | --help)
			show_help
			exit 0
			;;
		-*)
			# Could be a command-specific option, let command handle it
			break
			;;
		*)
			# First non-option is the command
			break
			;;
		esac
	done

	# Get the command
	local cmd="${1:-}"
	shift || true

	# Check if user just wants help (don't require root for help)
	# Also detect --format json early to suppress log output before initialCheck
	local wants_help=false
	local prev_arg=""
	for arg in "$@"; do
		if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
			wants_help=true
		fi
		if [[ "$prev_arg" == "--format" && "$arg" == "json" ]]; then
			OUTPUT_FORMAT="json"
		fi
		prev_arg="$arg"
	done

	# Dispatch to command handler (no command = default to interactive: install if not installed, else manage menu)
	case "$cmd" in
	"")
		[[ $wants_help == false ]] && initialCheck
		cmd_interactive "$@"
		;;
	install)
		[[ $wants_help == false ]] && initialCheck
		cmd_install "$@"
		;;
	uninstall)
		[[ $wants_help == false ]] && initialCheck
		cmd_uninstall "$@"
		;;
	client)
		[[ $wants_help == false ]] && initialCheck
		cmd_client "$@"
		;;
	server)
		[[ $wants_help == false ]] && initialCheck
		cmd_server "$@"
		;;
	fix)
		[[ $wants_help == false ]] && initialCheck
		requireOpenVPN
		fixOpenVPNSystemdService
		;;
	interactive)
		[[ $wants_help == false ]] && initialCheck
		cmd_interactive "$@"
		;;
	*)
		log_fatal "未知命令: $cmd。请使用 '$SCRIPT_NAME --help' 查看用法。"
		;;
	esac
}

# =============================================================================
# System Check Functions
# =============================================================================
function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 11 ]]; then
				log_warn "Your version of Debian is not supported."
				log_info "However, if you're using Debian >= 11 or unstable/testing, you can continue at your own risk."
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 18 ]]; then
				log_warn "Your version of Ubuntu is not supported."
				log_info "However, if you're using Ubuntu >= 18.04 or beta, you can continue at your own risk."
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/os-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "opensuse-tumbleweed" ]]; then
			OS="opensuse"
		fi
		if [[ $ID == "opensuse-leap" ]]; then
			OS="opensuse"
			if [[ ${VERSION_ID%.*} -lt 16 ]]; then
				log_info "The script only supports openSUSE Leap 16+."
				log_fatal "Your version of openSUSE Leap is not supported."
			fi
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
		fi
		if [[ $OS =~ (centos|oracle) ]] && [[ ${VERSION_ID%.*} -lt 8 ]]; then
			log_info "The script only supports CentOS Stream / Rocky Linux / AlmaLinux / Oracle Linux version 8+."
			log_fatal "Your version is not supported."
		fi
		if [[ $ID == "amzn" ]]; then
			if [[ "$PRETTY_NAME" =~ ^Amazon\ Linux\ 2023\.([0-9]+) ]] && [[ "${BASH_REMATCH[1]}" -ge 6 ]]; then
				OS="amzn2023"
			else
				log_info "The script only supports Amazon Linux 2023.6+"
				log_info "Amazon Linux 2 is EOL and no longer supported."
				log_fatal "Your version of Amazon Linux is not supported."
			fi
		fi
		if [[ $ID == "arch" ]]; then
			OS="arch"
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		log_fatal "It looks like you aren't running this installer on a Debian, Ubuntu, Fedora, openSUSE, CentOS, Amazon Linux 2023, Oracle Linux, Arch Linux, Rocky Linux or AlmaLinux system."
	fi
}

function checkArchPendingKernelUpgrade() {
	if [[ $OS != "arch" ]]; then
		return 0
	fi

	# Check if running kernel's modules are available
	# (detects if kernel was upgraded but system not rebooted)
	# Skip this check in containers - they share host kernel but have their own /lib/modules
	if [[ -f /.dockerenv ]] || grep -qE '(docker|lxc|containerd)' /proc/1/cgroup 2>/dev/null; then
		log_info "Running in container, skipping kernel modules check"
	else
		local running_kernel
		running_kernel=$(uname -r)
		if [[ ! -d "/lib/modules/${running_kernel}" ]]; then
			log_error "Kernel modules for running kernel ($running_kernel) not found!"
			log_info "This usually means the kernel was upgraded but the system wasn't rebooted."
			log_fatal "Please reboot your system and run this script again."
		fi
	fi

	log_info "Checking for pending kernel upgrades on Arch Linux..."

	# Sync package database to check for updates
	if ! pacman -Sy &>/dev/null; then
		log_warn "Failed to sync package database, skipping kernel upgrade check"
		return 0
	fi

	# Check for pending linux kernel upgrades
	local pending_kernels
	pending_kernels=$(pacman -Qu 2>/dev/null | grep -E '^linux' || true)

	if [[ -n "$pending_kernels" ]]; then
		log_warn "Linux kernel upgrade(s) pending:"
		echo "$pending_kernels" | while read -r line; do
			log_info "  $line"
		done
		echo ""
		log_info "This script uses 'pacman -Syu' which will upgrade your kernel."
		log_info "After a kernel upgrade, the TUN module won't be available until you reboot."
		echo ""
		log_info "Please upgrade your system and reboot first:"
		log_info "  sudo pacman -Syu"
		log_info "  sudo reboot"
		echo ""
		log_fatal "Aborting. Run this script again after upgrading and rebooting."
	fi

	log_success "No pending kernel upgrades"
}

function initialCheck() {
	log_debug "Checking root privileges..."
	if ! isRoot; then
		log_fatal "Sorry, you need to run this script as root."
	fi
	log_debug "Root check passed"

	log_debug "Checking TUN device availability..."
	if ! tunAvailable; then
		log_fatal "TUN is not available."
	fi
	log_debug "TUN device available at /dev/net/tun"

	log_debug "Detecting operating system..."
	checkOS
	log_debug "Detected OS: $OS (${PRETTY_NAME:-unknown})"
	checkArchPendingKernelUpgrade
}

# Check if OpenVPN version is at least the specified version
# Usage: openvpnVersionAtLeast "2.5"
# Returns 0 if version is >= specified, 1 otherwise
function openvpnVersionAtLeast() {
	local required_version="$1"
	local installed_version

	if ! command -v openvpn &>/dev/null; then
		return 1
	fi

	installed_version=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')
	if [[ -z "$installed_version" ]]; then
		return 1
	fi

	# Compare versions using sort -V
	if [[ "$(printf '%s\n' "$required_version" "$installed_version" | sort -V | head -n1)" == "$required_version" ]]; then
		return 0
	fi
	return 1
}

# Check if kernel version is at least the specified version
# Usage: kernelVersionAtLeast "6.16"
# Returns 0 if version is >= specified, 1 otherwise
function kernelVersionAtLeast() {
	local required_version="$1"
	local kernel_version

	kernel_version=$(uname -r | cut -d'-' -f1)
	if [[ -z "$kernel_version" ]]; then
		return 1
	fi

	if [[ "$(printf '%s\n' "$required_version" "$kernel_version" | sort -V | head -n1)" == "$required_version" ]]; then
		return 0
	fi
	return 1
}

# Check if Data Channel Offload (DCO) is available
# DCO requires: OpenVPN 2.6+, kernel support (Linux 6.16+ or ovpn-dco module)
# Returns 0 if DCO is available, 1 otherwise
function isDCOAvailable() {
	# DCO requires OpenVPN 2.6+
	if ! openvpnVersionAtLeast "2.6"; then
		return 1
	fi

	# DCO is built into Linux 6.16+, or available via ovpn-dco module
	if kernelVersionAtLeast "6.16"; then
		return 0
	elif lsmod 2>/dev/null | grep -q "^ovpn_dco" || modinfo ovpn-dco &>/dev/null; then
		return 0
	fi
	return 1
}

function installOpenVPNRepo() {
	log_info "Setting up official OpenVPN repository..."

	if [[ $OS =~ (debian|ubuntu) ]]; then
		run_cmd_fatal "Update package lists" apt-get update
		run_cmd_fatal "Installing prerequisites" apt-get install -y ca-certificates curl

		# Create keyrings directory
		run_cmd "Creating keyrings directory" mkdir -p /etc/apt/keyrings

		# Download and install GPG key
		if ! run_cmd "Downloading OpenVPN GPG key" curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg -o /etc/apt/keyrings/openvpn-repo-public.asc; then
			log_fatal "Failed to download OpenVPN repository GPG key"
		fi

		# Add repository - using stable release
		if [[ -z "${VERSION_CODENAME}" ]]; then
			log_fatal "VERSION_CODENAME is not set. Unable to configure OpenVPN repository."
		fi
		echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/openvpn-repo-public.asc] https://build.openvpn.net/debian/openvpn/stable ${VERSION_CODENAME} main" >/etc/apt/sources.list.d/openvpn-aptrepo.list

		log_info "正在使用新源更新软件包列表..."
		run_cmd_fatal "Update package lists" apt-get update

		log_info "OpenVPN 官方源已配置"

	elif [[ $OS =~ (centos|oracle) ]]; then
		# For RHEL-based systems, use Fedora Copr (OpenVPN 2.6 stable)
		# EPEL is required for pkcs11-helper dependency
		log_info "Configuring OpenVPN Copr repository for RHEL-based system..."

		# Oracle Linux uses oracle-epel-release-el* instead of epel-release
		if [[ $OS == "oracle" ]]; then
			EPEL_PACKAGE="oracle-epel-release-el${VERSION_ID%.*}"
		else
			EPEL_PACKAGE="epel-release"
		fi

		if ! command -v dnf &>/dev/null; then
			run_cmd_fatal "Installing EPEL repository" yum install -y "$EPEL_PACKAGE"
			run_cmd_fatal "Installing yum-plugin-copr" yum install -y yum-plugin-copr
			run_cmd_fatal "Enabling OpenVPN Copr repo" yum copr enable -y @OpenVPN/openvpn-release-2.6
		else
			run_cmd_fatal "Installing EPEL repository" dnf install -y "$EPEL_PACKAGE"
			run_cmd_fatal "Installing dnf-plugins-core" dnf install -y dnf-plugins-core
			run_cmd_fatal "Enabling OpenVPN Copr repo" dnf copr enable -y @OpenVPN/openvpn-release-2.6
		fi

		log_info "OpenVPN Copr repository configured"

	elif [[ $OS == "fedora" ]]; then
		# Fedora already ships with recent OpenVPN 2.6.x, no Copr needed
		log_info "Fedora already has recent OpenVPN packages, using distribution version"

	else
		log_info "No official OpenVPN repository available for this OS, using distribution packages"
	fi
}

function installUnbound() {
	log_info "Installing Unbound DNS resolver..."

	# Install Unbound if not present
	if [[ ! -e /etc/unbound/unbound.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd_fatal "Installing Unbound" apt-get install -y unbound
		elif [[ $OS =~ (centos|oracle) ]]; then
			run_cmd_fatal "Installing Unbound" yum install -y unbound
		elif [[ $OS =~ (fedora|amzn2023) ]]; then
			run_cmd_fatal "Installing Unbound" dnf install -y unbound
		elif [[ $OS == "opensuse" ]]; then
			run_cmd_fatal "Installing Unbound" zypper install -y unbound
		elif [[ $OS == "arch" ]]; then
			run_cmd_fatal "Installing Unbound" pacman -Syu --noconfirm unbound
		fi
	fi

	# Configure Unbound for OpenVPN (runs whether freshly installed or pre-existing)
	# Create conf.d directory (works on all distros)
	run_cmd "Creating Unbound config directory" mkdir -p /etc/unbound/unbound.conf.d

	# Ensure main config includes conf.d directory
	# Modern Debian/Ubuntu use include-toplevel, others need include directive
	if ! grep -qE "include(-toplevel)?:\s*.*/etc/unbound/unbound.conf.d" /etc/unbound/unbound.conf 2>/dev/null; then
		# Add include directive for conf.d if not present
		echo 'include: "/etc/unbound/unbound.conf.d/*.conf"' >>/etc/unbound/unbound.conf
	fi

	# Generate OpenVPN-specific Unbound configuration
	# Using consistent best-practice settings across all distros
	{
		echo 'server:'
		echo '    # OpenVPN DNS resolver configuration'

		# IPv4 VPN interface (only if clients get IPv4)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "    interface: $VPN_GATEWAY_IPV4"
			echo "    access-control: $VPN_SUBNET_IPV4/24 allow"
		fi

		# IPv6 VPN interface (only if clients get IPv6)
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "    interface: $VPN_GATEWAY_IPV6"
			echo "    access-control: ${VPN_SUBNET_IPV6}/112 allow"
		fi

		echo ''
		echo '    # Security hardening'
		echo '    hide-identity: yes'
		echo '    hide-version: yes'
		echo '    harden-glue: yes'
		echo '    harden-dnssec-stripped: yes'
		echo ''
		echo '    # Performance optimizations'
		echo '    prefetch: yes'
		echo '    use-caps-for-id: yes'
		echo '    qname-minimisation: yes'
		echo ''
		echo '    # Allow binding before tun interface exists'
		echo '    ip-freebind: yes'
		echo ''
		echo '    # DNS rebinding protection'
		echo '    private-address: 10.0.0.0/8'
		echo '    private-address: 172.16.0.0/12'
		echo '    private-address: 192.168.0.0/16'
		echo '    private-address: 169.254.0.0/16'
		echo '    private-address: 127.0.0.0/8'
		echo '    private-address: fd00::/8'
		echo '    private-address: fe80::/10'
		echo '    private-address: ::ffff:0:0/96'

		# Add VPN subnet to private addresses if IPv6 enabled
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "    private-address: ${VPN_SUBNET_IPV6}/112"
		fi

		# Disable remote-control (requires SSL certs on openSUSE)
		if [[ $OS == "opensuse" ]]; then
			echo ''
			echo 'remote-control:'
			echo '    control-enable: no'
		fi
	} >/etc/unbound/unbound.conf.d/openvpn.conf

	run_cmd "Enabling Unbound service" systemctl enable unbound
	run_cmd "Starting Unbound service" systemctl restart unbound

	# Validate Unbound is running
	for i in {1..10}; do
		if pgrep -x unbound >/dev/null; then
			return 0
		fi
		sleep 1
	done
	log_fatal "Unbound failed to start. Check 'journalctl -u unbound' for details."
}

function resolvePublicIPv4() {
	local public_ip=""

	# Try to resolve public IPv4 using: https://api.seeip.org
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -4 https://api.seeip.org 2>/dev/null)
	fi

	# Try to resolve using: https://ifconfig.me
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -4 https://ifconfig.me 2>/dev/null)
	fi

	# Try to resolve using: https://api.ipify.org
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -4 https://api.ipify.org 2>/dev/null)
	fi

	# Try to resolve using: ns1.google.com
	if [[ -z $public_ip ]]; then
		public_ip=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi

	echo "$public_ip"
}

function resolvePublicIPv6() {
	local public_ip=""

	# Try to resolve public IPv6 using: https://api6.seeip.org
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -6 https://api6.seeip.org 2>/dev/null)
	fi

	# Try to resolve using: https://ifconfig.me (IPv6)
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -6 https://ifconfig.me 2>/dev/null)
	fi

	# Try to resolve using: https://api64.ipify.org (dual-stack, prefer IPv6)
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -6 https://api64.ipify.org 2>/dev/null)
	fi

	# Try to resolve using: ns1.google.com
	if [[ -z $public_ip ]]; then
		public_ip=$(dig -6 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi

	echo "$public_ip"
}

# Legacy wrapper for backward compatibility
function resolvePublicIP() {
	if [[ $ENDPOINT_TYPE == "6" ]]; then
		resolvePublicIPv6
	else
		resolvePublicIPv4
	fi
}

# Detect server's IPv4 and IPv6 addresses
function detect_server_ips() {
	IP_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	IP_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	# Set IP based on ENDPOINT_TYPE
	if [[ $ENDPOINT_TYPE == "6" ]]; then
		IP="$IP_IPV6"
	else
		IP="$IP_IPV4"
	fi
}

# Calculate derived network configuration values
function prepare_network_config() {
	# Calculate IPv4 gateway (always needed for leak prevention)
	VPN_GATEWAY_IPV4="${VPN_SUBNET_IPV4%.*}.1"

	# Calculate IPv6 gateway if IPv6 is enabled
	if [[ $CLIENT_IPV6 == "y" ]]; then
		VPN_GATEWAY_IPV6="${VPN_SUBNET_IPV6}1"
	fi

	# Set legacy variable for backward compatibility
	IPV6_SUPPORT="$CLIENT_IPV6"
}

function installQuestions() {
	log_header "OpenVPN 安装向导"
	log_prompt "项目地址: https://github.com/angristan/openvpn-install"

	log_prompt "安装前需要确认以下选项。"
	log_prompt "可直接回车使用默认值。"

	# ==========================================================================
	# Step 1: Detect server IP addresses
	# ==========================================================================
	log_menu ""
	log_prompt "正在检测本机 IP 地址..."

	# Detect IPv4 address
	IP_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	# Detect IPv6 address
	IP_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -n $IP_IPV4 ]]; then
		log_prompt "  检测到 IPv4: $IP_IPV4"
	else
		log_prompt "  未检测到 IPv4"
	fi
	if [[ -n $IP_IPV6 ]]; then
		log_prompt "  检测到 IPv6: $IP_IPV6"
	else
		log_prompt "  未检测到 IPv6"
	fi

	# ==========================================================================
	# Step 2: Endpoint type selection
	# ==========================================================================
	log_menu ""
	log_prompt "客户端使用哪种 IP 版本连接本服务器？"

	# Determine default based on available addresses
	if [[ -n $IP_IPV4 ]]; then
		ENDPOINT_TYPE_DEFAULT=1
	elif [[ -n $IP_IPV6 ]]; then
		ENDPOINT_TYPE_DEFAULT=2
	else
		log_fatal "本机未检测到 IPv4 或 IPv6 地址。"
	fi

	log_menu "   1) IPv4"
	log_menu "   2) IPv6"
	until [[ $ENDPOINT_TYPE_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "连接类型 [1-2]: " -e -i $ENDPOINT_TYPE_DEFAULT ENDPOINT_TYPE_CHOICE
	done
	case $ENDPOINT_TYPE_CHOICE in
	1)
		ENDPOINT_TYPE="4"
		IP="$IP_IPV4"
		;;
	2)
		ENDPOINT_TYPE="6"
		IP="$IP_IPV6"
		;;
	esac

	# ==========================================================================
	# Step 3: Endpoint address (handle NAT for IPv4, direct for IPv6)
	# ==========================================================================
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		log_menu ""
		if [[ $ENDPOINT_TYPE == "4" ]]; then
			log_prompt "服务器监听的 IPv4 地址："
			read -rp "IPv4 地址: " -e -i "$IP" IP
		else
			log_prompt "服务器监听的 IPv6 地址："
			read -rp "IPv6 地址: " -e -i "$IP" IP
		fi
	fi

	# If IPv4 and private IP, server is behind NAT
	if [[ $ENDPOINT_TYPE == "4" ]] && echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		log_menu ""
		log_prompt "本机似乎处于 NAT 后。请填写公网 IPv4 地址或主机名。"
		log_prompt "客户端将使用该地址连接服务器。"

		if [[ -z $ENDPOINT ]]; then
			DEFAULT_ENDPOINT=$(resolvePublicIPv4)
		fi

		until [[ $ENDPOINT != "" ]]; do
			read -rp "公网 IPv4 地址或主机名: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
		done
	elif [[ $ENDPOINT_TYPE == "6" ]]; then
		# For IPv6, check if it's a link-local address (starts with fe80)
		if echo "$IP" | grep -qiE '^fe80'; then
			log_menu ""
			log_prompt "检测到的 IPv6 为链路本地地址。请填写公网 IPv6 地址或主机名。"
			log_prompt "客户端将使用该地址连接服务器。"

			if [[ -z $ENDPOINT ]]; then
				DEFAULT_ENDPOINT=$(resolvePublicIPv6)
			fi

			until [[ $ENDPOINT != "" ]]; do
				read -rp "公网 IPv6 地址或主机名: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
			done
		fi
	fi

	# ==========================================================================
	# Step 4: Client IP versions
	# ==========================================================================
	log_menu ""
	log_prompt "VPN 客户端使用哪种 IP 版本？"
	log_prompt "将决定客户端的 VPN 地址及通过隧道的上网方式。"

	# Check IPv6 connectivity for suggestion
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c1 -W2 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c1 -W2 ipv6.google.com > /dev/null 2>&1"
	fi
	HAS_IPV6_CONNECTIVITY="n"
	if eval "$PING6"; then
		HAS_IPV6_CONNECTIVITY="y"
	fi

	# Default suggestion based on connectivity
	if [[ $HAS_IPV6_CONNECTIVITY == "y" ]]; then
		CLIENT_IP_DEFAULT=3 # Dual-stack if IPv6 available
	else
		CLIENT_IP_DEFAULT=1 # IPv4 only otherwise
	fi

	log_menu "   1) 仅 IPv4"
	log_menu "   2) 仅 IPv6"
	log_menu "   3) 双栈 (IPv4 + IPv6)"
	until [[ $CLIENT_IP_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "客户端 IP 版本 [1-3]: " -e -i $CLIENT_IP_DEFAULT CLIENT_IP_CHOICE
	done
	case $CLIENT_IP_CHOICE in
	1)
		CLIENT_IPV4="y"
		CLIENT_IPV6="n"
		;;
	2)
		CLIENT_IPV4="n"
		CLIENT_IPV6="y"
		;;
	3)
		CLIENT_IPV4="y"
		CLIENT_IPV6="y"
		;;
	esac

	# ==========================================================================
	# Step 5: IPv4 subnet (prompt only if IPv4 enabled, but always set for leak prevention)
	# ==========================================================================
	if [[ $CLIENT_IPV4 == "y" ]]; then
		log_menu ""
		log_prompt "IPv4 VPN 网段："
		log_menu "   1) 默认: 10.8.0.0/24"
		log_menu "   2) 自定义"
		until [[ $SUBNET_IPV4_CHOICE =~ ^[1-2]$ ]]; do
			read -rp "IPv4 网段 [1-2]: " -e -i 1 SUBNET_IPV4_CHOICE
		done
		case $SUBNET_IPV4_CHOICE in
		1)
			VPN_SUBNET_IPV4="10.8.0.0"
			;;
		2)
			# Skip prompt if VPN_SUBNET_IPV4 is already set (e.g., via environment variable)
			if [[ -z $VPN_SUBNET_IPV4 ]]; then
				until [[ $VPN_SUBNET_IPV4 =~ ^(10\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|172\.(1[6-9]|2[0-9]|3[0-1])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|192\.168\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\.0$ ]]; do
					read -rp "自定义 IPv4 网段（如 10.9.0.0）: " VPN_SUBNET_IPV4
				done
			fi
			;;
		esac
	else
		# IPv6-only mode: still assign IPv4 subnet to clients for compatibility
		VPN_SUBNET_IPV4="10.8.0.0"
	fi

	# ==========================================================================
	# Step 6: IPv6 subnet (if IPv6 enabled for clients)
	# ==========================================================================
	if [[ $CLIENT_IPV6 == "y" ]]; then
		log_menu ""
		log_prompt "IPv6 VPN 网段："
		log_menu "   1) 默认: fd42:42:42:42::/112"
		log_menu "   2) 自定义"
		until [[ $SUBNET_IPV6_CHOICE =~ ^[1-2]$ ]]; do
			read -rp "IPv6 网段 [1-2]: " -e -i 1 SUBNET_IPV6_CHOICE
		done
		case $SUBNET_IPV6_CHOICE in
		1)
			VPN_SUBNET_IPV6="fd42:42:42:42::"
			;;
		2)
			# Skip prompt if VPN_SUBNET_IPV6 is already set (e.g., via environment variable)
			if [[ -z $VPN_SUBNET_IPV6 ]]; then
				until [[ $VPN_SUBNET_IPV6 =~ ^fd[0-9a-fA-F]{0,2}(:[0-9a-fA-F]{0,4}){0,6}::$ ]]; do
					read -rp "自定义 IPv6 网段（如 fd12:3456:789a::）: " VPN_SUBNET_IPV6
				done
			fi
			;;
		esac
	fi

	log_menu ""
	log_prompt "OpenVPN 监听端口？"
	log_menu "   1) 随机 [49152-65535]（推荐）"
	log_menu "   2) 自定义"
	log_menu "   3) 默认 1194"
	until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "端口 [1-3]: " -e -i 1 PORT_CHOICE
	done
	case $PORT_CHOICE in
	1)
		PORT=$(shuf -i 49152-65535 -n1)
		log_info "随机端口: $PORT"
		;;
	2)
		until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
			read -rp "自定义端口 [1-65535]: " -e -i "$(shuf -i 49152-65535 -n1)" PORT
		done
		;;
	3)
		PORT="1194"
		;;
	esac
	log_menu ""
	log_prompt "OpenVPN 使用哪种协议？"
	log_prompt "UDP 更快；TCP 兼容性更好（如过墙、公司网络）。"
	log_menu "   1) UDP"
	log_menu "   2) TCP（推荐）"
	until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "协议 [1-2]: " -e -i 2 PROTOCOL_CHOICE
	done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	log_menu ""
	log_prompt "VPN 使用哪种 DNS 解析？"
	local dns_labels=("当前系统 DNS（/etc/resolv.conf）" "自建 DNS (Unbound)" "Cloudflare（全球）" "Quad9（全球）" "Quad9 无审查（全球）" "FDN（法国）" "DNS.WATCH（德国）" "OpenDNS（全球）" "Google（全球）" "Yandex Basic（俄罗斯）" "AdGuard DNS（全球）" "NextDNS（全球）" "自定义")
	local dns_valid=false
	until [[ $dns_valid == true ]]; do
		select_with_labels "DNS" dns_labels DNS_PROVIDERS "adguard" DNS
		if [[ $DNS == "unbound" ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			log_menu ""
			log_prompt "Unbound 已安装。"
			log_prompt "可让本脚本配置 Unbound，供 OpenVPN 客户端使用。"
			log_prompt "将在 /etc/unbound/unbound.conf 中为 OpenVPN 网段添加一个服务器块。"
			log_prompt "不会修改现有配置。"
			log_menu ""

			local unbound_continue
			until [[ $unbound_continue =~ ^[yn]$ ]]; do
				read -rp "是否对 Unbound 应用上述配置？[y/n]: " -e unbound_continue
			done
			if [[ $unbound_continue == "n" ]]; then
				unset DNS
			else
				dns_valid=true
			fi
		elif [[ $DNS == "custom" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "主 DNS: " -e DNS1
			done
			until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
				read -rp "备用 DNS（可选）: " -e DNS2
				if [[ $DNS2 == "" ]]; then
					break
				fi
			done
			dns_valid=true
		else
			dns_valid=true
		fi
	done
	log_menu ""
	log_prompt "是否允许同一 .ovpn 配置在多个设备上同时使用？"
	log_prompt "注意：启用后客户端将不再有固定 IP。"
	until [[ $MULTI_CLIENT =~ (y|n) ]]; do
		read -rp "每客户端允许多设备？[y/n]: " -e -i n MULTI_CLIENT
	done
	log_menu ""
	log_prompt "是否自定义隧道 MTU？"
	log_menu "   MTU 控制最大包大小，降低可改善部分网络（如 PPPoE、移动网）的连通性。"
	log_menu "   1) 默认 (1500) - 适合多数网络"
	log_menu "   2) 自定义"
	until [[ $MTU_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "MTU [1-2]: " -e -i 1 MTU_CHOICE
	done
	if [[ $MTU_CHOICE == "2" ]]; then
		until [[ $MTU =~ ^[0-9]+$ ]] && [[ $MTU -ge 576 ]] && [[ $MTU -le 65535 ]]; do
			read -rp "MTU [576-65535]: " -e -i 1500 MTU
		done
	fi
	log_menu ""
	log_prompt "选择认证方式："
	log_menu "   1) PKI（证书颁发机构）- 传统 CA 认证（适合较大规模）"
	log_menu "   2) 对等指纹 - 类似 WireGuard 的简化认证（使用证书指纹）"
	log_menu "      注意：指纹模式需 OpenVPN 2.6+，适合家庭/小规模"
	local auth_mode_choice
	until [[ $auth_mode_choice =~ ^[1-2]$ ]]; do
		read -rp "认证方式 [1-2]: " -e -i 1 auth_mode_choice
	done
	case $auth_mode_choice in
	1)
		AUTH_MODE="pki"
		;;
	2)
		AUTH_MODE="fingerprint"
		# Verify OpenVPN 2.6+ is available for fingerprint mode
		local openvpn_ver
		openvpn_ver=$(get_openvpn_version)
		if [[ -n "$openvpn_ver" ]] && ! version_ge "$openvpn_ver" "2.6.0"; then
		log_warn "检测到 OpenVPN $openvpn_ver。指纹模式需要 2.6.0+。"
		log_warn "安装过程中将安装 OpenVPN 2.6+。"
		fi
		;;
	esac
	log_menu ""
	log_prompt "是否自定义加密设置？"
	log_prompt "若不熟悉，建议使用脚本提供的默认参数。"
	log_prompt "脚本中所有选项均为安全配置（与 OpenVPN 默认不同）。"
	log_prompt "详见 https://github.com/angristan/openvpn-install#security-and-encryption"
	log_menu ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "自定义加密设置？[y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# Use default, sane and fast parameters
		CIPHER="AES-128-GCM"
		CERT_TYPE="ecdsa"
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		TLS13_CIPHERSUITES="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
		TLS_VERSION_MIN="1.2"
		TLS_GROUPS="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="crypt"
	else
		log_menu ""
		log_prompt "选择数据通道加密算法："
		log_menu "   1) AES-128-GCM（推荐）"
		log_menu "   2) AES-192-GCM"
		log_menu "   3) AES-256-GCM"
		log_menu "   4) AES-128-CBC"
		log_menu "   5) AES-192-CBC"
		log_menu "   6) AES-256-CBC"
		log_menu "   7) CHACHA20-POLY1305（需 OpenVPN 2.5+，适合无 AES-NI 的设备）"
		until [[ $CIPHER_CHOICE =~ ^[1-7]$ ]]; do
			read -rp "加密算法 [1-7]: " -e -i 1 CIPHER_CHOICE
		done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		7)
			CIPHER="CHACHA20-POLY1305"
			;;
		esac
		log_menu ""
		log_prompt "选择证书类型："
		log_menu "   1) ECDSA（推荐）"
		log_menu "   2) RSA"
		local cert_type_choice
		until [[ $cert_type_choice =~ ^[1-2]$ ]]; do
			read -rp "证书密钥类型 [1-2]: " -e -i 1 cert_type_choice
		done
		case $cert_type_choice in
		1)
			CERT_TYPE="ecdsa"
			log_menu ""
			log_prompt "选择证书密钥使用的椭圆曲线："
			select_from_array "曲线" CERT_CURVES "prime256v1" CERT_CURVE
			;;
		2)
			CERT_TYPE="rsa"
			log_menu ""
			log_prompt "选择证书 RSA 密钥长度："
			select_from_array "RSA 密钥长度" RSA_KEY_SIZES "2048" RSA_KEY_SIZE
			;;
		esac
		log_menu ""
		log_prompt "选择控制通道加密算法："
		local cc_labels cc_values
		if [[ $CERT_TYPE == "ecdsa" ]]; then
			cc_labels=("ECDHE-ECDSA-AES-128-GCM-SHA256（推荐）" "ECDHE-ECDSA-AES-256-GCM-SHA384" "ECDHE-ECDSA-CHACHA20-POLY1305（OpenVPN 2.5+）")
			cc_values=("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256" "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384" "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256")
		else
			cc_labels=("ECDHE-RSA-AES-128-GCM-SHA256（推荐）" "ECDHE-RSA-AES-256-GCM-SHA384" "ECDHE-RSA-CHACHA20-POLY1305（OpenVPN 2.5+）")
			cc_values=("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256" "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384" "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256")
		fi
		select_with_labels "控制通道加密" cc_labels cc_values "${cc_values[0]}" CC_CIPHER
		log_menu ""
		log_prompt "选择最低 TLS 版本："
		log_menu "   1) TLS 1.2（推荐，兼容所有客户端）"
		log_menu "   2) TLS 1.3（更安全，需 OpenVPN 2.5+ 客户端）"
		until [[ $TLS_VERSION_MIN_CHOICE =~ ^[1-2]$ ]]; do
			read -rp "最低 TLS 版本 [1-2]: " -e -i 1 TLS_VERSION_MIN_CHOICE
		done
		case $TLS_VERSION_MIN_CHOICE in
		1)
			TLS_VERSION_MIN="1.2"
			;;
		2)
			TLS_VERSION_MIN="1.3"
			;;
		esac
		log_menu ""
		log_prompt "选择 TLS 1.3 加密套件（在协商为 TLS 1.3 时使用）："
		log_menu "   1) 全部安全套件（推荐）"
		log_menu "   2) 仅 AES-256-GCM"
		log_menu "   3) 仅 AES-128-GCM"
		log_menu "   4) 仅 ChaCha20-Poly1305"
		until [[ $TLS13_CIPHER_CHOICE =~ ^[1-4]$ ]]; do
			read -rp "TLS 1.3 加密套件 [1-4]: " -e -i 1 TLS13_CIPHER_CHOICE
		done
		case $TLS13_CIPHER_CHOICE in
		1)
			TLS13_CIPHERSUITES="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
			;;
		2)
			TLS13_CIPHERSUITES="TLS_AES_256_GCM_SHA384"
			;;
		3)
			TLS13_CIPHERSUITES="TLS_AES_128_GCM_SHA256"
			;;
		4)
			TLS13_CIPHERSUITES="TLS_CHACHA20_POLY1305_SHA256"
			;;
		esac
		log_menu ""
		log_prompt "选择 TLS 密钥交换组（ECDH）："
		log_menu "   1) 全部现代曲线（推荐）"
		log_menu "   2) 仅 X25519（最安全，可能有兼容问题）"
		log_menu "   3) 仅 NIST 曲线（prime256v1, secp384r1, secp521r1）"
		until [[ $TLS_GROUPS_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "TLS 密钥交换组 [1-3]: " -e -i 1 TLS_GROUPS_CHOICE
		done
		case $TLS_GROUPS_CHOICE in
		1)
			TLS_GROUPS="X25519:prime256v1:secp384r1:secp521r1"
			;;
		2)
			TLS_GROUPS="X25519"
			;;
		3)
			TLS_GROUPS="prime256v1:secp384r1:secp521r1"
			;;
		esac
		log_menu ""
		# The "auth" options behaves differently with AEAD ciphers (GCM, ChaCha20-Poly1305)
		if [[ $CIPHER =~ CBC$ ]]; then
			log_prompt "摘要算法用于认证数据通道包及控制通道的 tls-auth 包。"
		elif [[ $CIPHER =~ GCM$ ]] || [[ $CIPHER == "CHACHA20-POLY1305" ]]; then
			log_prompt "摘要算法用于认证控制通道的 tls-auth 包。"
		fi
		log_prompt "选择 HMAC 摘要算法："
		log_menu "   1) SHA-256（推荐）"
		log_menu "   2) SHA-384"
		log_menu "   3) SHA-512"
		until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
			read -rp "摘要算法 [1-3]: " -e -i 1 HMAC_ALG_CHOICE
		done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		log_menu ""
		log_prompt "可为控制通道增加一层安全。"
		local tls_sig_labels=("tls-crypt-v2（推荐）：加密控制通道，每客户端独立密钥" "tls-crypt：加密控制通道，所有客户端共享密钥" "tls-auth：仅认证控制通道，不加密")
		select_with_labels "控制通道安全" tls_sig_labels TLS_SIG_MODES "crypt" TLS_SIG
	fi
	log_menu ""
	log_prompt "走 VPN 的网段：只有这些网段的流量会通过 VPN（分流模式）。"
	log_prompt "请输入逗号分隔的 IPv4 CIDR，例如 192.168.1.0/24,10.0.0.0/8，留空则不推送额外路由。"
	# Auto-detect local LAN subnet as default (e.g. 192.168.110.0/24 from default route interface)
	DEFAULT_PUSH_ROUTES=""
	_detect_nic=$(ip -4 route ls 2>/dev/null | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -n $_detect_nic ]]; then
		_detect_subnet=$(ip -4 route show dev "$_detect_nic" 2>/dev/null | awk '/scope link/ {print $1}' | head -1)
		if [[ -n $_detect_subnet ]] && echo "$_detect_subnet" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)'; then
			DEFAULT_PUSH_ROUTES="$_detect_subnet"
			log_prompt "已根据本机网卡自动识别局域网网段: $DEFAULT_PUSH_ROUTES"
		fi
	fi
	PUSH_ROUTES=${PUSH_ROUTES:-$DEFAULT_PUSH_ROUTES}
	read -rp "走 VPN 的网段（留空跳过）: " -e -i "$PUSH_ROUTES" PUSH_ROUTES
	# Normalize: trim spaces, filter empty
	PUSH_ROUTES=$(echo "$PUSH_ROUTES" | sed 's/,[[:space:]]*/,/g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | sed 's/,[[:space:]]*$//')
	log_menu ""
	log_prompt "性能优化：可根据网络与主机环境选择，以提升吞吐或节省带宽。"
	log_menu "   1) 默认（推荐）：不压缩、系统缓冲区、mssfix 1400，适合多数场景"
	log_menu "   2) 高吞吐：精简配置（无 sndbuf/rcvbuf/mssfix），与高性能备份一致"
	log_menu "   3) 低带宽：启用 lz4 压缩，适合慢速或按流量计费链路"
	log_menu "   4) 关闭：使用 OpenVPN 默认，不做额外优化"
	PERF_OPT=${PERF_OPT:-2}
	until [[ $PERF_OPT =~ ^[1-4]$ ]]; do
		read -rp "请选择 [1-4]: " -e -i 2 PERF_OPT
	done
	log_menu ""
	log_prompt "以上为全部配置项。即将开始安装 OpenVPN 服务器。"
	log_prompt "安装完成后可生成客户端配置。"
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "按任意键继续..."
	fi
}

function installOpenVPN() {
	if [[ $NON_INTERACTIVE_INSTALL == "y" ]]; then
		# Resolve public IP if ENDPOINT not set
		if [[ -z $ENDPOINT ]]; then
			ENDPOINT=$(resolvePublicIP)
		fi

		# Log non-interactive mode and parameters
		log_info "=== OpenVPN 非交互安装 ==="
		log_info "以非交互模式运行，当前参数："
		log_info "  ENDPOINT=$ENDPOINT"
		log_info "  ENDPOINT_TYPE=$ENDPOINT_TYPE"
		log_info "  CLIENT_IPV4=$CLIENT_IPV4"
		log_info "  CLIENT_IPV6=$CLIENT_IPV6"
		log_info "  VPN_SUBNET_IPV4=$VPN_SUBNET_IPV4"
		log_info "  VPN_SUBNET_IPV6=$VPN_SUBNET_IPV6"
		log_info "  PORT=$PORT"
		log_info "  PROTOCOL=$PROTOCOL"
		log_info "  DNS=$DNS"
		[[ -n $MTU ]] && log_info "  MTU=$MTU"
		log_info "  MULTI_CLIENT=$MULTI_CLIENT"
		log_info "  AUTH_MODE=$AUTH_MODE"
		log_info "  CLIENT=$CLIENT"
		log_info "  CLIENT_CERT_DURATION_DAYS=$CLIENT_CERT_DURATION_DAYS"
		log_info "  SERVER_CERT_DURATION_DAYS=$SERVER_CERT_DURATION_DAYS"
		[[ -n $PUSH_ROUTES ]] && log_info "  PUSH_ROUTES=$PUSH_ROUTES"
		log_info "  PERF_OPT=$PERF_OPT"
	fi

	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $CLIENT_IPV6 == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	# $NIC can not be empty for script rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		log_warn "无法检测公网接口。"
		log_info "设置 MASQUERADE 需要该接口。"
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "是否继续？[y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

	# If OpenVPN isn't installed yet, install it. This script is more-or-less
	# idempotent on multiple runs, but will only install OpenVPN from upstream
	# the first time.
	if [[ ! -e /etc/openvpn/server.conf ]]; then
		log_header "正在安装 OpenVPN"

		# Setup official OpenVPN repository for latest versions
		installOpenVPNRepo

		log_info "正在安装 OpenVPN 及依赖..."
		# socat is used for communicating with the OpenVPN management interface (client disconnect on revoke)
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd_fatal "正在安装 OpenVPN" apt-get install -y openvpn iptables openssl curl ca-certificates tar dnsutils socat
			# 自动安装 DCO 内核模块以支持数据通道卸载（需先装内核头文件供 DKMS 编译，包不存在时跳过）
			_kver=$(uname -r)
			if run_cmd "安装当前内核头文件 (linux-headers-$_kver)" apt-get install -y "linux-headers-$_kver" 2>/dev/null; then
				:
			elif run_cmd "安装内核头文件 (linux-headers-amd64)" apt-get install -y linux-headers-amd64 2>/dev/null; then
				:
			fi
			if run_cmd "安装 DCO 内核模块 (openvpn-dco-dkms)" apt-get install -y openvpn-dco-dkms; then
				if modprobe ovpn-dco 2>/dev/null; then
					log_info "ovpn-dco 模块已加载。"
				else
					log_info "ovpn-dco 已安装，首次使用需重启后执行 modprobe ovpn-dco。"
				fi
			fi
		elif [[ $OS == 'centos' ]]; then
			run_cmd_fatal "Installing OpenVPN" yum install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat 'policycoreutils-python*'
		elif [[ $OS == 'oracle' ]]; then
			run_cmd_fatal "Installing OpenVPN" yum install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat policycoreutils-python-utils
		elif [[ $OS == 'amzn2023' ]]; then
			run_cmd_fatal "Installing OpenVPN" dnf install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat
		elif [[ $OS == 'fedora' ]]; then
			run_cmd_fatal "Installing OpenVPN" dnf install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat policycoreutils-python-utils
		elif [[ $OS == 'opensuse' ]]; then
			run_cmd_fatal "Installing OpenVPN" zypper install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat
		elif [[ $OS == 'arch' ]]; then
			run_cmd_fatal "Installing OpenVPN" pacman --needed --noconfirm -Syu openvpn iptables openssl ca-certificates curl tar bind socat
		fi

		# Verify ChaCha20-Poly1305 compatibility if selected
		if [[ $CIPHER == "CHACHA20-POLY1305" ]] || [[ $CC_CIPHER =~ CHACHA20 ]]; then
			local installed_version
			installed_version=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')
			if ! openvpnVersionAtLeast "2.5"; then
				log_fatal "ChaCha20-Poly1305 requires OpenVPN 2.5 or later. Installed version: $installed_version"
			fi
			log_info "当前 OpenVPN 版本支持 ChaCha20-Poly1305"
		fi

		# Check Data Channel Offload (DCO) availability
		if isDCOAvailable; then
			# Check if configuration is DCO-compatible (udp or udp6)
			if [[ $PROTOCOL =~ ^udp ]] && [[ $CIPHER =~ (GCM|CHACHA20-POLY1305) ]]; then
				log_info "数据通道卸载 (DCO) 可用，将用于提升性能"
			else
				log_info "数据通道卸载 (DCO) 可用但未启用（需 UDP + AEAD 加密）"
			fi
		else
			log_info "数据通道卸载 (DCO) 不可用（需 OpenVPN 2.6+ 及内核支持）。Debian/Ubuntu 可安装 openvpn-dco-dkms 后执行 modprobe ovpn-dco，详见 FAQ。"
		fi

		# Create the server directory (OpenVPN 2.4+ directory structure)
		run_cmd_fatal "创建 OpenVPN 目录" mkdir -p /etc/openvpn
	fi

	# Determine which user/group OpenVPN should run as
	# - Fedora/RHEL/Amazon create 'openvpn' user with 'openvpn' group
	# - Arch creates 'openvpn' user with 'network' group
	# - Debian/Ubuntu/openSUSE don't create a dedicated user, use 'nobody'
	#
	# Also check if the systemd service file already handles user/group switching.
	# If so, we shouldn't add user/group to config (would cause double privilege drop).
	SYSTEMD_HANDLES_USER=false
	for service_file in /usr/lib/systemd/system/openvpn-server@.service /lib/systemd/system/openvpn-server@.service; do
		if [[ -f "$service_file" ]] && grep -q "^User=" "$service_file"; then
			SYSTEMD_HANDLES_USER=true
			break
		fi
	done

	if id openvpn &>/dev/null; then
		OPENVPN_USER=openvpn
		# Get the openvpn user's primary group (e.g., 'openvpn' on Fedora, 'network' on Arch)
		OPENVPN_GROUP=$(id -gn openvpn 2>/dev/null || echo openvpn)
	else
		OPENVPN_USER=nobody
		if grep -qs "^nogroup:" /etc/group; then
			OPENVPN_GROUP=nogroup
		else
			OPENVPN_GROUP=nobody
		fi
	fi

	# Install the latest version of easy-rsa from source, if not already installed.
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		download_with_mirror_fallback \
			"https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz" \
			"$HOME/easy-rsa.tgz" \
			"Easy-RSA v${EASYRSA_VERSION}"
		log_info "正在校验 Easy-RSA 校验和..."
		CHECKSUM_OUTPUT=$(echo "${EASYRSA_SHA256}  $HOME/easy-rsa.tgz" | sha256sum -c 2>&1) || {
			_log_to_file "[CHECKSUM] $CHECKSUM_OUTPUT"
			run_cmd "Cleaning up failed download" rm -f ~/easy-rsa.tgz
			log_fatal "SHA256 checksum verification failed for easy-rsa download!"
		}
		_log_to_file "[CHECKSUM] $CHECKSUM_OUTPUT"
		run_cmd_fatal "Creating Easy-RSA directory" mkdir -p /etc/openvpn/easy-rsa
		run_cmd_fatal "Extracting Easy-RSA" tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/easy-rsa
		run_cmd "Cleaning up archive" rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		ecdsa)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		rsa)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
		# Note: 2>/dev/null suppresses "Broken pipe" errors from fold when head exits early
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 2>/dev/null | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 2>/dev/null | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		# Create the PKI, set up the CA, the DH params and the server certificate
		log_info "正在初始化 PKI..."
		run_cmd_fatal "初始化 PKI" ./easyrsa init-pki

		if [[ $AUTH_MODE == "pki" ]]; then
			# Traditional PKI mode with CA
			export EASYRSA_CA_EXPIRE=$DEFAULT_CERT_VALIDITY_DURATION_DAYS
			log_info "正在构建 CA..."
			run_cmd_fatal "构建 CA" ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

			export EASYRSA_CERT_EXPIRE=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
			log_info "正在构建服务器证书..."
			run_cmd_fatal "构建服务器证书" ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
			export EASYRSA_CRL_DAYS=$DEFAULT_CRL_VALIDITY_DURATION_DAYS
			run_cmd_fatal "Generating CRL" ./easyrsa gen-crl
		else
			# Fingerprint mode with self-signed certificates (OpenVPN 2.6+)
			log_info "Building self-signed server certificate for fingerprint mode..."
			export EASYRSA_CERT_EXPIRE=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
			run_cmd_fatal "Building self-signed server certificate" ./easyrsa --batch self-sign-server "$SERVER_NAME" nopass

			# Extract and store server fingerprint
			SERVER_FINGERPRINT=$(openssl x509 -in "pki/issued/$SERVER_NAME.crt" -fingerprint -sha256 -noout | cut -d'=' -f2)
			if [[ -z $SERVER_FINGERPRINT ]]; then
				log_error "Failed to extract server certificate fingerprint"
				exit 1
			fi
			mkdir -p /etc/openvpn
			echo "$SERVER_FINGERPRINT" >/etc/openvpn/server-fingerprint
			log_info "Server fingerprint: $SERVER_FINGERPRINT"
		fi

		log_info "正在生成 TLS 密钥..."
		case $TLS_SIG in
		crypt-v2)
			# Generate tls-crypt-v2 server key
			run_cmd_fatal "Generating tls-crypt-v2 server key" openvpn --genkey tls-crypt-v2-server /etc/openvpn/tls-crypt-v2.key
			;;
		crypt)
			# Generate tls-crypt key
			run_cmd_fatal "Generating tls-crypt key" openvpn --genkey secret /etc/openvpn/tls-crypt.key
			;;
		auth)
			# Generate tls-auth key
			run_cmd_fatal "Generating tls-auth key" openvpn --genkey secret /etc/openvpn/tls-auth.key
			;;
		esac
		# Store auth mode for later use
		echo "$AUTH_MODE" >AUTH_MODE_GENERATED
	else
		# If easy-rsa is already installed, grab the generated SERVER_NAME
		# for client configs
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
		# Read stored auth mode
		if [[ -f AUTH_MODE_GENERATED ]]; then
			AUTH_MODE=$(cat AUTH_MODE_GENERATED)
		else
			# Default to pki for existing installations
			AUTH_MODE="pki"
		fi
	fi

	# Move all the generated files
	log_info "正在复制证书..."
	if [[ $AUTH_MODE == "pki" ]]; then
		run_cmd_fatal "复制证书到 /etc/openvpn" cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
		# Make cert revocation list readable for non-root
		run_cmd "Setting CRL permissions" chmod 644 /etc/openvpn/crl.pem
	else
		# Fingerprint mode: only copy server cert and key (no CA or CRL)
		run_cmd_fatal "复制证书到 /etc/openvpn" cp "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn
	fi

	# Generate server.conf
	log_info "正在生成服务器配置..."
	echo "port $PORT" >/etc/openvpn/server.conf

	# Protocol selection: use proto6 variants if endpoint is IPv6
	if [[ $ENDPOINT_TYPE == "6" ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
	else
		echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	fi

	if [[ $MULTI_CLIENT == "y" ]]; then
		echo "duplicate-cn" >>/etc/openvpn/server.conf
	fi

	echo "dev tun" >>/etc/openvpn/server.conf
	# Only add user/group if systemd doesn't handle it (avoids double privilege drop)
	if [[ $SYSTEMD_HANDLES_USER == "false" ]]; then
		echo "user $OPENVPN_USER
group $OPENVPN_GROUP" >>/etc/openvpn/server.conf
	fi
	echo "persist-key
persist-tun
keepalive 10 120
topology subnet" >>/etc/openvpn/server.conf

	# IPv4 server directive - assign IPv4 to clients for VPN subnet access
	echo "server $VPN_SUBNET_IPV4 255.255.255.0" >>/etc/openvpn/server.conf

	# IPv6 server directive (only if clients get IPv6)
	if [[ $CLIENT_IPV6 == "y" ]]; then
		{
			echo "server-ipv6 ${VPN_SUBNET_IPV6}/112"
			echo "tun-ipv6"
			echo "push tun-ipv6"
		} >>/etc/openvpn/server.conf
	fi

	# ifconfig-pool-persist is incompatible with duplicate-cn
	if [[ $MULTI_CLIENT != "y" ]]; then
		echo "ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf
	fi

	# DNS resolvers
	case $DNS in
	system)
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# Copy IPv4 resolvers if client has IPv4, or IPv6 resolvers if client has IPv6
			if [[ $line =~ ^[0-9.]*$ ]] && [[ $CLIENT_IPV4 == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			elif [[ $line =~ : ]] && [[ $CLIENT_IPV6 == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			fi
		done
		;;
	unbound)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "push \"dhcp-option DNS $VPN_GATEWAY_IPV4\"" >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "push \"dhcp-option DNS $VPN_GATEWAY_IPV6\"" >>/etc/openvpn/server.conf
		fi
		;;
	cloudflare)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2606:4700:4700::1001"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2606:4700:4700::1111"' >>/etc/openvpn/server.conf
		fi
		;;
	quad9)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2620:fe::fe"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2620:fe::9"' >>/etc/openvpn/server.conf
		fi
		;;
	quad9-uncensored)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2620:fe::10"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2620:fe::fe:10"' >>/etc/openvpn/server.conf
		fi
		;;
	fdn)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2001:910:800::40"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2001:910:800::12"' >>/etc/openvpn/server.conf
		fi
		;;
	dnswatch)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2001:1608:10:25::1c04:b12f"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2001:1608:10:25::9249:d69b"' >>/etc/openvpn/server.conf
		fi
		;;
	opendns)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2620:119:35::35"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2620:119:53::53"' >>/etc/openvpn/server.conf
		fi
		;;
	google)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2001:4860:4860::8888"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2001:4860:4860::8844"' >>/etc/openvpn/server.conf
		fi
		;;
	yandex)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2a02:6b8::feed:0ff"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2a02:6b8:0:1::feed:0ff"' >>/etc/openvpn/server.conf
		fi
		;;
	adguard)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2a10:50c0::ad1:ff"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2a10:50c0::ad2:ff"' >>/etc/openvpn/server.conf
		fi
		;;
	nextdns)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2a07:a8c0::"' >>/etc/openvpn/server.conf
			echo 'push "dhcp-option DNS 2a07:a8c1::"' >>/etc/openvpn/server.conf
		fi
		;;
	custom)
		echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server.conf
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server.conf
		fi
		;;
	esac

	# Do NOT set VPN as default gateway (split tunnel): only traffic to VPN subnet and PUSH_ROUTES go through the tunnel.
	# This avoids making the VPN the exit node and prevents issues with local network / internet access.
	# IPv4: no redirect-gateway - client keeps local default route.
	if [[ $CLIENT_IPV6 == "y" ]]; then
		# IPv6: no redirect-gateway - client keeps local IPv6 default route.
		:
	else
		# Block IPv6 on clients to prevent IPv6 leaks when VPN only handles IPv4
		echo 'push "block-ipv6"' >>/etc/openvpn/server.conf
	fi

	# Push custom routes (走 VPN 的网段) so only these subnets go through the VPN
	echo '# PUSH_ROUTES_START' >>/etc/openvpn/server.conf
	PUSH_ROUTES_FILE="/etc/openvpn/push-routes"
	: >"$PUSH_ROUTES_FILE"
	if [[ -n $PUSH_ROUTES ]]; then
		IFS=',' read -ra ROUTES <<< "$PUSH_ROUTES"
		for r in "${ROUTES[@]}"; do
			r=$(echo "$r" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
			[[ -z $r ]] && continue
			parsed=$(parse_push_route_ipv4 "$r")
			if [[ -n $parsed ]]; then
				echo "push \"route $parsed\"" >>/etc/openvpn/server.conf
				echo "$parsed" >>"$PUSH_ROUTES_FILE"
			fi
		done
	fi
	echo '# PUSH_ROUTES_END' >>/etc/openvpn/server.conf

	# Push performance options to clients (PERF_OPT 1/3 推送；2=高性能不推送，与精简备份一致)
	echo '# PERF_PUSH_START' >>/etc/openvpn/server.conf
	case "${PERF_OPT:-2}" in
	1)
		echo 'push "sndbuf 0"' >>/etc/openvpn/server.conf
		echo 'push "rcvbuf 0"' >>/etc/openvpn/server.conf
		echo 'push "allow-compression no"' >>/etc/openvpn/server.conf
		echo 'push "mssfix 1400"' >>/etc/openvpn/server.conf
		;;
	2) ;;
	3)
		echo 'push "compress lz4-v2"' >>/etc/openvpn/server.conf
		echo 'push "sndbuf 0"' >>/etc/openvpn/server.conf
		echo 'push "rcvbuf 0"' >>/etc/openvpn.server.conf
		echo 'push "mssfix 1400"' >>/etc/openvpn.server.conf
		;;
	4) ;;
	esac
	echo '# PERF_PUSH_END' >>/etc/openvpn/server.conf

	if [[ -n $MTU ]]; then
		echo "tun-mtu $MTU" >>/etc/openvpn/server.conf
	fi

	# Use ECDH key exchange (dh none) with tls-groups for curve negotiation
	echo "dh none" >>/etc/openvpn/server.conf
	echo "tls-groups $TLS_GROUPS" >>/etc/openvpn/server.conf

	case $TLS_SIG in
	crypt-v2)
		echo "tls-crypt-v2 tls-crypt-v2.key" >>/etc/openvpn/server.conf
		;;
	crypt)
		echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
		;;
	auth)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
		;;
	esac

	# Common server config options
	# PKI mode adds crl-verify, ca, and remote-cert-tls
	# Fingerprint mode: <peer-fingerprint> block is added when first client is created
	# PERF_OPT 2 = 高性能：仅 cipher+ncp-ciphers+tls-cipher（无 data-ciphers/tls-ciphersuites），无 PERF 块，与精简备份一致
	{
		[[ $AUTH_MODE == "pki" ]] && echo "crl-verify crl.pem
ca ca.crt"
		echo "cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER"
		case "${PERF_OPT:-2}" in
		2)
			echo "ncp-ciphers $CIPHER
tls-server
tls-version-min $TLS_VERSION_MIN
tls-cipher $CC_CIPHER"
			;;
		*)
			echo "ignore-unknown-option data-ciphers
data-ciphers $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min $TLS_VERSION_MIN
tls-cipher $CC_CIPHER
tls-ciphersuites $TLS13_CIPHERSUITES"
			;;
		esac
		[[ $AUTH_MODE == "pki" ]] && echo "remote-cert-tls client"
		echo "client-config-dir ccd
status /var/log/openvpn/status.log
management /var/run/openvpn-server/server.sock unix
verb 3
# PERF_SERVER_START"
		# Performance options (PERF_OPT: 1=default 2=high 3=low 4=off). 2=高性能：不加 sndbuf/rcvbuf/mssfix，与精简备份一致
		case "${PERF_OPT:-2}" in
		1)
			echo "# Performance: OS buffers, no compression, mssfix
sndbuf 0
rcvbuf 0
allow-compression no
mssfix 1400"
			;;
		2) ;;
		3)
			echo "# Performance: lz4 compression for low bandwidth
sndbuf 0
rcvbuf 0
compress lz4-v2
mssfix 1400"
			;;
		4) ;;
		esac
		echo "# PERF_SERVER_END"
	} >>/etc/openvpn/server.conf
	# Store PERF_OPT for later "modify performance" feature
	echo "${PERF_OPT:-2}" >/etc/openvpn/perf-opt

	# Create client-config-dir dir
	run_cmd_fatal "Creating client config directory" mkdir -p /etc/openvpn/ccd
	# Create log dir
	run_cmd_fatal "Creating log directory" mkdir -p /var/log/openvpn

	# On distros that use a dedicated OpenVPN user (not "nobody"), e.g., Fedora, RHEL, Arch,
	# set ownership so OpenVPN can read config/certs and write to log directory
	if [[ $OPENVPN_USER != "nobody" ]]; then
		log_info "Setting ownership for OpenVPN user..."
		chown -R "$OPENVPN_USER:$OPENVPN_GROUP" /etc/openvpn
		chown "$OPENVPN_USER:$OPENVPN_GROUP" /var/log/openvpn
	fi

	# Enable routing
	log_info "正在启用 IP 转发..."
	run_cmd_fatal "Creating sysctl.d directory" mkdir -p /etc/sysctl.d

	# Enable IPv4 forwarding if clients get IPv4
	if [[ $CLIENT_IPV4 == 'y' ]]; then
		echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	else
		echo '# IPv4 forwarding not needed (no IPv4 clients)' >/etc/sysctl.d/99-openvpn.conf
	fi
	# Enable IPv6 forwarding if clients get IPv6
	if [[ $CLIENT_IPV6 == 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
	fi
	# Apply sysctl rules
	run_cmd "Applying sysctl rules" sysctl --system

	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				# Strip "6" suffix from protocol (semanage expects "udp" or "tcp", not "udp6"/"tcp6")
				SELINUX_PROTOCOL="${PROTOCOL%6}"
				run_cmd "Configuring SELinux port" semanage port -a -t openvpn_port_t -p "$SELINUX_PROTOCOL" "$PORT"
			fi
		fi
	fi

	# Finally, restart and enable OpenVPN（经典布局：/etc/openvpn/server.conf）
	log_info "正在配置 OpenVPN 服务..."

	# 本脚本统一使用 openvpn-server@server。先停止并禁用旧名 openvpn@server（若存在），再启用新名
	run_cmd "禁用 openvpn@server（若存在）" systemctl disable openvpn@server 2>/dev/null || true
	run_cmd "停止 openvpn@server（若存在）" systemctl stop openvpn@server 2>/dev/null || true

	# 优先使用 openvpn@.service 作为模板（Type=notify、WorkingDirectory=/etc/openvpn、--config /etc/openvpn/%i.conf 形式，性能更好），复制为 openvpn-server@.service 后仅做必要修补
	if [[ -f /usr/lib/systemd/system/openvpn@.service ]]; then
		SERVICE_SOURCE="/usr/lib/systemd/system/openvpn@.service"
	elif [[ -f /lib/systemd/system/openvpn@.service ]]; then
		SERVICE_SOURCE="/lib/systemd/system/openvpn@.service"
	elif [[ -f /etc/systemd/system/openvpn@.service ]]; then
		SERVICE_SOURCE="/etc/systemd/system/openvpn@.service"
	elif [[ -f /usr/lib/systemd/system/openvpn-server@.service ]]; then
		SERVICE_SOURCE="/usr/lib/systemd/system/openvpn-server@.service"
	elif [[ -f /lib/systemd/system/openvpn-server@.service ]]; then
		SERVICE_SOURCE="/lib/systemd/system/openvpn-server@.service"
	else
		log_fatal "未找到 openvpn@.service 或 openvpn-server@.service，无法创建服务。"
	fi

	run_cmd_fatal "复制并创建 openvpn-server@.service" cp "$SERVICE_SOURCE" /etc/systemd/system/openvpn-server@.service
	# 仅做必要修补，保留 Type=notify、ExecStart 等原样
	grep -q "LimitNPROC" /etc/systemd/system/openvpn-server@.service && run_cmd "修补服务文件 (LimitNPROC)" sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
	grep -q "/etc/openvpn/server" /etc/systemd/system/openvpn-server@.service && run_cmd "修补服务文件 (经典布局路径)" sed -i 's|/etc/openvpn/server|/etc/openvpn|g' /etc/systemd/system/openvpn-server@.service
	if grep -q "WorkingDirectory=" /etc/systemd/system/openvpn-server@.service; then
		run_cmd "修补服务文件 (WorkingDirectory)" sed -i 's|^WorkingDirectory=.*|WorkingDirectory=/etc/openvpn|' /etc/systemd/system/openvpn-server@.service
	else
		run_cmd "修补服务文件 (添加 WorkingDirectory)" sed -i '/\[Service\]/a WorkingDirectory=/etc/openvpn' /etc/systemd/system/openvpn-server@.service
	fi

	run_cmd "重载 systemd" systemctl daemon-reload
	run_cmd "启用 OpenVPN 服务" systemctl enable openvpn-server@server
	if [[ $AUTH_MODE == "pki" ]]; then
		run_cmd "启动 OpenVPN 服务" systemctl restart "$(getOpenVPNServiceUnit)"
	fi

	if [[ $DNS == "unbound" ]]; then
		installUnbound
	fi

	# Configure firewall rules
	# Use source-based rules for VPN traffic (works reliably regardless of which tun interface OpenVPN uses)
	log_info "正在配置防火墙规则..."

	if systemctl is-active --quiet firewalld; then
		# Use firewalld native commands for systems with firewalld active
		log_info "firewalld detected, using firewall-cmd..."
		run_cmd "Adding OpenVPN port to firewalld" firewall-cmd --permanent --add-port="$PORT/$PROTOCOL"
		run_cmd "Adding masquerade to firewalld" firewall-cmd --permanent --add-masquerade

		# Add rich rules for VPN traffic (source-based only, as firewalld doesn't reliably
		# support interface patterns with direct rules when using nftables backend)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			run_cmd "Adding IPv4 VPN subnet rule" firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$VPN_SUBNET_IPV4/24\" accept"
		fi

		if [[ $CLIENT_IPV6 == 'y' ]]; then
			run_cmd "Adding IPv6 VPN subnet rule" firewall-cmd --permanent --add-rich-rule="rule family=\"ipv6\" source address=\"${VPN_SUBNET_IPV6}/112\" accept"
		fi

		run_cmd "Reloading firewalld" firewall-cmd --reload
	elif systemctl is-active --quiet nftables; then
		# Use nftables native rules for systems with nftables active
		log_info "nftables detected, configuring nftables rules..."
		run_cmd_fatal "Creating nftables directory" mkdir -p /etc/nftables

		# Create nftables rules file
		{
			echo "table inet openvpn {"
			echo "	chain input {"
			echo "		type filter hook input priority 0; policy accept;"
			if [[ $CLIENT_IPV4 == 'y' ]]; then
				echo "		iifname \"tun*\" ip saddr $VPN_SUBNET_IPV4/24 accept"
			fi
			if [[ $CLIENT_IPV6 == 'y' ]]; then
				echo "		iifname \"tun*\" ip6 saddr ${VPN_SUBNET_IPV6}/112 accept"
			fi
			echo "		iifname \"$NIC\" $PROTOCOL dport $PORT accept"
			echo "	}"
			echo ""
			echo "	chain forward {"
			echo "		type filter hook forward priority 0; policy accept;"
			if [[ $CLIENT_IPV4 == 'y' ]]; then
				echo "		iifname \"tun*\" ip saddr $VPN_SUBNET_IPV4/24 accept"
				echo "		oifname \"tun*\" ip daddr $VPN_SUBNET_IPV4/24 accept"
			fi
			if [[ $CLIENT_IPV6 == 'y' ]]; then
				echo "		iifname \"tun*\" ip6 saddr ${VPN_SUBNET_IPV6}/112 accept"
				echo "		oifname \"tun*\" ip6 daddr ${VPN_SUBNET_IPV6}/112 accept"
			fi
			echo "	}"
			echo "}"
		} >/etc/nftables/openvpn.nft

		# IPv4 NAT rules (only if clients get IPv4)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "
table ip openvpn-nat {
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip saddr $VPN_SUBNET_IPV4/24 oifname \"$NIC\" masquerade
	}
}" >>/etc/nftables/openvpn.nft
		fi

		# IPv6 NAT rules (only if clients get IPv6)
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "
table ip6 openvpn-nat {
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip6 saddr ${VPN_SUBNET_IPV6}/112 oifname \"$NIC\" masquerade
	}
}" >>/etc/nftables/openvpn.nft
		fi

		# Add include to nftables.conf if not already present
		if ! grep -q 'include.*/etc/nftables/openvpn.nft' /etc/nftables.conf; then
			run_cmd "Adding include to nftables.conf" sh -c 'echo "include \"/etc/nftables/openvpn.nft\"" >> /etc/nftables.conf'
		fi

		# Reload nftables to apply rules
		run_cmd "Reloading nftables" systemctl reload nftables
	else
		# Use iptables for systems without firewalld or nftables
		run_cmd_fatal "Creating iptables directory" mkdir -p /etc/iptables

		# Script to add rules
		echo "#!/bin/sh" >/etc/iptables/add-openvpn-rules.sh

		# IPv4 rules (only if clients get IPv4)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "iptables -t nat -I POSTROUTING 1 -s $VPN_SUBNET_IPV4/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun+ -s $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -I FORWARD 1 -i tun+ -s $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -I FORWARD 1 -o tun+ -d $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
		fi

		# IPv6 rules (only if clients get IPv6)
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "ip6tables -t nat -I POSTROUTING 1 -s ${VPN_SUBNET_IPV6}/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun+ -s ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -I FORWARD 1 -i tun+ -s ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -I FORWARD 1 -o tun+ -d ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
		fi

		# Script to remove rules
		echo "#!/bin/sh" >/etc/iptables/rm-openvpn-rules.sh

		# IPv4 removal rules
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "iptables -t nat -D POSTROUTING -s $VPN_SUBNET_IPV4/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun+ -s $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -D FORWARD -i tun+ -s $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -D FORWARD -o tun+ -d $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
		fi

		# IPv6 removal rules
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "ip6tables -t nat -D POSTROUTING -s ${VPN_SUBNET_IPV6}/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun+ -s ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -D FORWARD -i tun+ -s ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -D FORWARD -o tun+ -d ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
		fi

		run_cmd "Making add-openvpn-rules.sh executable" chmod +x /etc/iptables/add-openvpn-rules.sh
		run_cmd "Making rm-openvpn-rules.sh executable" chmod +x /etc/iptables/rm-openvpn-rules.sh

		# Handle the rules via a systemd script
		echo "[Unit]
Description=iptables rules for OpenVPN
After=firewalld.service
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

		# Enable service and apply rules
		run_cmd "Reloading systemd" systemctl daemon-reload
		run_cmd "Enabling iptables service" systemctl enable iptables-openvpn
		run_cmd "Starting iptables service" systemctl start iptables-openvpn
	fi

	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	# client-template.txt is created so we have a template to add further users later
	log_info "正在创建客户端模板..."
	echo "client" >/etc/openvpn/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	elif [[ $PROTOCOL == 'udp6' ]]; then
		echo "proto udp6" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/client-template.txt
	elif [[ $PROTOCOL == 'tcp6' ]]; then
		echo "proto tcp6-client" >>/etc/openvpn/client-template.txt
	fi
	# Common client template options
	# PKI mode adds remote-cert-tls and verify-x509-name
	# Fingerprint mode adds peer-fingerprint when generating client config
	# PERF_OPT 2 = 高性能客户端：仅 cipher+tls-cipher、route+route-nopull，无 data-ciphers/ncp-ciphers/tls-ciphersuites 与 sndbuf/rcvbuf/mssfix
	{
		echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun"
		[[ $AUTH_MODE == "pki" ]] && echo "remote-cert-tls server
verify-x509-name $SERVER_NAME name"
		echo "auth $HMAC_ALG
auth-nocache
cipher $CIPHER"
		case "${PERF_OPT:-2}" in
		2)
			# 高性能：仅 cipher + tls-cipher，不加 data-ciphers/ncp-ciphers/tls-ciphersuites
			echo "tls-client
tls-version-min $TLS_VERSION_MIN
tls-cipher $CC_CIPHER"
			;;
		*)
			echo "ignore-unknown-option data-ciphers
data-ciphers $CIPHER
ncp-ciphers $CIPHER
tls-client
tls-version-min $TLS_VERSION_MIN
tls-cipher $CC_CIPHER
tls-ciphersuites $TLS13_CIPHERSUITES"
			;;
		esac
		echo "ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3
# PERF_CLIENT_START"
		# Performance options in client template (PERF_OPT 1=default 2=high 3=low 4=off)
		case "${PERF_OPT:-2}" in
		2)
			# 高性能：仅 split tunnel（route + pull-filter + route-nopull），不加 sndbuf/rcvbuf/mssfix
			if [[ -n $PUSH_ROUTES ]]; then
				IFS=',' read -ra ROUTES <<< "$PUSH_ROUTES"
				for r in "${ROUTES[@]}"; do
					r=$(echo "$r" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
					[[ -z $r ]] && continue
					parsed=$(parse_push_route_ipv4 "$r")
					[[ -n $parsed ]] && echo "route $parsed"
				done
			fi
			echo "pull-filter ignore \"redirect-gateway\"
route-nopull"
			;;
		1|3)
			echo "# Performance: ignore redirect-gateway (split tunnel); buffers; mssfix
pull-filter ignore \"redirect-gateway\"
sndbuf 0
rcvbuf 0
mssfix 1400"
			;;
		4)
			echo "pull-filter ignore \"redirect-gateway\""
			;;
		esac
		echo "# PERF_CLIENT_END"
	} >>/etc/openvpn/client-template.txt

	if [[ -n $MTU ]]; then
		echo "tun-mtu $MTU" >>/etc/openvpn/client-template.txt
	fi

	# Generate the custom client.ovpn
	if [[ $NEW_CLIENT == "n" ]]; then
		if [[ $AUTH_MODE == "fingerprint" ]]; then
			log_info "No clients added. OpenVPN will not start until you add at least one client."
		else
			log_info "No clients added. To add clients, simply run the script again."
		fi
	else
		# 默认安装为首个客户端生成随机密码（未指定时），安装完成后显示
		if [[ $PASS == "2" ]] && [[ -z "${PASSPHRASE:-}" ]]; then
			PASSPHRASE=$(openssl rand -hex 12)
			INSTALL_GENERATED_PASSPHRASE=1
		fi
		log_info "正在生成首个客户端证书..."
		newClient
		# In fingerprint mode, start service now that we have at least one fingerprint
		if [[ $AUTH_MODE == "fingerprint" ]]; then
			run_cmd "Starting OpenVPN service" systemctl restart "$(getOpenVPNServiceUnit)"
		fi
		log_success "如需添加更多客户端，请再次运行本脚本。"
		if [[ -n "${INSTALL_GENERATED_PASSPHRASE:-}" ]] && [[ $PASS == "2" ]] && [[ -n "${PASSPHRASE:-}" ]]; then
			if [[ $OUTPUT_FORMAT != "json" ]]; then
				echo ""
				echo -e "${COLOR_BOLD}${COLOR_GREEN}----------------------------------------${COLOR_RESET}"
				echo -e "${COLOR_BOLD}  首个客户端私钥密码（请妥善保存）${COLOR_RESET}"
				echo -e "${COLOR_BOLD}${COLOR_GREEN}----------------------------------------${COLOR_RESET}"
				echo ""
				echo -e "  客户端名称: ${COLOR_BOLD}$CLIENT${COLOR_RESET}"
				echo -e "  私钥密码:   ${COLOR_BOLD}${COLOR_GREEN}$PASSPHRASE${COLOR_RESET}"
				echo ""
				echo -e "  ${COLOR_DIM}导入 .ovpn 或连接 VPN 时需输入此密码。${COLOR_RESET}"
				echo ""
			fi
			_log_to_file "首个客户端 $CLIENT 已使用自动生成的私钥密码（已向用户显示）"
		fi
	fi
}

# Helper function to get the home directory for storing client configs
function getHomeDir() {
	local client="$1"
	if [ -d "/home/${client}" ]; then
		echo "/home/${client}"
	elif [ "${SUDO_USER}" ]; then
		if [ "${SUDO_USER}" == "root" ]; then
			echo "/root"
		else
			echo "/home/${SUDO_USER}"
		fi
	else
		echo "/root"
	fi
}

# Helper function to get the owner of a client config file (if client matches a system user)
function getClientOwner() {
	local client="$1"
	# Check if client name corresponds to an existing system user with a home directory
	if id "$client" &>/dev/null && [ -d "/home/${client}" ]; then
		echo "${client}"
	elif [ "${SUDO_USER}" ] && [ "${SUDO_USER}" != "root" ]; then
		echo "${SUDO_USER}"
	fi
}

# Helper function to set proper ownership and permissions on client config file
function setClientConfigPermissions() {
	local filepath="$1"
	local owner="$2"

	if [[ -n "$owner" ]]; then
		local owner_group
		owner_group=$(id -gn "$owner")
		chmod go-rw "$filepath"
		chown "$owner:$owner_group" "$filepath"
	fi
}

# Helper function to write client config file with proper path and permissions
# Usage: writeClientConfig <client_name>
# Uses CLIENT_FILEPATH env var if set, otherwise defaults to home directory
# Side effects: sets GENERATED_CONFIG_PATH global variable with the final path
function writeClientConfig() {
	local client="$1"
	local clientFilePath

	# Determine output file path
	if [[ -n "$CLIENT_FILEPATH" ]]; then
		clientFilePath="$CLIENT_FILEPATH"
		# Ensure parent directory exists for custom paths
		local parentDir
		parentDir=$(dirname "$clientFilePath")
		if [[ ! -d "$parentDir" ]]; then
			run_cmd_fatal "Creating directory $parentDir" mkdir -p "$parentDir"
		fi
	else
		local homeDir
		homeDir=$(getHomeDir "$client")
		clientFilePath="$homeDir/$client.ovpn"
	fi

	# Generate the .ovpn config file
	generateClientConfig "$client" "$clientFilePath"

	# Set proper ownership and permissions if client matches a system user
	local clientOwner
	clientOwner=$(getClientOwner "$client")
	setClientConfigPermissions "$clientFilePath" "$clientOwner"

	# Export path for caller to use
	GENERATED_CONFIG_PATH="$clientFilePath"
}

# Helper function to regenerate the CRL after certificate changes.
# Easy-RSA 3.x: 仅 revoke 会在数据库标记吊销，OpenVPN 需通过 CRL 拦截；必须 gen-crl 并分发到 /etc/openvpn/。
function regenerateCRL() {
	export EASYRSA_CRL_DAYS=$DEFAULT_CRL_VALIDITY_DURATION_DAYS
	run_cmd_fatal "生成新 CRL" ./easyrsa gen-crl
	run_cmd "移除旧 CRL" rm -f /etc/openvpn/crl.pem
	run_cmd_fatal "分发 CRL 到 OpenVPN 目录" cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem
	run_cmd "设置 CRL 权限" chmod 644 /etc/openvpn/crl.pem
}

# Helper function to generate .ovpn client config file
# Usage: generateClientConfig <client_name> <filepath>
function generateClientConfig() {
	local client="$1"
	local filepath="$2"

	# Read auth mode
	local auth_mode="pki"
	if [[ -f /etc/openvpn/easy-rsa/AUTH_MODE_GENERATED ]]; then
		auth_mode=$(cat /etc/openvpn/easy-rsa/AUTH_MODE_GENERATED)
	fi

	# Determine if we use tls-crypt-v2, tls-crypt, or tls-auth
	local tls_sig=""
	if grep -qs "^tls-crypt-v2" /etc/openvpn/server.conf; then
		tls_sig="1"
	elif grep -qs "^tls-crypt" /etc/openvpn/server.conf; then
		tls_sig="2"
	elif grep -qs "^tls-auth" /etc/openvpn/server.conf; then
		tls_sig="3"
	fi

	# Generate the custom client.ovpn
	run_cmd "Creating client config" cp /etc/openvpn/client-template.txt "$filepath"
	{
		if [[ $auth_mode == "pki" ]]; then
			# PKI mode: include CA certificate
			echo "<ca>"
			cat "/etc/openvpn/easy-rsa/pki/ca.crt"
			echo "</ca>"
		else
			# Fingerprint mode: use server fingerprint instead of CA
			local server_fingerprint
			if [[ ! -f /etc/openvpn/server-fingerprint ]]; then
				log_error "Server fingerprint file not found"
				exit 1
			fi
			server_fingerprint=$(cat /etc/openvpn/server-fingerprint)
			if [[ -z $server_fingerprint ]]; then
				log_error "Server fingerprint is empty"
				exit 1
			fi
			echo "peer-fingerprint $server_fingerprint"
		fi

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/easy-rsa/pki/issued/$client.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/easy-rsa/pki/private/$client.key"
		echo "</key>"

		# 高性能客户端（模板含 route-nopull）：在 key 与 tls 块之间追加 route NET NETMASK vpn_gateway
		if grep -q "route-nopull" /etc/openvpn/client-template.txt 2>/dev/null && [[ -f /etc/openvpn/push-routes ]] && [[ -s /etc/openvpn/push-routes ]]; then
			while IFS= read -r line; do
				[[ -n $line ]] && echo "route $line vpn_gateway"
			done </etc/openvpn/push-routes
		fi

		case $tls_sig in
		1)
			# Generate per-client tls-crypt-v2 key in /etc/openvpn/
			# Using /tmp would fail on Ubuntu 25.04+ due to AppArmor restrictions
			tls_crypt_v2_tmpfile=$(mktemp /etc/openvpn/tls-crypt-v2-client.XXXXXX)
			if [[ -z "$tls_crypt_v2_tmpfile" ]] || [[ ! -f "$tls_crypt_v2_tmpfile" ]]; then
				log_error "Failed to create temporary file for tls-crypt-v2 client key"
				exit 1
			fi
			if ! openvpn --tls-crypt-v2 /etc/openvpn/tls-crypt-v2.key \
				--genkey tls-crypt-v2-client "$tls_crypt_v2_tmpfile"; then
				rm -f "$tls_crypt_v2_tmpfile"
				log_error "Failed to generate tls-crypt-v2 client key"
				exit 1
			fi
			echo "<tls-crypt-v2>"
			cat "$tls_crypt_v2_tmpfile"
			echo "</tls-crypt-v2>"
			rm -f "$tls_crypt_v2_tmpfile"
			;;
		2)
			echo "<tls-crypt>"
			cat /etc/openvpn/tls-crypt.key
			echo "</tls-crypt>"
			;;
		3)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$filepath"
}

# Helper function to get the current auth mode
# Returns: "pki" or "fingerprint"
function getAuthMode() {
	if [[ -f /etc/openvpn/easy-rsa/AUTH_MODE_GENERATED ]]; then
		cat /etc/openvpn/easy-rsa/AUTH_MODE_GENERATED
	else
		echo "pki"
	fi
}

# Helper function to get valid client names from server.conf fingerprint block
# In fingerprint mode, clients are tracked via comments in the <peer-fingerprint> block
# Format in server.conf:
#   <peer-fingerprint>
#   # client_name
#   SHA256:fingerprint
#   </peer-fingerprint>
# Returns: newline-separated list of client names
function getClientsFromFingerprints() {
	local server_conf="/etc/openvpn/server.conf"
	if [[ ! -f "$server_conf" ]]; then
		return
	fi
	# Extract client names from comments in peer-fingerprint block
	# Comments are in format "# client_name" on lines before fingerprints
	sed -n '/<peer-fingerprint>/,/<\/peer-fingerprint>/p' "$server_conf" | grep "^# " | sed 's/^# //'
}

# Helper function to check if a client exists in fingerprint mode
# Arguments: client_name
# Returns: 0 if exists, 1 if not
function clientExistsInFingerprints() {
	local client_name="$1"
	getClientsFromFingerprints | grep -qx "$client_name"
}

# Helper function to get certificate expiry info
# Arguments: cert_file_path
# Outputs: expiry_date|days_remaining (pipe-separated)
function getCertExpiry() {
	local cert_file="$1"
	local expiry_date="unknown"
	local days_remaining="null"

	if [[ -f "$cert_file" ]]; then
		local enddate
		enddate=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
		if [[ -n "$enddate" ]]; then
			local expiry_epoch
			expiry_epoch=$(date -d "$enddate" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$enddate" +%s 2>/dev/null)
			if [[ -n "$expiry_epoch" ]]; then
				expiry_date=$(date -d "@$expiry_epoch" +%Y-%m-%d 2>/dev/null || date -r "$expiry_epoch" +%Y-%m-%d 2>/dev/null)
				local now_epoch
				now_epoch=$(date +%s)
				days_remaining=$(((expiry_epoch - now_epoch) / 86400))
			fi
		fi
	fi
	echo "$expiry_date|$days_remaining"
}

# Helper function to remove certificate files for regeneration
# Arguments: name (client or server name)
# Must be called from easy-rsa directory
function removeCertFiles() {
	local name="$1"
	rm -f "pki/issued/$name.crt" "pki/private/$name.key" "pki/reqs/$name.req"
}

# Helper function to extract SHA256 fingerprint from certificate
# Arguments: cert_file_path
# Outputs: fingerprint string or empty on failure
function extractFingerprint() {
	local cert_file="$1"
	openssl x509 -in "$cert_file" -fingerprint -sha256 -noout 2>/dev/null | cut -d'=' -f2
}

# Helper function to list valid clients and select one
# Arguments: show_expiry (optional, "true" to show expiry info)
# Sets global variables:
#   CLIENT - the selected client name
#   CLIENTNUMBER - the selected client number (1-based index)
#   NUMBEROFCLIENTS - total count of valid clients
function selectClient() {
	local show_expiry="${1:-false}"
	local client_number
	local auth_mode
	local clients_list

	auth_mode=$(getAuthMode)

	# Get list of valid clients based on auth mode
	if [[ $auth_mode == "fingerprint" ]]; then
		# Fingerprint mode: get clients from server.conf peer-fingerprint block
		clients_list=$(getClientsFromFingerprints)
		NUMBEROFCLIENTS=$(echo "$clients_list" | grep -c . || echo 0)
	else
		# PKI mode: get valid clients from index.txt
		clients_list=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt 2>/dev/null | grep "^V" | cut -d '=' -f 2)
		NUMBEROFCLIENTS=$(echo "$clients_list" | grep -c . || echo 0)
	fi

	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		log_fatal "当前没有任何客户端！"
	fi

	# If CLIENT is set, validate it exists as a valid client
	if [[ -n $CLIENT ]]; then
		if echo "$clients_list" | grep -qx "$CLIENT"; then
			return
		else
			log_fatal "未找到或无效的客户端: '$CLIENT'"
		fi
	fi

	# Display client list
	if [[ $show_expiry == "true" ]]; then
		local i=1
		while read -r client; do
			local client_cert="/etc/openvpn/easy-rsa/pki/issued/$client.crt"
			local days
			days=$(getDaysUntilExpiry "$client_cert")
			local expiry
			expiry=$(formatExpiry "$days")
			echo "     $i) $client $expiry"
			((i++))
		done <<<"$clients_list"
	else
		echo "$clients_list" | nl -s ') '
	fi

	# Prompt for selection
	until [[ ${CLIENTNUMBER:-$client_number} -ge 1 && ${CLIENTNUMBER:-$client_number} -le $NUMBEROFCLIENTS ]]; do
		if [[ $NUMBEROFCLIENTS == '1' ]]; then
			read -rp "请选择客户端 [1]: " client_number
		else
			read -rp "请选择客户端 [1-$NUMBEROFCLIENTS]: " client_number
		fi
	done
	CLIENTNUMBER="${CLIENTNUMBER:-$client_number}"
	CLIENT=$(echo "$clients_list" | sed -n "${CLIENTNUMBER}p")
}

# Escape a string for JSON output
function json_escape() {
	local str="$1"
	# Escape backslashes first, then quotes, then control characters
	str="${str//\\/\\\\}"
	str="${str//\"/\\\"}"
	str="${str//$'\n'/\\n}"
	str="${str//$'\r'/\\r}"
	str="${str//$'\t'/\\t}"
	printf '%s' "$str"
}

function listClients() {
	local index_file="/etc/openvpn/easy-rsa/pki/index.txt"
	local cert_dir="/etc/openvpn/easy-rsa/pki/issued"
	local number_of_clients
	local format="${OUTPUT_FORMAT:-table}"
	local auth_mode

	auth_mode=$(getAuthMode)

	# Collect client data based on auth mode
	local clients_data=()

	if [[ $auth_mode == "fingerprint" ]]; then
		# Fingerprint mode: get clients from certificates in pki/issued/
		# Valid clients have their fingerprint in server.conf, revoked ones don't
		local valid_clients
		valid_clients=$(getClientsFromFingerprints)

		# Get all client certificates (exclude server certs)
		local all_clients=()
		for cert_file in "$cert_dir"/*.crt; do
			[[ ! -f "$cert_file" ]] && continue
			local client_name
			client_name=$(basename "$cert_file" .crt)
			# Skip server certificates and backup files
			[[ "$client_name" == server_* ]] && continue
			[[ "$client_name" == *.bak ]] && continue
			all_clients+=("$client_name")
		done

		number_of_clients=${#all_clients[@]}

		if [[ $number_of_clients == '0' ]]; then
			if [[ $format == "json" ]]; then
				echo '{"clients":[]}'
			else
				log_warn "当前没有任何客户端证书！"
			fi
			return
		fi

		for client_name in "${all_clients[@]}"; do
			[[ -z "$client_name" ]] && continue
			local status_text
			# Check if client is in the valid fingerprints list
			if echo "$valid_clients" | grep -qx "$client_name"; then
				status_text="valid"
			else
				status_text="revoked"
			fi
			local expiry_info
			expiry_info=$(getCertExpiry "$cert_dir/$client_name.crt")
			clients_data+=("$client_name|$status_text|$expiry_info")
		done
	else
		# PKI mode: get clients from index.txt
		# Exclude server certificates (CN starting with server_)
		number_of_clients=$(tail -n +2 "$index_file" 2>/dev/null | grep "^[VR]" | grep -cv "/CN=server_" || echo 0)

		if [[ $number_of_clients == '0' ]]; then
			if [[ $format == "json" ]]; then
				echo '{"clients":[]}'
			else
				log_warn "当前没有任何客户端证书！"
			fi
			return
		fi

		while read -r line; do
			local status="${line:0:1}"
			local client_name
			client_name=$(echo "$line" | sed 's/.*\/CN=//')

			local status_text
			if [[ "$status" == "V" ]]; then
				status_text="valid"
			elif [[ "$status" == "R" ]]; then
				status_text="revoked"
			else
				status_text="unknown"
			fi

			local expiry_info
			expiry_info=$(getCertExpiry "$cert_dir/$client_name.crt")
			clients_data+=("$client_name|$status_text|$expiry_info")
		done < <(tail -n +2 "$index_file" | grep "^[VR]" | grep -v "/CN=server_" | sort -t$'\t' -k2)
	fi

	if [[ $format == "json" ]]; then
		# Output JSON
		echo '{"clients":['
		local first=true
		for client_entry in "${clients_data[@]}"; do
			IFS='|' read -r name status expiry days <<<"$client_entry"
			[[ $first == true ]] && first=false || printf ','
			# Handle null for days_remaining (no quotes for JSON null)
			local days_json
			if [[ "$days" == "null" || -z "$days" ]]; then
				days_json="null"
			else
				days_json="$days"
			fi
			printf '{"name":"%s","status":"%s","expiry":"%s","days_remaining":%s}\n' \
				"$(json_escape "$name")" "$(json_escape "$status")" "$(json_escape "$expiry")" "$days_json"
		done
		echo ']}'
	else
		# Output table
		log_header "客户端证书"
		log_info "共 $number_of_clients 个客户端证书"
		log_menu ""
		printf "   %-25s %-10s %-12s %s\n" "名称" "状态" "到期日" "剩余"
		printf "   %-25s %-10s %-12s %s\n" "----" "------" "------" "---------"

		for client_entry in "${clients_data[@]}"; do
			IFS='|' read -r name status expiry days <<<"$client_entry"
			local relative
			if [[ $days == "null" ]]; then
				relative="未知"
			elif [[ $days -lt 0 ]]; then
				relative="$((-days)) 天前"
			elif [[ $days -eq 0 ]]; then
				relative="今天"
			elif [[ $days -eq 1 ]]; then
				relative="1 天"
			else
				relative="$days 天"
			fi
			# Capitalize status for table display
			local status_display="${status^}"
			printf "   %-25s %-10s %-12s %s\n" "$name" "$status_display" "$expiry" "$relative"
		done
		log_menu ""
	fi
}

function formatBytes() {
	local bytes=$1
	# Validate input is numeric
	if ! [[ "$bytes" =~ ^[0-9]+$ ]]; then
		echo "N/A"
		return
	fi
	if [[ $bytes -ge 1073741824 ]]; then
		awk "BEGIN {printf \"%.1fG\", $bytes/1073741824}"
	elif [[ $bytes -ge 1048576 ]]; then
		awk "BEGIN {printf \"%.1fM\", $bytes/1048576}"
	elif [[ $bytes -ge 1024 ]]; then
		awk "BEGIN {printf \"%.1fK\", $bytes/1024}"
	else
		echo "${bytes}B"
	fi
}

function listConnectedClients() {
	local status_file="/var/log/openvpn/status.log"
	local format="${OUTPUT_FORMAT:-table}"

	if [[ ! -f "$status_file" ]]; then
		if [[ $format == "json" ]]; then
			echo '{"error":"Status file not found","clients":[]}'
		else
			log_warn "未找到状态文件: $status_file"
			log_info "请确认 OpenVPN 服务已运行。"
		fi
		return
	fi

	local client_count
	client_count=$(grep -c "^CLIENT_LIST" "$status_file" 2>/dev/null) || client_count=0

	if [[ "$client_count" -eq 0 ]]; then
		if [[ $format == "json" ]]; then
			echo '{"clients":[]}'
		else
			log_header "已连接客户端"
			log_info "当前没有客户端连接。"
			log_info "说明：数据每 60 秒刷新一次。"
		fi
		return
	fi

	# Collect client data
	local clients_data=()
	while IFS=',' read -r _ name real_addr vpn_ip _ bytes_recv bytes_sent connected_since _; do
		clients_data+=("$name|$real_addr|$vpn_ip|$bytes_recv|$bytes_sent|$connected_since")
	done < <(grep "^CLIENT_LIST" "$status_file")

	if [[ $format == "json" ]]; then
		echo '{"clients":['
		local first=true
		for client_entry in "${clients_data[@]}"; do
			IFS='|' read -r name real_addr vpn_ip bytes_recv bytes_sent connected_since <<<"$client_entry"
			[[ $first == true ]] && first=false || printf ','
			printf '{"name":"%s","real_address":"%s","vpn_ip":"%s","bytes_received":%s,"bytes_sent":%s,"connected_since":"%s"}\n' \
				"$(json_escape "$name")" "$(json_escape "$real_addr")" "$(json_escape "$vpn_ip")" \
				"${bytes_recv:-0}" "${bytes_sent:-0}" "$(json_escape "$connected_since")"
		done
		echo ']}'
	else
		log_header "已连接客户端"
		log_info "当前共 $client_count 个客户端连接"
		log_menu ""
		printf "   %-20s %-22s %-16s %-20s %s\n" "名称" "真实地址" "VPN IP" "连接时间" "流量"
		printf "   %-20s %-22s %-16s %-20s %s\n" "----" "------------" "------" "---------------" "--------"

		for client_entry in "${clients_data[@]}"; do
			IFS='|' read -r name real_addr vpn_ip bytes_recv bytes_sent connected_since <<<"$client_entry"
			local recv_human sent_human
			recv_human=$(formatBytes "$bytes_recv")
			sent_human=$(formatBytes "$bytes_sent")
			local transfer="↓${recv_human} ↑${sent_human}"
			printf "   %-20s %-22s %-16s %-20s %s\n" "$name" "$real_addr" "$vpn_ip" "$connected_since" "$transfer"
		done
		log_menu ""
		log_info "说明：数据每 60 秒刷新一次。"
	fi
}

function newClient() {
	log_header "添加新客户端"

	# Only prompt for client name if not already set or invalid
	if ! is_valid_client_name "$CLIENT"; then
		log_prompt "请输入客户端名称。"
		log_prompt "名称只能包含字母、数字、下划线或短横线（最多 $MAX_CLIENT_NAME_LENGTH 个字符）。"
		until is_valid_client_name "$CLIENT"; do
			read -rp "客户端名称: " -e CLIENT
		done
	fi

	# Only prompt for cert duration if not already set
	if [[ -z $CLIENT_CERT_DURATION_DAYS ]] || ! [[ $CLIENT_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] || [[ $CLIENT_CERT_DURATION_DAYS -lt 1 ]]; then
		log_menu ""
		log_prompt "客户端证书有效期为多少天？"
		until [[ $CLIENT_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] && [[ $CLIENT_CERT_DURATION_DAYS -ge 1 ]]; do
			read -rp "证书有效期（天）: " -e -i $DEFAULT_CERT_VALIDITY_DURATION_DAYS CLIENT_CERT_DURATION_DAYS
		done
	fi

	# Only prompt for password if not already set
	if ! [[ $PASS =~ ^[1-2]$ ]]; then
		log_menu ""
		log_prompt "是否为该客户端设置私钥密码？"
		log_prompt "（设置后，导入 .ovpn 或连接 VPN 时需输入此密码）"
		log_menu "   1) 不设置密码"
		log_menu "   2) 设置密码"
		until [[ $PASS =~ ^[1-2]$ ]]; do
			read -rp "请选择 [1-2]: " -e -i 1 PASS
		done
	fi

	# When user chose to set password, prompt for it here if not already provided (e.g. via --password)
	if [[ $PASS == "2" ]] && [[ -z "$PASSPHRASE" ]]; then
		log_prompt "请输入客户端私钥密码（输入时不显示）："
		read -rs PASSPHRASE
		echo ""
		if [[ -z "$PASSPHRASE" ]]; then
			log_warn "未输入密码，稍后将由 easyrsa 提示输入。"
		else
			log_prompt "请再次输入密码以确认："
			read -rs PASSPHRASE_CONFIRM
			echo ""
			if [[ "$PASSPHRASE" != "$PASSPHRASE_CONFIRM" ]]; then
				log_fatal "两次输入的密码不一致，请重新添加客户端。"
			fi
		fi
	fi

	cd /etc/openvpn/easy-rsa/ || return

	# Read auth mode
	if [[ -f AUTH_MODE_GENERATED ]]; then
		AUTH_MODE=$(cat AUTH_MODE_GENERATED)
	else
		AUTH_MODE="pki"
	fi

	# Check if client already exists
	local CLIENTEXISTS=0
	if [[ $AUTH_MODE == "fingerprint" ]]; then
		# Fingerprint mode: check server.conf peer-fingerprint block
		if clientExistsInFingerprints "$CLIENT"; then
			CLIENTEXISTS=1
		fi
	else
		# PKI mode: check index.txt
		if [[ -f pki/index.txt ]]; then
			CLIENTEXISTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -E "^V" | grep -c -E "/CN=$CLIENT\$")
		fi
	fi

	if [[ $CLIENTEXISTS != '0' ]]; then
		log_error "该客户端名称已存在，请换一个名称。"
		exit 1
	fi

	# In fingerprint mode, clean up any revoked cert files so we can reuse the name
	if [[ $AUTH_MODE == "fingerprint" ]] && [[ -f "pki/issued/$CLIENT.crt" ]]; then
		log_info "Removing old revoked certificate files for $CLIENT..."
		removeCertFiles "$CLIENT"
	fi

	log_info "正在生成客户端证书..."
	export EASYRSA_CERT_EXPIRE=$CLIENT_CERT_DURATION_DAYS

	# Determine easyrsa command based on auth mode
	local easyrsa_cmd cert_desc
	if [[ $AUTH_MODE == "pki" ]]; then
		easyrsa_cmd="build-client-full"
		cert_desc="client certificate"
	else
		easyrsa_cmd="self-sign-client"
		cert_desc="self-signed client certificate"
	fi

	case $PASS in
	1)
		run_cmd_fatal "Building $cert_desc" ./easyrsa --batch "$easyrsa_cmd" "$CLIENT" nopass
		;;
	2)
		if [[ -z "$PASSPHRASE" ]]; then
			log_warn "请在下方输入客户端私钥密码（easyrsa 将提示两次）"
			if ! ./easyrsa --batch "$easyrsa_cmd" "$CLIENT"; then
				log_fatal "生成 $cert_desc 失败"
			fi
		else
			log_info "使用已提供的密码加密客户端私钥"
			export EASYRSA_PASSPHRASE="$PASSPHRASE"
			run_cmd_fatal "Building $cert_desc" ./easyrsa --batch --passin=env:EASYRSA_PASSPHRASE --passout=env:EASYRSA_PASSPHRASE "$easyrsa_cmd" "$CLIENT"
			unset EASYRSA_PASSPHRASE
		fi
		;;
	esac

	# Fingerprint mode: register client fingerprint with server
	if [[ $AUTH_MODE == "fingerprint" ]]; then
		CLIENT_FINGERPRINT=$(openssl x509 -in "pki/issued/$CLIENT.crt" -fingerprint -sha256 -noout | cut -d'=' -f2)
		if [[ -z $CLIENT_FINGERPRINT ]]; then
			log_error "Failed to extract client certificate fingerprint"
			exit 1
		fi
		log_info "Client fingerprint: $CLIENT_FINGERPRINT"

		# Add fingerprint to server.conf's <peer-fingerprint> block
		# Create the block if this is the first client
		if ! grep -q '<peer-fingerprint>' /etc/openvpn/server.conf; then
			echo "# Client fingerprints are listed below
<peer-fingerprint>
# $CLIENT
$CLIENT_FINGERPRINT
</peer-fingerprint>" >>/etc/openvpn/server.conf
		else
			# Insert comment and fingerprint before closing tag
			sed -i "/<\/peer-fingerprint>/i # $CLIENT\n$CLIENT_FINGERPRINT" /etc/openvpn/server.conf
		fi

		# Reload OpenVPN to pick up new fingerprint
		log_info "Reloading OpenVPN to apply new fingerprint..."
		if systemctl is-active --quiet "$(getOpenVPNServiceUnit)"; then
			systemctl reload "$(getOpenVPNServiceUnit)" 2>/dev/null || systemctl restart "$(getOpenVPNServiceUnit)"
		fi
	fi

	log_success "客户端 $CLIENT 已添加，证书有效期为 $CLIENT_CERT_DURATION_DAYS 天。"

	# Write the .ovpn config file with proper path and permissions
	writeClientConfig "$CLIENT"

	log_info "请下载 .ovpn 文件并导入到 OpenVPN 客户端；若设置了密码，连接时需输入。"
	log_menu ""
	log_success "配置文件已写入: $GENERATED_CONFIG_PATH"
}

function revokeClient() {
	log_header "吊销客户端"
	log_prompt "请选择要吊销的客户端证书"
	selectClient

	cd /etc/openvpn/easy-rsa/ || return

	# Read auth mode
	local auth_mode="pki"
	if [[ -f AUTH_MODE_GENERATED ]]; then
		auth_mode=$(cat AUTH_MODE_GENERATED)
	fi

	log_info "正在吊销客户端 $CLIENT 的证书..."

	if [[ $auth_mode == "pki" ]]; then
		# PKI mode: Easy-RSA 3.x 使用 revoke（无需 revoke-issued），吊销后必须更新并分发 CRL
		run_cmd_fatal "吊销证书" ./easyrsa --batch revoke "$CLIENT"
		regenerateCRL
		run_cmd "备份 index" cp /etc/openvpn/easy-rsa/pki/index.txt{,.bk}
	else
		# Fingerprint mode: remove fingerprint from server.conf
		# Keep cert files so revoked clients appear in client list
		log_info "正在从服务器配置中移除该客户端指纹..."

		# Remove comment line and fingerprint line below it from server.conf
		sed -i "/^# $CLIENT\$/{N;d;}" /etc/openvpn/server.conf

		# Reload OpenVPN to apply fingerprint removal
		log_info "正在重载 OpenVPN 以应用指纹移除..."
		if systemctl is-active --quiet "$(getOpenVPNServiceUnit)"; then
			systemctl reload "$(getOpenVPNServiceUnit)" 2>/dev/null || systemctl restart "$(getOpenVPNServiceUnit)"
		fi
	fi

	run_cmd "从 /home 删除客户端配置" find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	run_cmd "从 /root 删除客户端配置" rm -f "/root/$CLIENT.ovpn"
	run_cmd "删除 IP 分配" sed -i "/^$CLIENT,.*/d" /etc/openvpn/ipp.txt

	# Disconnect the client if currently connected
	disconnectClient "$CLIENT"

	log_success "客户端 $CLIENT 的证书已吊销。"
}

# Disconnect a client via the management interface; if socket unavailable, restart OpenVPN to drop all and reload CRL
function disconnectClient() {
	local client_name="$1"
	local mgmt_socket="/var/run/openvpn-server/server.sock"

	if [[ -S "$mgmt_socket" ]]; then
		log_info "正在断开客户端 $client_name..."
		if echo "kill $client_name" | socat - UNIX-CONNECT:"$mgmt_socket" >/dev/null 2>&1; then
			log_success "客户端 $client_name 已断开。"
		else
			log_warn "无法通过管理接口断开（可能未连接）。"
		fi
		return 0
	fi

	# 未找到管理套接字时：重启 OpenVPN 可立即断开所有连接并加载新 CRL，吊销的客户端将无法重连
	if systemctl is-active --quiet "$(getOpenVPNServiceUnit)" 2>/dev/null; then
		log_warn "未找到管理套接字，改为重启 OpenVPN 服务以应用 CRL 并断开所有连接。"
		run_cmd "重启 OpenVPN 以应用 CRL" systemctl restart "$(getOpenVPNServiceUnit)"
		log_success "OpenVPN 已重启，已断开所有客户端；被吊销的证书将无法再连接。"
	else
		log_warn "未找到管理套接字且 OpenVPN 服务未运行。下次启动后将使用新 CRL。"
	fi
}

function renewClient() {
	local client_cert_duration_days
	local auth_mode

	log_header "续期客户端证书"
	log_prompt "请选择要续期的客户端证书"
	selectClient "true"

	# Allow user to specify renewal duration (use CLIENT_CERT_DURATION_DAYS env var for headless mode)
	if [[ -z $CLIENT_CERT_DURATION_DAYS ]] || ! [[ $CLIENT_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] || [[ $CLIENT_CERT_DURATION_DAYS -lt 1 ]]; then
		log_menu ""
		log_prompt "续期后的证书有效期为多少天？"
		until [[ $client_cert_duration_days =~ ^[0-9]+$ ]] && [[ $client_cert_duration_days -ge 1 ]]; do
			read -rp "证书有效期（天）: " -e -i $DEFAULT_CERT_VALIDITY_DURATION_DAYS client_cert_duration_days
		done
	else
		client_cert_duration_days=$CLIENT_CERT_DURATION_DAYS
	fi

	cd /etc/openvpn/easy-rsa/ || return
	auth_mode=$(getAuthMode)
	log_info "正在续期客户端 $CLIENT 的证书..."

	# Backup the old certificate before renewal
		run_cmd "备份旧证书" cp "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt" "/etc/openvpn/easy-rsa/pki/issued/$CLIENT.crt.bak"

	export EASYRSA_CERT_EXPIRE=$client_cert_duration_days

	if [[ $auth_mode == "fingerprint" ]]; then
		# Fingerprint mode: delete old cert, generate new self-signed, update fingerprint
		removeCertFiles "$CLIENT"
		run_cmd_fatal "生成新证书" ./easyrsa --batch self-sign-client "$CLIENT" nopass

		local new_fingerprint
		new_fingerprint=$(extractFingerprint "pki/issued/$CLIENT.crt")
		if [[ -z "$new_fingerprint" ]]; then
			log_fatal "无法提取新证书指纹"
		fi
		log_info "新指纹: $new_fingerprint"

		# Update fingerprint in server.conf (comment line followed by fingerprint)
		if grep -q "^# $CLIENT\$" /etc/openvpn/server.conf; then
			sed -i "/^# $CLIENT\$/{n;s/.*/$new_fingerprint/}" /etc/openvpn/server.conf
		else
			log_fatal "在 server.conf 中未找到该客户端指纹条目"
		fi

		# Reload OpenVPN to apply new fingerprint
		if systemctl is-active --quiet "$(getOpenVPNServiceUnit)"; then
			systemctl reload "$(getOpenVPNServiceUnit)" 2>/dev/null || systemctl restart "$(getOpenVPNServiceUnit)"
		fi
	else
		# PKI mode: use easyrsa renew
		run_cmd_fatal "续期证书" ./easyrsa --batch renew "$CLIENT"

		# Revoke the old certificate
		run_cmd_fatal "吊销旧证书" ./easyrsa --batch revoke-renewed "$CLIENT"

		# Regenerate the CRL
		regenerateCRL
	fi

	# Write the .ovpn config file with proper path and permissions
	writeClientConfig "$CLIENT"

	log_menu ""
	log_success "客户端 $CLIENT 的证书已续期，有效期为 $client_cert_duration_days 天。"
	log_info "新配置文件已写入 $GENERATED_CONFIG_PATH。"
	log_info "请下载新的 .ovpn 文件并导入到 OpenVPN 客户端。"
}

function renewServer() {
	local server_name server_cert_duration_days auth_mode

	log_header "续期服务器证书"

	# Determine auth mode
	auth_mode=$(getAuthMode)

	# Get the server name from the config (extract basename since path may be relative)
	server_name=$(basename "$(grep '^cert ' /etc/openvpn/server.conf | cut -d ' ' -f 2)" .crt)
	if [[ -z "$server_name" ]]; then
		log_fatal "无法从 /etc/openvpn/server.conf 获取服务器证书名称"
	fi

	log_prompt "将续期服务器证书: $server_name"
	log_warn "续期后将重启 OpenVPN 服务。"
	if [[ "$auth_mode" == "fingerprint" ]]; then
		log_warn "所有客户端配置将使用新服务器指纹重新生成。"
	fi
	if [[ -z $CONTINUE ]]; then
		read -rp "是否继续？[y/n]: " -e -i n CONTINUE
	fi
	if [[ $CONTINUE != "y" ]]; then
		log_info "已取消续期。"
		return
	fi

	# Allow user to specify renewal duration (use SERVER_CERT_DURATION_DAYS env var for headless mode)
	if [[ -z $SERVER_CERT_DURATION_DAYS ]] || ! [[ $SERVER_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] || [[ $SERVER_CERT_DURATION_DAYS -lt 1 ]]; then
		log_menu ""
		log_prompt "续期后的证书有效期为多少天？"
		until [[ $server_cert_duration_days =~ ^[0-9]+$ ]] && [[ $server_cert_duration_days -ge 1 ]]; do
			read -rp "证书有效期（天）: " -e -i $DEFAULT_CERT_VALIDITY_DURATION_DAYS server_cert_duration_days
		done
	else
		server_cert_duration_days=$SERVER_CERT_DURATION_DAYS
	fi

	cd /etc/openvpn/easy-rsa/ || return
	log_info "正在续期服务器证书..."

	export EASYRSA_CERT_EXPIRE=$server_cert_duration_days

	if [[ "$auth_mode" == "fingerprint" ]]; then
		# Fingerprint mode: delete old cert, generate new self-signed, update fingerprint
		run_cmd "备份旧证书" cp "pki/issued/$server_name.crt" "pki/issued/$server_name.crt.bak"
		removeCertFiles "$server_name"
		run_cmd_fatal "生成新服务器证书" ./easyrsa --batch self-sign-server "$server_name" nopass

		local new_fingerprint
		new_fingerprint=$(extractFingerprint "pki/issued/$server_name.crt")
		if [[ -z "$new_fingerprint" ]]; then
			log_fatal "无法提取新服务器证书指纹"
		fi
		echo "$new_fingerprint" >/etc/openvpn/server-fingerprint
		log_info "新服务器指纹: $new_fingerprint"

		# Copy new cert and key, then regenerate client configs (they embed server fingerprint)
		cp "pki/issued/$server_name.crt" "pki/private/$server_name.key" /etc/openvpn/
		local client
		for client in $(getClientsFromFingerprints); do
			[[ -f "pki/issued/$client.crt" ]] && CLIENT="$client" writeClientConfig "$client"
		done
	else
		# PKI mode: use standard easyrsa renew

		# Backup the old certificate before renewal
		run_cmd "Backing up old certificate" cp "/etc/openvpn/easy-rsa/pki/issued/$server_name.crt" "/etc/openvpn/easy-rsa/pki/issued/$server_name.crt.bak"

		# Renew the certificate (keeps the same private key)
		export EASYRSA_CERT_EXPIRE=$server_cert_duration_days
		run_cmd_fatal "Renewing certificate" ./easyrsa --batch renew "$server_name"

		# Revoke the old certificate
		run_cmd_fatal "Revoking old certificate" ./easyrsa --batch revoke-renewed "$server_name"

		# Regenerate the CRL
		regenerateCRL

		# Copy the new certificate to /etc/openvpn/
		run_cmd_fatal "Copying new certificate" cp "/etc/openvpn/easy-rsa/pki/issued/$server_name.crt" /etc/openvpn/
	fi

	# Restart OpenVPN
	log_info "Restarting OpenVPN service..."
	run_cmd "Restarting OpenVPN" systemctl restart "$(getOpenVPNServiceUnit)"

	log_success "Server certificate renewed successfully and is valid for $server_cert_duration_days days."
}

function getDaysUntilExpiry() {
	local cert_file="$1"
	if [[ -f "$cert_file" ]]; then
		local expiry_date
		expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
		local expiry_epoch
		expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s 2>/dev/null)
		if [[ -z "$expiry_epoch" ]]; then
			echo "?"
			return
		fi
		local now_epoch
		now_epoch=$(date +%s)
		echo $(((expiry_epoch - now_epoch) / 86400))
	else
		echo "?"
	fi
}

function formatExpiry() {
	local days="$1"
	if [[ "$days" == "?" ]]; then
		echo "(unknown expiry)"
	elif [[ $days -lt 0 ]]; then
		echo "(EXPIRED $((-days)) days ago)"
	elif [[ $days -eq 0 ]]; then
		echo "(expires today)"
	elif [[ $days -eq 1 ]]; then
		echo "(expires in 1 day)"
	else
		echo "(expires in $days days)"
	fi
}

function renewMenu() {
	local server_name server_cert server_days server_expiry renew_option

	log_header "Certificate Renewal"

	# Get server certificate expiry for menu display (extract basename since path may be relative)
	server_name=$(basename "$(grep '^cert ' /etc/openvpn/server.conf | cut -d ' ' -f 2)" .crt)
	if [[ -z "$server_name" ]]; then
		server_expiry="(unknown expiry)"
	else
		server_cert="/etc/openvpn/easy-rsa/pki/issued/$server_name.crt"
		server_days=$(getDaysUntilExpiry "$server_cert")
		server_expiry=$(formatExpiry "$server_days")
	fi

	log_menu ""
	log_prompt "What do you want to renew?"
	log_menu "   1) Renew a client certificate"
	log_menu "   2) Renew the server certificate $server_expiry"
	log_menu "   3) Back to main menu"
	until [[ ${RENEW_OPTION:-$renew_option} =~ ^[1-3]$ ]]; do
		read -rp "Select an option [1-3]: " renew_option
	done
	renew_option="${RENEW_OPTION:-$renew_option}"

	case $renew_option in
	1)
		renewClient
		;;
	2)
		renewServer
		;;
	3)
		manageMenu
		;;
	esac
}

function removeUnbound() {
	run_cmd "Removing OpenVPN Unbound config" rm -f /etc/unbound/unbound.conf.d/openvpn.conf

	# Clean up include directive if conf.d directory is now empty
	if [[ -d /etc/unbound/unbound.conf.d ]] && [[ -z "$(ls -A /etc/unbound/unbound.conf.d)" ]]; then
		run_cmd "Cleaning up Unbound include directive" \
			sed -i '/^include: "\/etc\/unbound\/unbound\.conf\.d\/\*\.conf"$/d' /etc/unbound/unbound.conf
	fi

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		log_info "If you were already using Unbound before installing OpenVPN, I removed the configuration related to OpenVPN."
		read -rp "Do you want to completely remove Unbound? [y/n]: " -e REMOVE_UNBOUND
	done

	if [[ $REMOVE_UNBOUND == 'y' ]]; then
		log_info "Removing Unbound..."
		run_cmd "Stopping Unbound" systemctl stop unbound

		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd "Removing Unbound" apt-get remove --purge -y unbound
		elif [[ $OS == 'arch' ]]; then
			run_cmd "Removing Unbound" pacman --noconfirm -R unbound
		elif [[ $OS =~ (centos|oracle) ]]; then
			run_cmd "Removing Unbound" yum remove -y unbound
		elif [[ $OS =~ (fedora|amzn2023) ]]; then
			run_cmd "Removing Unbound" dnf remove -y unbound
		elif [[ $OS == 'opensuse' ]]; then
			run_cmd "Removing Unbound" zypper remove -y unbound
		fi

		run_cmd "Removing Unbound config" rm -rf /etc/unbound/
		log_success "Unbound removed!"
	else
		run_cmd "Restarting Unbound" systemctl restart unbound
		log_info "Unbound wasn't removed."
	fi
}

function removeOpenVPN() {
	log_header "卸载 OpenVPN"
	if [[ -d /etc/openvpn ]] && [[ -f /etc/openvpn/server.conf ]]; then
		log_prompt "卸载前可先备份配置，便于日后恢复。是否先备份配置？[y/n]: "
		read -rp "" -e -i n do_backup
		if [[ ${do_backup,,} == "y" ]]; then
			backupOpenVPNConfig
		fi
	fi
	if [[ -z $REMOVE ]]; then
		read -rp "确定要卸载 OpenVPN？[y/n]: " -e -i n REMOVE
	fi
	if [[ $REMOVE == 'y' ]]; then
		# Get OpenVPN configuration
		PORT=$(grep '^port ' /etc/openvpn/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server.conf | cut -d " " -f 2)
		# Strip "6" suffix for firewall/SELinux commands (they expect "udp"/"tcp", not "udp6"/"tcp6")
		PROTOCOL_BASE="${PROTOCOL%6}"
		# Extract IPv4 subnet (may be empty if IPv4 not enabled)
		VPN_SUBNET_IPV4=$(grep '^server ' /etc/openvpn/server.conf | cut -d " " -f 2)
		# Extract IPv6 subnet (may be empty if IPv6 not enabled)
		VPN_SUBNET_IPV6=$(grep '^server-ipv6 ' /etc/openvpn/server.conf | cut -d " " -f 2 | sed 's|/.*||')

		# Stop OpenVPN
		log_info "正在停止 OpenVPN 服务..."
		run_cmd "禁用 OpenVPN 服务" systemctl disable "$(getOpenVPNServiceUnit)"
		run_cmd "停止 OpenVPN 服务" systemctl stop "$(getOpenVPNServiceUnit)"
		# 仅删除本脚本复制的 unit（openvpn-server@.service）；openvpn@.service 为系统包提供，不删除
		if [[ $(getOpenVPNServiceUnit) == "openvpn-server@server" ]] && [[ -f /etc/systemd/system/openvpn-server@.service ]]; then
			run_cmd "删除服务文件" rm -f /etc/systemd/system/openvpn-server@.service
		fi

		# Remove firewall rules
		log_info "正在移除防火墙规则..."
		if systemctl is-active --quiet firewalld && firewall-cmd --list-ports | grep -q "$PORT/$PROTOCOL_BASE"; then
			# firewalld was used
			run_cmd "从 firewalld 移除 OpenVPN 端口" firewall-cmd --permanent --remove-port="$PORT/$PROTOCOL_BASE"
			run_cmd "从 firewalld 移除 masquerade" firewall-cmd --permanent --remove-masquerade
			# Remove IPv4 rich rule if configured
			if [[ -n $VPN_SUBNET_IPV4 ]]; then
				firewall-cmd --permanent --remove-rich-rule="rule family=\"ipv4\" source address=\"$VPN_SUBNET_IPV4/24\" accept" 2>/dev/null || true
			fi
			# Remove IPv6 rich rule if configured
			if [[ -n $VPN_SUBNET_IPV6 ]]; then
				firewall-cmd --permanent --remove-rich-rule="rule family=\"ipv6\" source address=\"${VPN_SUBNET_IPV6}/112\" accept" 2>/dev/null || true
			fi
			run_cmd "重载 firewalld" firewall-cmd --reload
		elif [[ -f /etc/nftables/openvpn.nft ]]; then
			# nftables was used
			# Delete tables (suppress errors in case tables don't exist)
			nft delete table inet openvpn 2>/dev/null || true
			nft delete table ip openvpn-nat 2>/dev/null || true
			nft delete table ip6 openvpn-nat 2>/dev/null || true
			run_cmd "从 nftables.conf 移除 include" sed -i '/include.*openvpn\.nft/d' /etc/nftables.conf
			run_cmd "删除 nftables 规则文件" rm -f /etc/nftables/openvpn.nft
		elif [[ -f /etc/systemd/system/iptables-openvpn.service ]]; then
			# iptables was used
			run_cmd "停止 iptables 服务" systemctl stop iptables-openvpn
			run_cmd "禁用 iptables 服务" systemctl disable iptables-openvpn
			run_cmd "删除 iptables 服务文件" rm /etc/systemd/system/iptables-openvpn.service
			run_cmd "重载 systemd" systemctl daemon-reload
			run_cmd "删除 iptables 添加脚本" rm -f /etc/iptables/add-openvpn-rules.sh
			run_cmd "删除 iptables 删除脚本" rm -f /etc/iptables/rm-openvpn-rules.sh
		fi

		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					run_cmd "移除 SELinux 端口" semanage port -d -t openvpn_port_t -p "$PROTOCOL_BASE" "$PORT"
				fi
			fi
		fi

		log_info "正在卸载 OpenVPN 软件包..."
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd "卸载 OpenVPN" apt-get remove --purge -y openvpn
			# Remove OpenVPN official repository and GPG key
			if [[ -e /etc/apt/sources.list.d/openvpn-aptrepo.list ]]; then
				run_cmd "删除 OpenVPN 源" rm /etc/apt/sources.list.d/openvpn-aptrepo.list
			fi
			if [[ -e /etc/apt/keyrings/openvpn-repo-public.asc ]]; then
				run_cmd "删除 OpenVPN GPG 密钥" rm /etc/apt/keyrings/openvpn-repo-public.asc
			fi
			run_cmd_fatal "更新软件包列表" apt-get update
		elif [[ $OS == 'arch' ]]; then
			run_cmd "卸载 OpenVPN" pacman --noconfirm -R openvpn
		elif [[ $OS =~ (centos|oracle) ]]; then
			run_cmd "卸载 OpenVPN" yum remove -y openvpn
			# Disable Copr repo if it was enabled
			if command -v dnf &>/dev/null; then
				run_cmd "禁用 OpenVPN Copr 源" dnf copr disable -y @OpenVPN/openvpn-release-2.6 2>/dev/null || true
			else
				run_cmd "禁用 OpenVPN Copr 源" yum copr disable -y @OpenVPN/openvpn-release-2.6 2>/dev/null || true
			fi
		elif [[ $OS == 'amzn2023' ]]; then
			run_cmd "卸载 OpenVPN" dnf remove -y openvpn
		elif [[ $OS == 'fedora' ]]; then
			run_cmd "卸载 OpenVPN" dnf remove -y openvpn
		elif [[ $OS == 'opensuse' ]]; then
			run_cmd "卸载 OpenVPN" zypper remove -y openvpn
		fi

		# Cleanup
		run_cmd "删除 /home 下客户端配置" find /home/ -maxdepth 2 -name "*.ovpn" -delete
		run_cmd "删除 /root 下客户端配置" find /root/ -maxdepth 1 -name "*.ovpn" -delete
		run_cmd "删除 /etc/openvpn" rm -rf /etc/openvpn
		run_cmd "删除 OpenVPN 文档" rm -rf /usr/share/doc/openvpn*
		run_cmd "删除 sysctl 配置" rm -f /etc/sysctl.d/99-openvpn.conf
		run_cmd "删除 OpenVPN 日志" rm -rf /var/log/openvpn

		# Unbound
		if [[ -e /etc/unbound/unbound.conf.d/openvpn.conf ]]; then
			removeUnbound
		fi
		log_success "OpenVPN 已卸载！"
	else
		log_info "已取消卸载。"
	fi
}

function setPushRoutes() {
	local conf="/etc/openvpn/server.conf"
	local push_routes_file="/etc/openvpn/push-routes"
	local new_routes

	# Show current: from push-routes file or parse server.conf
	if [[ -f $push_routes_file ]] && [[ -s $push_routes_file ]]; then
		log_prompt "当前走 VPN 的网段（network netmask）："
		while IFS= read -r line; do
			[[ -n $line ]] && log_prompt "  $line"
		done < "$push_routes_file"
	else
		log_prompt "当前未设置走 VPN 的网段。"
	fi
	log_menu ""
	log_prompt "请输入新的走 VPN 的网段（逗号分隔的 IPv4 CIDR，如 192.168.1.0/24,10.0.0.0/8，留空则清空）："
	read -rp "走 VPN 的网段: " -e new_routes
	new_routes=$(echo "$new_routes" | sed 's/,[[:space:]]*/,/g' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

	# Build new block
	local new_block_file
	new_block_file=$(mktemp)
	trap 'rm -f "$new_block_file"' RETURN
	echo '# PUSH_ROUTES_START' > "$new_block_file"
	: > "$push_routes_file"
	if [[ -n $new_routes ]]; then
		IFS=',' read -ra ROUTES <<< "$new_routes"
		for r in "${ROUTES[@]}"; do
			r=$(echo "$r" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
			[[ -z $r ]] && continue
			parsed=$(parse_push_route_ipv4 "$r")
			if [[ -n $parsed ]]; then
				echo "push \"route $parsed\"" >> "$new_block_file"
				echo "$parsed" >> "$push_routes_file"
			fi
		done
	fi
	echo '# PUSH_ROUTES_END' >> "$new_block_file"

	# Replace block in server.conf
	local start_ln end_ln insert_after
	start_ln=$(grep -n '^# PUSH_ROUTES_START$' "$conf" | head -1 | cut -d: -f1)
	if [[ -z $start_ln ]]; then
		# Old install without markers: append block after last "push " line (push-routes file already written above)
		local last_push_ln
		last_push_ln=$(grep -n '^push "' "$conf" | tail -1 | cut -d: -f1)
		if [[ -z $last_push_ln ]]; then
			log_fatal "未在 server.conf 中找到 push 行，无法添加走 VPN 的网段。请用本脚本重新安装或手动编辑。"
		fi
		sed -i "${last_push_ln}r $new_block_file" "$conf"
	else
		end_ln=$(grep -n '^# PUSH_ROUTES_END$' "$conf" | head -1 | cut -d: -f1)
		if [[ -z $end_ln ]]; then
			log_fatal "未在 server.conf 中找到 # PUSH_ROUTES_END，请检查配置。"
		fi
		sed -i "${start_ln},${end_ln}d" "$conf"
		insert_after=$((start_ln - 1))
		sed -i "${insert_after}r $new_block_file" "$conf"
	fi

	log_info "正在重启 OpenVPN 服务以应用新路由..."
	run_cmd "Restarting OpenVPN" systemctl restart "$(getOpenVPNServiceUnit)"
	log_success "走 VPN 的网段已更新。"
}

# Output all client names (one per line) that have a cert in pki/issued, excluding server certs
getClientNamesForRegen() {
	local cert_dir="/etc/openvpn/easy-rsa/pki/issued"
	local cert_file client_name
	for cert_file in "$cert_dir"/*.crt; do
		[[ ! -f "$cert_file" ]] && continue
		client_name=$(basename "$cert_file" .crt)
		[[ "$client_name" == server_* ]] && continue
		[[ "$client_name" == *.bak ]] && continue
		echo "$client_name"
	done
}

function setListenPort() {
	local conf="/etc/openvpn/server.conf"
	local template="/etc/openvpn/client-template.txt"
	local old_port new_port protocol protocol_base

	old_port=$(grep '^port ' "$conf" | cut -d " " -f 2)
	protocol=$(grep '^proto ' "$conf" | cut -d " " -f 2)
	protocol_base="${protocol%6}"

	log_prompt "当前监听端口: $old_port"
	log_prompt "请输入新的端口 [1-65535]（直接回车取消）："
	read -rp "新端口: " -e new_port
	new_port=$(echo "$new_port" | tr -d '[:space:]')
	[[ -z $new_port ]] && { log_info "已取消。"; return 0; }
	if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ "$new_port" -lt 1 ]] || [[ "$new_port" -gt 65535 ]]; then
		log_fatal "无效端口: $new_port，须为 1-65535。"
	fi
	[[ "$new_port" == "$old_port" ]] && { log_info "端口未变更。"; return 0; }

	# Update server.conf
	run_cmd "更新 server.conf 端口" sed -i "s/^port .*/port $new_port/" "$conf"

	# Update client-template.txt (remote IP PORT line)
	if [[ -f $template ]]; then
		run_cmd "更新客户端模板中的端口" sed -i "s/^remote \([^ ]*\) [0-9][0-9]*/remote \\1 $new_port/" "$template"
	fi

	# Firewall: remove old port, add new port
	if systemctl is-active --quiet firewalld 2>/dev/null; then
		run_cmd "从 firewalld 移除旧端口" firewall-cmd --permanent --remove-port="$old_port/$protocol_base" 2>/dev/null || true
		run_cmd "在 firewalld 添加新端口" firewall-cmd --permanent --add-port="$new_port/$protocol_base"
		run_cmd "重载 firewalld" firewall-cmd --reload
	elif [[ -f /etc/nftables/openvpn.nft ]]; then
		run_cmd "更新 nftables 规则中的端口" sed -i "s/dport $old_port/dport $new_port/g" /etc/nftables/openvpn.nft
		run_cmd "重载 nftables" systemctl reload nftables
	elif [[ -f /etc/iptables/add-openvpn-rules.sh ]]; then
		run_cmd "移除旧 iptables 规则" /etc/iptables/rm-openvpn-rules.sh 2>/dev/null || true
		run_cmd "更新 iptables 脚本中的端口" sed -i "s/--dport $old_port/--dport $new_port/g" /etc/iptables/add-openvpn-rules.sh /etc/iptables/rm-openvpn-rules.sh
		run_cmd "添加新 iptables 规则" /etc/iptables/add-openvpn-rules.sh
	fi

	# SELinux: remove old custom port, add new if custom
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			[[ $old_port != '1194' ]] && run_cmd "移除 SELinux 旧端口" semanage port -d -t openvpn_port_t -p "$protocol_base" "$old_port" 2>/dev/null || true
			[[ $new_port != '1194' ]] && run_cmd "添加 SELinux 新端口" semanage port -a -t openvpn_port_t -p "$protocol_base" "$new_port" 2>/dev/null || true
		fi
	fi

	# Restart OpenVPN
	log_info "正在重启 OpenVPN 服务..."
	run_cmd "重启 OpenVPN" systemctl restart "$(getOpenVPNServiceUnit)"

	# Regenerate all existing client configs
	local client count=0
	cd /etc/openvpn/easy-rsa/ || return
	for client in $(getClientNamesForRegen); do
		[[ -z "$client" ]] && continue
		[[ -f "pki/issued/$client.crt" ]] || continue
		log_info "重新生成客户端配置: $client"
		CLIENT="$client" writeClientConfig "$client"
		((count++)) || true
	done
	cd - >/dev/null || true
	log_success "监听端口已改为 $new_port；服务已重启，已重新生成 $count 个客户端配置文件。"
}

function setProtocol() {
	local server_conf="/etc/openvpn/server.conf"
	local template="/etc/openvpn/client-template.txt"
	local old_proto new_proto new_proto_client port protocol_base choice
	local is_ipv6=false

	old_proto=$(grep '^proto ' "$server_conf" | cut -d " " -f 2)
	port=$(grep '^port ' "$server_conf" | cut -d " " -f 2)
	[[ "$old_proto" == *6 ]] && is_ipv6=true
	protocol_base="${old_proto%6}"

	log_prompt "当前协议: $old_proto（端口: $port）"
	log_prompt "请选择新协议："
	log_menu "   1) UDP"
	log_menu "   2) TCP"
	until [[ "${choice:-}" =~ ^[12]$ ]]; do
		read -rp "请选择 [1-2]: " -e choice
	done
	if [[ $choice == "1" ]]; then
		$is_ipv6 && new_proto="udp6" || new_proto="udp"
		new_proto_client="proto $new_proto"
	else
		$is_ipv6 && new_proto="tcp6" || new_proto="tcp"
		new_proto_client="proto ${new_proto}-client"
	fi
	[[ "$new_proto" == "$old_proto" ]] && { log_info "协议未变更。"; return 0; }

	# Update server.conf
	run_cmd "更新 server.conf 协议" sed -i "s/^proto .*/proto $new_proto/" "$server_conf"

	# Update client-template.txt: replace proto line and explicit-exit-notify
	if [[ -f $template ]]; then
		sed -i "s/^proto .*/$new_proto_client/" "$template"
		if [[ "$new_proto" == udp* ]]; then
			grep -q '^explicit-exit-notify$' "$template" || sed -i "/^proto /a explicit-exit-notify" "$template"
		else
			sed -i '/^explicit-exit-notify$/d' "$template"
		fi
	fi

	# Firewall: remove old port/protocol, add same port with new protocol
	if systemctl is-active --quiet firewalld 2>/dev/null; then
		run_cmd "从 firewalld 移除旧规则" firewall-cmd --permanent --remove-port="$port/$protocol_base" 2>/dev/null || true
		run_cmd "在 firewalld 添加新协议规则" firewall-cmd --permanent --add-port="$port/${new_proto%6}"
		run_cmd "重载 firewalld" firewall-cmd --reload
	elif [[ -f /etc/nftables/openvpn.nft ]]; then
		run_cmd "更新 nftables 规则中的协议" sed -i "s/ $old_proto dport/ $new_proto dport/g" /etc/nftables/openvpn.nft
		run_cmd "重载 nftables" systemctl reload nftables
	elif [[ -f /etc/iptables/add-openvpn-rules.sh ]]; then
		run_cmd "移除旧 iptables 规则" /etc/iptables/rm-openvpn-rules.sh 2>/dev/null || true
		run_cmd "更新 iptables 脚本中的协议" sed -i "s/-p $protocol_base/-p ${new_proto%6}/g" /etc/iptables/add-openvpn-rules.sh /etc/iptables/rm-openvpn-rules.sh
		run_cmd "添加新 iptables 规则" /etc/iptables/add-openvpn-rules.sh
	fi

	# SELinux: update port type for new protocol
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			[[ $port != '1194' ]] && run_cmd "移除 SELinux 旧协议端口" semanage port -d -t openvpn_port_t -p "$protocol_base" "$port" 2>/dev/null || true
			[[ $port != '1194' ]] && run_cmd "添加 SELinux 新协议端口" semanage port -a -t openvpn_port_t -p "${new_proto%6}" "$port" 2>/dev/null || true
		fi
	fi

	# Restart OpenVPN to apply protocol change
	log_info "正在重启 OpenVPN 服务以使协议生效..."
	run_cmd "重启 OpenVPN" systemctl restart "$(getOpenVPNServiceUnit)"

	# Regenerate all existing client configs
	local client count=0
	cd /etc/openvpn/easy-rsa/ || return
	for client in $(getClientNamesForRegen); do
		[[ -z "$client" ]] && continue
		[[ -f "pki/issued/$client.crt" ]] || continue
		log_info "重新生成客户端配置: $client"
		CLIENT="$client" writeClientConfig "$client"
		((count++)) || true
	done
	cd - >/dev/null || true
	log_success "协议已改为 $new_proto；服务已重启，已重新生成 $count 个客户端配置文件。"
}

function setPerfOpt() {
	local server_conf="/etc/openvpn/server.conf"
	local template="/etc/openvpn/client-template.txt"
	local perf_opt_file="/etc/openvpn/perf-opt"
	local current_opt new_opt
	local start_ln end_ln insert_after
	local tmp_block

	tmp_block=$(mktemp) || log_fatal "无法创建临时文件"
	trap 'rm -f "$tmp_block"' RETURN

	# Read current PERF_OPT from file or infer from server.conf
	if [[ -f $perf_opt_file ]]; then
		current_opt=$(cat "$perf_opt_file")
	else
		if grep -q 'sndbuf 393216' "$server_conf" 2>/dev/null; then
			current_opt=2
		elif grep -q 'compress lz4-v2' "$server_conf" 2>/dev/null; then
			current_opt=3
		elif grep -q '^sndbuf ' "$server_conf" 2>/dev/null; then
			current_opt=1
		elif grep -q '^# PERF_SERVER_START$' "$server_conf" 2>/dev/null && ! grep -q '^sndbuf ' "$server_conf" 2>/dev/null && ! grep -q 'push "sndbuf' "$server_conf" 2>/dev/null; then
			current_opt=2
		else
			current_opt=4
		fi
	fi
	current_opt=${current_opt:-1}

	log_prompt "当前性能优化: $current_opt（1=默认 2=高吞吐 3=低带宽 4=关闭）"
	log_menu "   1) 默认：不压缩、系统缓冲区、mssfix 1400"
	log_menu "   2) 高吞吐：精简配置（无 sndbuf/rcvbuf/mssfix，与高性能备份一致）"
	log_menu "   3) 低带宽：启用 lz4 压缩"
	log_menu "   4) 关闭：使用 OpenVPN 默认"
	until [[ "${new_opt:-}" =~ ^[1-4]$ ]]; do
		read -rp "请选择 [1-4]: " -e -i "$current_opt" new_opt
	done
	[[ "$new_opt" == "$current_opt" ]] && { log_info "未变更。"; return 0; }

	# Replace server-side performance block
	if grep -q '^# PERF_SERVER_START$' "$server_conf" 2>/dev/null; then
		start_ln=$(grep -n '^# PERF_SERVER_START$' "$server_conf" | head -1 | cut -d: -f1)
		end_ln=$(grep -n '^# PERF_SERVER_END$' "$server_conf" | head -1 | cut -d: -f1)
		[[ -z $start_ln || -z $end_ln ]] && log_fatal "未找到性能优化标记，请检查 server.conf。"
		: > "$tmp_block"
		echo '# PERF_SERVER_START' >> "$tmp_block"
		case "$new_opt" in
		1) echo -e "# Performance: OS buffers, no compression, mssfix\nsndbuf 0\nrcvbuf 0\nallow-compression no\nmssfix 1400" >> "$tmp_block" ;;
		2) ;;  # 高性能：不加 sndbuf/rcvbuf/mssfix，与精简备份一致
		3) echo -e "# Performance: lz4 compression for low bandwidth\nsndbuf 0\nrcvbuf 0\ncompress lz4-v2\nmssfix 1400" >> "$tmp_block" ;;
		4) ;;
		esac
		echo '# PERF_SERVER_END' >> "$tmp_block"
		sed -i "${start_ln},${end_ln}d" "$server_conf"
		insert_after=$((start_ln - 1))
		sed -i "${insert_after}r $tmp_block" "$server_conf"
	else
		log_fatal "未找到 # PERF_SERVER_START 标记，无法修改。请用本脚本重新安装或手动编辑 server.conf。"
	fi

	# Replace push performance block
	if grep -q '^# PERF_PUSH_START$' "$server_conf" 2>/dev/null; then
		start_ln=$(grep -n '^# PERF_PUSH_START$' "$server_conf" | head -1 | cut -d: -f1)
		end_ln=$(grep -n '^# PERF_PUSH_END$' "$server_conf" | head -1 | cut -d: -f1)
		[[ -z $start_ln || -z $end_ln ]] && log_fatal "未找到 PERF_PUSH 标记，请检查 server.conf。"
		: > "$tmp_block"
		echo '# PERF_PUSH_START' >> "$tmp_block"
		case "$new_opt" in
		1) echo -e 'push "sndbuf 0"\npush "rcvbuf 0"\npush "allow-compression no"\npush "mssfix 1400"' >> "$tmp_block" ;;
		2) ;;  # 高性能：不推送 sndbuf/rcvbuf/mssfix
		3) echo -e 'push "compress lz4-v2"\npush "sndbuf 0"\npush "rcvbuf 0"\npush "mssfix 1400"' >> "$tmp_block" ;;
		4) ;;
		esac
		echo '# PERF_PUSH_END' >> "$tmp_block"
		sed -i "${start_ln},${end_ln}d" "$server_conf"
		insert_after=$((start_ln - 1))
		sed -i "${insert_after}r $tmp_block" "$server_conf"
	fi

	# Replace client template performance block
	if [[ -f $template ]] && grep -q '^# PERF_CLIENT_START$' "$template" 2>/dev/null; then
		start_ln=$(grep -n '^# PERF_CLIENT_START$' "$template" | head -1 | cut -d: -f1)
		end_ln=$(grep -n '^# PERF_CLIENT_END$' "$template" | head -1 | cut -d: -f1)
		[[ -n $start_ln && -n $end_ln ]] && {
			: > "$tmp_block"
			echo '# PERF_CLIENT_START' >> "$tmp_block"
			case "$new_opt" in
			2)
				# 高性能：仅 route + pull-filter + route-nopull
				if [[ -f /etc/openvpn/push-routes ]] && [[ -s /etc/openvpn/push-routes ]]; then
					while IFS= read -r line; do
						[[ -n $line ]] && echo "route $line" >> "$tmp_block"
					done </etc/openvpn/push-routes
				fi
				echo 'pull-filter ignore "redirect-gateway"' >> "$tmp_block"
				echo 'route-nopull' >> "$tmp_block"
				;;
			1|3) echo -e "# Performance: ignore redirect-gateway; buffers; mssfix\npull-filter ignore \"redirect-gateway\"\nsndbuf 0\nrcvbuf 0\nmssfix 1400" >> "$tmp_block" ;;
			4) echo 'pull-filter ignore "redirect-gateway"' >> "$tmp_block" ;;
			esac
			echo '# PERF_CLIENT_END' >> "$tmp_block"
			sed -i "${start_ln},${end_ln}d" "$template"
			insert_after=$((start_ln - 1))
			sed -i "${insert_after}r $tmp_block" "$template"
		}
	fi

	echo "$new_opt" > "$perf_opt_file"

	# Regenerate all client configs
	local client count=0
	cd /etc/openvpn/easy-rsa/ || return
	for client in $(getClientNamesForRegen); do
		[[ -z "$client" ]] && continue
		[[ -f "pki/issued/$client.crt" ]] || continue
		log_info "重新生成客户端配置: $client"
		CLIENT="$client" writeClientConfig "$client"
		((count++)) || true
	done
	cd - >/dev/null || true

	log_info "正在重启 OpenVPN 服务..."
	run_cmd "重启 OpenVPN" systemctl restart "$(getOpenVPNServiceUnit)"
	log_success "性能优化已改为选项 $new_opt；已重新生成 $count 个客户端配置文件，服务已重启。"
}

function restartOpenVPN() {
	log_info "正在重启 OpenVPN 服务..."
	run_cmd "重启 OpenVPN" systemctl restart "$(getOpenVPNServiceUnit)"
	log_success "OpenVPN 服务已重启。"
}

# 修复 systemd 服务：经典布局下确保使用 openvpn-server@server，从 /etc/openvpn 读取 server.conf
function fixOpenVPNSystemdService() {
	log_header "修复 OpenVPN systemd 服务"
	if [[ ! -f /etc/openvpn/server.conf ]]; then
		log_fatal "未找到 /etc/openvpn/server.conf，请确认由本脚本安装（经典布局）。"
	fi
	# 先停止并禁用旧名 openvpn@server（若存在），再使用 openvpn-server@server
	run_cmd "禁用 openvpn@server（若存在）" systemctl disable openvpn@server 2>/dev/null || true
	run_cmd "停止 openvpn@server（若存在）" systemctl stop openvpn@server 2>/dev/null || true

	local unit="/etc/systemd/system/openvpn-server@.service"
	if [[ ! -f $unit ]]; then
		# 与安装逻辑一致：优先 openvpn@.service（Type=notify 等形式，性能更好）
		log_prompt "未找到 $unit，将根据 openvpn@.service 创建并修补。"
		if [[ -f /usr/lib/systemd/system/openvpn@.service ]]; then
			SERVICE_SOURCE="/usr/lib/systemd/system/openvpn@.service"
		elif [[ -f /lib/systemd/system/openvpn@.service ]]; then
			SERVICE_SOURCE="/lib/systemd/system/openvpn@.service"
		elif [[ -f /etc/systemd/system/openvpn@.service ]]; then
			SERVICE_SOURCE="/etc/systemd/system/openvpn@.service"
		elif [[ -f /usr/lib/systemd/system/openvpn-server@.service ]]; then
			SERVICE_SOURCE="/usr/lib/systemd/system/openvpn-server@.service"
		elif [[ -f /lib/systemd/system/openvpn-server@.service ]]; then
			SERVICE_SOURCE="/lib/systemd/system/openvpn-server@.service"
		else
			log_fatal "未找到 openvpn@.service 或 openvpn-server@.service，无法创建 $unit。"
		fi
		run_cmd_fatal "复制并创建 openvpn-server@.service" cp "$SERVICE_SOURCE" "$unit"
		grep -q "LimitNPROC" "$unit" && run_cmd "修补服务文件 (LimitNPROC)" sed -i 's|LimitNPROC|#LimitNPROC|' "$unit"
	fi

	log_prompt "修正 openvpn-server@.service 的工作目录与路径，使服务从 /etc/openvpn 读取 server.conf。"
	grep -q "/etc/openvpn/server" "$unit" && run_cmd "修正 unit 中的路径" sed -i 's|/etc/openvpn/server|/etc/openvpn|g' "$unit"
	if grep -q "WorkingDirectory=" "$unit"; then
		run_cmd "修正 WorkingDirectory" sed -i 's|^WorkingDirectory=.*|WorkingDirectory=/etc/openvpn|' "$unit"
	else
		run_cmd "添加 WorkingDirectory" sed -i '/\[Service\]/a WorkingDirectory=/etc/openvpn' "$unit"
	fi
	run_cmd "重载 systemd" systemctl daemon-reload
	run_cmd "启用并重启 OpenVPN" systemctl enable openvpn-server@server 2>/dev/null || true
	run_cmd "重启 OpenVPN" systemctl restart openvpn-server@server
	log_success "systemd 服务已修复并重启。若仍报错，请执行: systemctl status openvpn-server@server"
}

# 备份 OpenVPN 配置为压缩包（tar.gz）
# 可选参数：输出路径或目录，默认当前目录
function backupOpenVPNConfig() {
	log_header "备份 OpenVPN 配置"
	if [[ ! -d /etc/openvpn ]] || [[ ! -f /etc/openvpn/server.conf ]]; then
		log_fatal "未找到 /etc/openvpn 或 server.conf，请确认已安装 OpenVPN。"
	fi
	local default_dir
	default_dir=$(pwd)
	[[ -d /root ]] && default_dir="/root"
	local out_path="${1:-}"
	if [[ -z $out_path ]]; then
		local ts
		ts=$(date +%Y%m%d-%H%M%S)
		out_path="$default_dir/openvpn-backup-$ts.tar.gz"
		log_prompt "备份将保存到: $out_path"
		read -rp "可输入自定义路径（留空使用上述路径）: " -e out_custom
		[[ -n $out_custom ]] && out_path="$out_custom"
	fi
	out_path=$(echo "$out_path" | sed 's|^[[:space:]]*||;s|[[:space:]]*$||')
	[[ -z $out_path ]] && log_fatal "未指定备份路径。"
	# 若为目录则在该目录下生成默认文件名
	if [[ -d "$out_path" ]]; then
		local ts
		ts=$(date +%Y%m%d-%H%M%S)
		out_path="$out_path/openvpn-backup-$ts.tar.gz"
	fi
	local out_dir
	out_dir=$(dirname "$out_path")
	[[ ! -d $out_dir ]] && run_cmd_fatal "创建输出目录" mkdir -p "$out_dir"
	run_cmd_fatal "创建备份压缩包" tar -C / -czvf "$out_path" etc/openvpn
	log_success "配置已备份到: $out_path"
}

# 从压缩包导入 OpenVPN 配置（覆盖现有 /etc/openvpn）
# 支持直接输入文件路径，或输入目录后从列出的备份中选择
function importOpenVPNConfig() {
	log_header "导入 OpenVPN 配置"
	local arch_path input_path
	log_prompt "请输入备份文件路径，或输入目录以列出并选择备份文件: "
	read -rp "" -e input_path
	input_path=$(echo "$input_path" | sed 's|^[[:space:]]*||;s|[[:space:]]*$||')
	[[ -z $input_path ]] && { log_error "未输入路径。"; return 1; }

	if [[ -d $input_path ]]; then
		# 目录：列出 .tar.gz / .tgz / .tar 文件供选择
		local -a backups
		local i choice
		while IFS= read -r -d '' f; do
			backups+=( "$f" )
		done < <(find "$input_path" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.tgz' -o -name '*.tar' \) -print0 2>/dev/null | sort -z)
		[[ ${#backups[@]} -eq 0 ]] && log_fatal "该目录下未找到备份文件（.tar.gz / .tgz / .tar）。"
		log_prompt "找到以下备份，请选择要恢复的序号（0 取消）:"
		for i in "${!backups[@]}"; do
			log_menu "   $((i + 1))) $(basename "${backups[$i]}")"
		done
		until [[ $choice =~ ^[0-9]+$ ]] && [[ $choice -ge 0 ]] && [[ $choice -le ${#backups[@]} ]]; do
			read -rp "请选择 [0-${#backups[@]}]: " -e choice
		done
		[[ $choice -eq 0 ]] && { log_info "已取消。"; return 0; }
		arch_path="${backups[$((choice - 1))]}"
	else
		arch_path="$input_path"
	fi

	[[ ! -f $arch_path ]] && log_fatal "文件不存在: $arch_path"
	case "$arch_path" in
		*.tar.gz|*.tgz|*.tar) ;;
		*) log_fatal "仅支持 .tar.gz、.tgz 或 .tar 格式。";;
	esac
	if [[ -d /etc/openvpn ]] && [[ -f /etc/openvpn/server.conf ]]; then
		log_prompt "当前已有配置，导入将先删除再恢复 /etc/openvpn。是否继续？[y/n]: "
		read -rp "" -e confirm
		[[ ${confirm,,} != "y" ]] && { log_info "已取消。"; return 0; }
	fi
	run_cmd "停止 OpenVPN 服务（若在运行）" systemctl stop "$(getOpenVPNServiceUnit)" 2>/dev/null || true
	run_cmd "禁用 openvpn@server（若存在）" systemctl disable openvpn@server 2>/dev/null || true
	[[ -d /etc/openvpn ]] && run_cmd "删除现有配置目录" rm -rf /etc/openvpn
	log_info "正在解压备份到 /etc/openvpn ..."
	if [[ $arch_path == *.tar ]]; then
		run_cmd_fatal "解压备份" tar -C / -xvf "$arch_path"
	else
		run_cmd_fatal "解压备份" tar -C / -xzvf "$arch_path"
	fi
	if [[ ! -f /etc/openvpn/server.conf ]]; then
		log_fatal "解压后未找到 /etc/openvpn/server.conf，请检查备份文件是否由本脚本生成。"
	fi
	run_cmd "重载 systemd" systemctl daemon-reload
	run_cmd "启用 OpenVPN 服务" systemctl enable openvpn-server@server 2>/dev/null || true
	run_cmd "启动 OpenVPN 服务" systemctl start openvpn-server@server 2>/dev/null || true
	log_success "配置已导入。建议执行菜单「修复 OpenVPN systemd 服务」以确认服务单元正确。"
}

function manageMenu() {
	local menu_option

	log_header "OpenVPN 管理"
	log_prompt "项目地址: https://github.com/angristan/openvpn-install"
	log_success "OpenVPN 已安装。"
	log_menu ""
	log_prompt "请选择操作："
	log_menu "   1) 添加新用户"
	log_menu "   2) 列出客户端证书"
	log_menu "   3) 吊销用户"
	log_menu "   4) 续期证书"
	log_menu "   5) 移除 OpenVPN"
	log_menu "   6) 查看已连接客户端"
	log_menu "   7) 修改走 VPN 的网段"
	log_menu "   8) 修改监听端口"
	log_menu "   9) 修改协议 (TCP/UDP)"
	log_menu "  10) 修改性能优化"
	log_menu "  11) 重启 OpenVPN 服务"
	log_menu "  12) 修复 OpenVPN systemd 服务（WorkingDirectory 等）"
	log_menu "  13) 备份配置（压缩包）"
	log_menu "  14) 导入配置（从压缩包恢复）"
	log_menu "  15) 退出"
	until [[ ${MENU_OPTION:-$menu_option} =~ ^([1-9]|10|11|12|13|14|15)$ ]]; do
		read -rp "请选择 [1-15]: " menu_option
	done
	menu_option="${MENU_OPTION:-$menu_option}"

	case $menu_option in
	1)
		newClient
		exit 0
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		renewMenu
		;;
	5)
		removeOpenVPN
		;;
	6)
		listConnectedClients
		;;
	7)
		setPushRoutes
		;;
	8)
		setListenPort
		;;
	9)
		setProtocol
		;;
	10)
		setPerfOpt
		;;
	11)
		restartOpenVPN
		;;
	12)
		fixOpenVPNSystemdService
		;;
	13)
		backupOpenVPNConfig
		;;
	14)
		importOpenVPNConfig
		;;
	15)
		exit 0
		;;
	esac
}

# =============================================================================
# Main Entry Point
# =============================================================================
parse_args "$@"
