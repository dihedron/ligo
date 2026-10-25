# shellcheck shell=bash
# Common functions of the lab: settings, output and small helpers. Sourced by
# lab.sh, which sets LAB_DIR (test/lab) and REPO_DIR (the repository).

# load_settings reads lab.env, then lab.local.env if present, then gives
# precedence to the LAB_* variables set in the environment.
load_settings() {
	local name pair saved=()
	for name in $(compgen -A export LAB_); do
		saved+=("$name=${!name}")
	done
	# shellcheck disable=SC1091 # lab.env: settings, checked on its own
	source "$LAB_DIR/lab.env"
	if [[ -f "$LAB_DIR/lab.local.env" ]]; then
		# shellcheck disable=SC1091
		source "$LAB_DIR/lab.local.env"
	fi
	for pair in "${saved[@]}"; do
		printf -v "${pair%%=*}" '%s' "${pair#*=}"
	done
	[[ "$LAB_STATE_DIR" = /* ]] || LAB_STATE_DIR="$LAB_DIR/$LAB_STATE_DIR"
}

# --- Output -------------------------------------------------------------------

if [[ -t 1 ]]; then
	_green=$'\e[32m' _yellow=$'\e[33m' _red=$'\e[31m' _bold=$'\e[1m' _reset=$'\e[0m'
else
	_green='' _yellow='' _red='' _bold='' _reset=''
fi

section() { printf '\n%s%s%s\n' "$_bold" "$*" "$_reset"; }
info() { printf '        %s\n' "$*"; }
die() {
	printf '%serror:%s %s\n' "$_red" "$_reset" "$*" >&2
	exit 1
}

# Check results, counted by the preflight.
CHECK_FAILS=0
CHECK_WARNS=0
ok() { printf '  %sok%s    %s\n' "$_green" "$_reset" "$*"; }
warn() {
	printf '  %swarn%s  %s\n' "$_yellow" "$_reset" "$*"
	CHECK_WARNS=$((CHECK_WARNS + 1))
}
fail() {
	printf '  %sfail%s  %s\n' "$_red" "$_reset" "$*"
	CHECK_FAILS=$((CHECK_FAILS + 1))
}

# confirm QUESTION: true when the user (or LAB_ASSUME_YES) says yes.
confirm() {
	[[ "$LAB_ASSUME_YES" == yes ]] && return 0
	local answer
	read -r -p "$1 [y/N] " answer
	[[ "$answer" == [yY] || "$answer" == [yY][eE][sS] ]]
}

# --- Scenarios ----------------------------------------------------------------

# select_scenarios VALUE: checks a --scenario value (empty: LAB_SCENARIOS).
select_scenarios() {
	local value="${1:-$LAB_SCENARIOS}" scenario
	[[ "$value" == all ]] && value="storage"
	for scenario in $value; do
		[[ "$scenario" == storage ]] || die "unknown scenario \"$scenario\": only storage exists"
	done
}

# --- Addresses ----------------------------------------------------------------

# subnet_prefix: the first three octets of LAB_SUBNET (a /24).
subnet_prefix() { printf '%s' "${LAB_SUBNET%.*}"; }
# lab_gateway: the bridge's address on the lab subnet.
lab_gateway() { printf '%s.1' "$(subnet_prefix)"; }
# pg_ip: the PostgreSQL VM's address.
pg_ip() { printf '%s.%s' "$(subnet_prefix)" "$LAB_PG_HOST"; }

# --- LXD ----------------------------------------------------------------------

# lxd: lxc in the lab's project.
lxd() { lxc --project "$LAB_PROJECT" "$@"; }

# lxd_reachable: true when this session can talk to the LXD daemon.
lxd_reachable() { lxc query /1.0 >/dev/null 2>&1; }

# ensure_lxd_access ARGS: when this session cannot reach LXD but the user is
# in the lxd group (joined after this session started), runs lab.sh ARGS
# again through "sg lxd".
ensure_lxd_access() {
	lxd_reachable || [[ -n "${LAB_SG_DONE:-}" ]] || ! command -v lxc >/dev/null && return 0
	if getent group lxd | cut -d: -f4 | tr ',' '\n' | grep -qx "$(id -un)"; then
		export LAB_SG_DONE=1
		exec sg lxd -c "$(printf '%q ' "$LAB_DIR/lab.sh" "$@")"
	fi
}
