#!/usr/bin/env bash
# The ligo lab: LXD virtual machines for the integration and acceptance
# tests. See .specs/ligo-test-environment.md and "lab.sh help".
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/../.." && pwd)"

# shellcheck source=lib/common.sh
source "$LAB_DIR/lib/common.sh"
# shellcheck source=lib/preflight.sh
source "$LAB_DIR/lib/preflight.sh"
# shellcheck source=lib/lxd.sh
source "$LAB_DIR/lib/lxd.sh"
# shellcheck source=lib/pki.sh
source "$LAB_DIR/lib/pki.sh"
# shellcheck source=lib/pg.sh
source "$LAB_DIR/lib/pg.sh"
# shellcheck source=lib/snapshot.sh
source "$LAB_DIR/lib/snapshot.sh"

usage() {
	cat <<USAGE
usage: lab.sh <command> [options]

commands:
  preflight                 check that this machine can run the lab
  up [--scenario S]         build the lab (or complete a partial one)
  down                      destroy the lab: VMs, network, project, storage
                            pool and state, after confirmation
  status                    show the lab's VMs and what was recorded
  env                       print the integration tests' environment, as
                            export lines: eval "\$(test/lab/lab.sh env)"
  test [-run REGEX] [pkg...]
                            run "go test -tags integration" (default ./...)
                            with that environment
  psql [--as ROLE | --superuser] [args]
                            psql in the pg VM as ligo_ROLE (migrator, app,
                            reader, dbos; default migrator) over TLS, or as
                            postgres over the Unix socket
  snapshot                  save the VMs as the lab's baseline
  reset                     return the VMs to the baseline (an empty
                            database), and wait until it answers
  stop / start              stop the VMs cleanly / start them as they were
  ssh <vm> [command]        a root shell, or a command, in a VM
  logs <vm> [unit]          a VM's cloud-init log, or a unit's journal
  help                      this text

settings: lab.env, overridden by lab.local.env and the environment
USAGE
}

# require_lab fails unless "up" has built the lab.
require_lab() {
	if [[ ! -f "$LAB_STATE_DIR/env.json" ]] || ! vm_exists pg; then
		die "the lab is not built: run lab.sh up"
	fi
}

cmd_up() {
	local scenario=""
	while (($#)); do
		case "$1" in
		--scenario) scenario="$2" && shift 2 ;;
		*) die "up: unknown option $1" ;;
		esac
	done
	select_scenarios "$scenario"
	preflight
	pki_up
	lxd_up
	pg_up
	pg_record
	has_snapshot || lab_snapshot
	section "Done"
	info "the lab is up: eval \"\$(test/lab/lab.sh env)\", or lab.sh test"
}

cmd_down() {
	confirm "Destroy the ligo lab (VMs, snapshots, network, project, pool, state)?" || die "cancelled"
	if vm_exists pg; then
		lxd delete pg --force && info "VM pg deleted"
	fi
	lxd_down
	rm -rf "$LAB_STATE_DIR"
	info "state directory removed"
}

cmd_status() {
	section "VMs ($LAB_PROJECT)"
	lxd list -c nsN4 -f compact 2>/dev/null || info "no project $LAB_PROJECT"
	section "Recorded (env.json)"
	if [[ -f "$LAB_STATE_DIR/env.json" ]]; then jq . "$LAB_STATE_DIR/env.json"; else info "nothing recorded"; fi
}

cmd_env() {
	require_lab
	local role upper
	for role in migrator app reader dbos; do
		upper="$(tr '[:lower:]' '[:upper:]' <<<"$role")"
		printf 'export LIGO_TEST_PG_%s_DSN=%q\n' "$upper" "$(pg_dsn "$role")"
	done
}

cmd_test() {
	require_lab
	local args=() pkgs=()
	while (($#)); do
		case "$1" in
		-run) args+=(-run "$2") && shift 2 ;;
		*) pkgs+=("$1") && shift ;;
		esac
	done
	((${#pkgs[@]})) || pkgs=(./...)
	eval "$(cmd_env)"
	cd "$REPO_DIR"
	go test -count=1 -tags integration "${args[@]}" "${pkgs[@]}"
}

cmd_psql() {
	require_lab
	case "${1:-}" in
	--superuser) shift && pg_superuser "$@" ;;
	--as) local role="$2" && shift 2 && pg_psql "$role" "$@" ;;
	*) pg_psql migrator "$@" ;;
	esac
}

cmd_ssh() {
	local vm="${1:?ssh: which VM?}"
	shift
	if (($#)); then lxd exec "$vm" -- "$@"; else lxd exec "$vm" -- bash -l; fi
}

cmd_logs() {
	local vm="${1:?logs: which VM?}"
	if (($# > 1)); then lxd exec "$vm" -- journalctl --no-pager -u "$2"; else lxd exec "$vm" -- cat /var/log/cloud-init-output.log; fi
}

main() {
	local command="${1:-help}"
	(($#)) && shift
	load_settings
	ensure_lxd_access "$command" "$@"
	case "$command" in
	preflight) preflight ;;
	up) cmd_up "$@" ;;
	down) cmd_down ;;
	status) cmd_status ;;
	env) cmd_env ;;
	test) cmd_test "$@" ;;
	psql) cmd_psql "$@" ;;
	snapshot) require_lab && lab_snapshot ;;
	reset) require_lab && lab_reset ;;
	stop) require_lab && lab_stop ;;
	start) require_lab && lab_start ;;
	ssh) cmd_ssh "$@" ;;
	logs) cmd_logs "$@" ;;
	help | -h | --help) usage ;;
	*) usage >&2 && exit 2 ;;
	esac
}

main "$@"
