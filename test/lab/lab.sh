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
# shellcheck source=lib/inner.sh
source "$LAB_DIR/lib/inner.sh"
# shellcheck source=lib/fetch.sh
source "$LAB_DIR/lib/fetch.sh"
# shellcheck source=lib/spire.sh
source "$LAB_DIR/lib/spire.sh"
# shellcheck source=lib/bao.sh
source "$LAB_DIR/lib/bao.sh"
# shellcheck source=lib/ldap.sh
source "$LAB_DIR/lib/ldap.sh"
# shellcheck source=lib/deploy.sh
source "$LAB_DIR/lib/deploy.sh"
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
  env --on ligo1            the environment of the tests on ligo1, one
                            VAR=value per line
  deploy                    build the lab-tagged tests and copy them to ligo1
  test --on ligo1 [-run REGEX]
                            deploy, then run them on ligo1 as the user ligo
  test [-run REGEX] [pkg...]
                            run "go test -tags integration" (default ./...)
                            with that environment
  spire <prod|test> [args]  spire-server on that zone's server
  bao <prod|test> [args]    the bao CLI on that zone's OpenBao, as root token
  ldapsearch [args]         ldapsearch over ldaps as ligo-admin-auth
  psql [--as ROLE | --superuser] [args]
                            psql in the pg container as ligo_ROLE (migrator, app,
                            reader, dbos; default migrator) over TLS, or as
                            postgres over the Unix socket
  snapshot                  save the VMs as the lab's baseline
  reset                     return the VMs to the baseline (an empty
                            database), and wait until it answers
  stop / start              stop the VMs cleanly / start them as they were
  ssh <name> [command]      a root shell, or a command, in the lab VM (lxd)
                            or an inner instance (pg, ...)
  logs <name> [unit]        its cloud-init log, or a unit's journal
  help                      this text

settings: lab.env, overridden by lab.local.env and the environment
USAGE
}

# require_lab fails unless "up" has built the lab.
require_lab() {
	if [[ ! -f "$LAB_STATE_DIR/env.json" ]] || ! vm_exists lxd; then
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
	lxd_vm_up
	pg_up
	pg_record
	if selected identity; then
		identity_spire_up
		identity_bao_up
		ldap_up
	fi
	# a new snapshot when there is none, or when up added inner instances
	if ! has_snapshot || [[ "$(env_get '.snapshot_instances // ""')" != "$(inner_names)" ]]; then
		lab_snapshot
	fi
	section "Done"
	info "the lab is up: eval \"\$(test/lab/lab.sh env)\", or lab.sh test"
}

cmd_down() {
	confirm "Destroy the ligo lab (VMs, snapshots, network, project, pool, state)?" || die "cancelled"
	local vm
	for vm in lxd pg; do # pg: the VM of the lab's first layout
		if vm_exists "$vm"; then
			lxd delete "$vm" --force && info "VM $vm deleted"
		fi
	done
	lxd_down
	rm -rf "$LAB_STATE_DIR"
	info "state directory removed"
}

cmd_status() {
	section "VM ($LAB_PROJECT)"
	lxd list -c nsN4 -f compact 2>/dev/null || info "no project $LAB_PROJECT"
	if vm_running lxd; then
		section "Inner instances"
		inner list -c ntsN4 -f compact
	fi
	section "Recorded (env.json)"
	if [[ -f "$LAB_STATE_DIR/env.json" ]]; then jq . "$LAB_STATE_DIR/env.json"; else info "nothing recorded"; fi
}

cmd_env() {
	require_lab
	if [[ "${1:-}" == --on ]]; then
		[[ "${2:-}" == ligo1 ]] || die "env --on: only ligo1"
		env_ligo1
		return
	fi
	local role upper
	for role in migrator app reader dbos; do
		upper="$(tr '[:lower:]' '[:upper:]' <<<"$role")"
		printf 'export LIGO_TEST_PG_%s_DSN=%q\n' "$upper" "$(pg_dsn "$role")"
	done
}

cmd_test() {
	require_lab
	if [[ "${1:-}" == --on ]]; then
		[[ "${2:-}" == ligo1 ]] || die "test --on: only ligo1"
		shift 2
		test_ligo1 "$@"
		return
	fi
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

# on NAME ARGS: runs ARGS in the lab VM ("lxd") or in an inner instance.
on() {
	local name="$1"
	shift
	if [[ "$name" == lxd ]]; then lxd exec lxd -- "$@"; else inner_exec "$name" "$@"; fi
}

cmd_ssh() {
	local name="${1:?ssh: lxd or an inner instance?}"
	shift
	if (($#)); then
		on "$name" "$@"
	elif [[ "$name" == lxd ]]; then
		lxd exec lxd -- bash -l
	else
		lxd exec lxd -t -- lxc exec "$name" -- bash -l
	fi
}

cmd_logs() {
	local name="${1:?logs: lxd or an inner instance?}"
	if (($# > 1)); then on "$name" journalctl --no-pager -u "$2"; else on "$name" cat /var/log/cloud-init-output.log; fi
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
	env) cmd_env "$@" ;;
	deploy) cmd_deploy ;;
	test) cmd_test "$@" ;;
	psql) cmd_psql "$@" ;;
	spire) require_lab && spire "$@" ;;
	bao) require_lab && bao "$@" ;;
	ldapsearch) require_lab && ldapsearch_as ligo-admin-auth "$@" ;;
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
