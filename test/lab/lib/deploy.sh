# shellcheck shell=bash
# Tests that need SVIDs run on ligo1, the ligo host, as the user ligo: deploy
# builds them on the lab host and copies them there; "test --on ligo1" runs
# them (.specs/ligo-test-environment.md, "Tests on ligo1").

LIGO1_TESTS=/home/ligo/tests

# lab_packages: the packages with tests built with the lab tag.
lab_packages() {
	(cd "$REPO_DIR" && grep -rlE '^//go:build .*\blab\b' --include='*_test.go' . | xargs -r -n1 dirname | sort -u)
}

# env_ligo1: the environment of the tests on ligo1: the database directly
# (pg.ligo.lab), ligo's Workload API sockets, OpenBao and LDAP, and the lab CA
# copied to ligo1.
env_ligo1() {
	local role upper
	for role in migrator app reader dbos; do
		upper="$(tr '[:lower:]' '[:upper:]' <<<"$role")"
		printf 'LIGO_TEST_PG_%s_DSN=%s\n' "$upper" "$(pg_dsn "$role" pg.ligo.lab /etc/ligo-lab/ca.crt)"
	done
	printf '%s\n' \
		"LIGO_TEST_CA=/etc/ligo-lab/ca.crt" \
		"LIGO_TEST_SPIRE_PROD_SOCKET=unix:///run/spire/prod/agent.sock" \
		"LIGO_TEST_SPIRE_TEST_SOCKET=unix:///run/spire/test/agent.sock" \
		"LIGO_TEST_BAO_PROD_ADDR=https://bao-prod.ligo.lab:$BAO_PORT" \
		"LIGO_TEST_BAO_PROD_AUDIENCE=https://bao-prod.ligo.lab" \
		"LIGO_TEST_LDAP_URL=$LDAP_URL" \
		"LIGO_TEST_LDAP_BASE=$LDAP_BASE"
}

# cmd_deploy: builds the lab tests (static, linux/amd64) and copies them to
# ligo1, owned by ligo.
cmd_deploy() {
	require_lab
	inner_exists ligo1 || die "ligo1 does not exist: lab.sh up --scenario identity"
	section "Deploy"
	local out="$LAB_STATE_DIR/tests" pkg name
	rm -rf "${out:?}" && mkdir -p "$out"
	for pkg in $(lab_packages); do
		name="$(tr '/' '_' <<<"${pkg#./}").test"
		(cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags 'integration lab' -o "$out/$name" "$pkg") ||
			die "cannot build the tests of $pkg"
		info "built $pkg"
	done
	inner_exec ligo1 sh -c "rm -rf $LIGO1_TESTS && install -d -o ligo -g ligo $LIGO1_TESTS /etc/ligo-lab"
	inner_push "$LAB_STATE_DIR/pki/ca.crt" ligo1 /etc/ligo-lab/ca.crt 0644
	for name in "$out"/*.test; do
		inner_push "$name" ligo1 "$LIGO1_TESTS/${name##*/}" 0755
	done
	inner_exec ligo1 chown -R ligo:ligo "$LIGO1_TESTS"
	info "copied $(find "$out" -name '*.test' | wc -l) test binaries to ligo1:$LIGO1_TESTS"
}

# test_ligo1 [-run REGEX]: deploys, then runs every lab test binary on ligo1
# as the user ligo; fails if any fails.
test_ligo1() {
	local run=()
	while (($#)); do
		case "$1" in
		-run) run=(-test.run "$2") && shift 2 ;;
		*) die "test --on ligo1: unknown argument $1" ;;
		esac
	done
	cmd_deploy
	section "Tests on ligo1"
	local uid envs=() line name failed=0
	uid="$(env_get .ligo1.ligo_uid)"
	while IFS= read -r line; do
		envs+=(--env "$line")
	done < <(env_ligo1)
	for name in $(inner_exec ligo1 sh -c "ls $LIGO1_TESTS"); do
		info "$name"
		lxd exec lxd -- lxc exec ligo1 --user "$uid" --cwd "$LIGO1_TESTS" "${envs[@]}" -- \
			"$LIGO1_TESTS/$name" -test.count=1 -test.v "${run[@]}" | sed 's/^/        /' || failed=1
	done
	((failed == 0)) || die "lab tests failed on ligo1"
	info "lab tests passed on ligo1"
}
