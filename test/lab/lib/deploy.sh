# shellcheck shell=bash
# Tests that need SVIDs run on ligo1, the ligo host, as the user ligo: deploy
# builds them on the lab host and copies them there; "test --on ligo1" runs
# them (.specs/ligo-test-environment.md, "Tests on ligo1").

LIGO1_TESTS=/home/ligo/tests

# LIGO1_PLUGINS is ligo1's plugins.directory; LAB_PLUGINS are the lab's
# plugins (test/lab/plugins), in the zone prod.
LIGO1_PLUGINS=/usr/lib/ligo/plugins
LAB_PLUGINS=(labprobe target-postgres)

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
		"LIGO_TEST_LDAP_BASE=$LDAP_BASE" \
		"LIGO_TEST_PLUGIN_DIR=$LIGO1_PLUGINS"
	local name
	for name in "${LAB_PLUGINS[@]}"; do
		[[ -f "$LAB_STATE_DIR/plugins/$name" ]] &&
			echo "LIGO_TEST_$(tr '[:lower:]-' '[:upper:]_' <<<"$name")_SHA256=$(sha256sum "$LAB_STATE_DIR/plugins/$name" | cut -d' ' -f1)"
	done
	return 0
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
	deploy_plugins
}

# deploy_plugins: builds the lab plugins and installs them on ligo1 as
# production expects (root:root, 0755, §5.3 rule 3); then registers each
# plugin's SPIRE entry, which selects on its hash, and its OpenBao objects.
# Both change with every build, so every deploy applies them.
deploy_plugins() {
	local out="$LAB_STATE_DIR/plugins" uid name sum
	rm -rf "${out:?}" && mkdir -p "$out"
	uid="$(env_get .ligo1.ligo_uid)"
	inner_exec ligo1 install -d -o root -g root -m 0755 /usr/lib/ligo "$LIGO1_PLUGINS"
	for name in "${LAB_PLUGINS[@]}"; do
		(cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$out/$name" "./test/lab/plugins/$name") ||
			die "cannot build the plugin $name"
		inner_push "$out/$name" ligo1 "$LIGO1_PLUGINS/$name" 0755
		sum="$(sha256sum "$out/$name" | cut -d' ' -f1)"
		plugin_entry prod "ligo/plugin/$name" "$name-prod" "$uid" "$sum"
		plugin_svid_wait prod "$name" "$uid"
		info "plugin $name installed in ligo1:$LIGO1_PLUGINS (sha256 ${sum:0:12}…); the agent issues its SVID, selected by that hash"
	done
	pg_target
	plugin_bao labprobe lab-admin "$LAB_STATE_DIR/passwords/labprobe"
	plugin_bao target-postgres lab_target_admin "$LAB_STATE_DIR/passwords/target-admin"
}

# plugin_svid_wait ZONE NAME UID: waits until the zone's agent issues the
# plugin's SVID to the plugin's binary run as the user ligo (a new entry
# reaches the agents at their next sync); the binary asks the agent itself,
# so the agent attests exactly what it will attest for the plugin.
plugin_svid_wait() {
	local zone="$1" name="$2" uid="$3"
	for _ in $(seq 1 30); do
		lxd exec lxd -- lxc exec ligo1 --user "$uid" -- "$LIGO1_PLUGINS/$name" -svids "unix:///run/spire/$zone/agent.sock" 2>/dev/null |
			grep -qx "spiffe://$zone.lab/ligo/plugin/$name" && return
		sleep 1
	done
	die "the $zone agent does not issue the SVID of the plugin $name after 30s (uid $uid)"
}

# plugin_entry ZONE PATH HINT UID SHA256: the plugin's entry under ligo1's
# node alias, replaced when the binary's hash changed.
plugin_entry() {
	local zone="$1" id="spiffe://$1.lab/$2" hint="$3" uid="$4" sum="$5" entry
	spire "$zone" entry show -spiffeID "$id" 2>/dev/null | grep -q "unix:sha256:$sum" && return
	for entry in $(spire "$zone" entry show -spiffeID "$id" 2>/dev/null | awk '/^Entry ID/ {print $4}'); do
		spire "$zone" entry delete -entryID "$entry" >/dev/null
	done
	spire "$zone" entry create -parentID "spiffe://$zone.lab/node/ligo1" -spiffeID "$id" -hint "$hint" \
		-selector "unix:uid:$uid" -selector "unix:sha256:$sum" >/dev/null || die "cannot register $id"
}

# plugin_bao NAME USER PASSWORD_FILE: on bao-prod, the plugin's bootstrap
# credential (USER and the password in PASSWORD_FILE, created if missing),
# the policy that reads it and the JWT role of the plugin's SVID.
plugin_bao() {
	local name="$1" user="$2" file="$3"
	[[ -f "$file" ]] || (umask 077 && openssl rand -hex 16 >"$file")
	# the password goes through stdin, never on a command line
	tr -d "\n" <"$file" | bao prod kv put -mount=kv "ligo/bootstrap/$name" username="$user" password=- >/dev/null ||
		die "bao-prod: cannot write the bootstrap credential of $name"
	inner_exec bao-prod sh -c "cat >/root/ligo-plugin-$name.hcl" <<HCL
# the bootstrap credential of $name, read only
path "kv/data/ligo/bootstrap/$name" {
  capabilities = ["read"]
}
HCL
	bao prod policy write "ligo-plugin-$name" "/root/ligo-plugin-$name.hcl" >/dev/null
	bao prod write "auth/jwt-spiffe/role/ligo-plugin-$name" role_type=jwt user_claim=sub \
		bound_subject="spiffe://prod.lab/ligo/plugin/$name" bound_audiences="https://bao-prod.ligo.lab" \
		token_policies="ligo-plugin-$name" token_ttl=15m token_max_ttl=1h >/dev/null ||
		die "bao-prod: cannot write the role ligo-plugin-$name"
}

# test_ligo1 [-run REGEX]: deploys, then runs the lab tests (TestLab*, or
# REGEX) of every lab test binary on ligo1 as the user ligo; fails if any
# fails.
test_ligo1() {
	local run=(-test.run '^TestLab')
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
