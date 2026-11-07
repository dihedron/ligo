# shellcheck shell=bash
# Tests that need SVIDs run on a ligo host (ligo1, and ligo2 with ha) as the
# user ligo: deploy builds them on the lab host and copies them to every ligo
# host; "test --on HOST" runs them there (.specs/ligo-test-environment.md,
# "Tests on ligo1").

LIGO_TESTS=/home/ligo/tests

# LIGO_PLUGINS is the ligo hosts' plugins.directory; LAB_PLUGINS are the lab's
# plugins (test/lab/plugins), in the zone prod. A plugin's binary is
# ligo-plugin-<backend>; its SPIFFE path, hint and bootstrap use <backend>.
# ligo-plugin-openldap is the shipped one, from cmd/plugins.
LIGO_PLUGINS=/usr/lib/ligo/plugins
LAB_PLUGINS=(labprobe ligo-plugin-postgres ligo-plugin-vault ligo-plugin-echo ligo-plugin-openldap)

# lab_packages: the packages with tests built with the lab tag.
lab_packages() {
	(cd "$REPO_DIR" && grep -rlE '^//go:build .*\blab\b' --include='*_test.go' . | xargs -r -n1 dirname | sort -u)
}

# env_ligo: the environment of the tests on a ligo host: the database
# directly (pg.ligo.lab), ligo's Workload API sockets, the secrets backend and LDAP, and
# the lab CA copied to the host.
env_ligo() {
	local role upper
	for role in migrator app reader dbos; do
		upper="$(tr '[:lower:]' '[:upper:]' <<<"$role")"
		printf 'LIGO_TEST_PG_%s_DSN=%s\n' "$upper" "$(pg_dsn "$role" pg.ligo.lab /etc/ligo-lab/ca.crt)"
	done
	printf '%s\n' \
		"LIGO_TEST_CA=/etc/ligo-lab/ca.crt" \
		"LIGO_TEST_SPIRE_PROD_SOCKET=unix:///run/spire/prod/agent.sock" \
		"LIGO_TEST_SPIRE_TEST_SOCKET=unix:///run/spire/test/agent.sock" \
		"LIGO_TEST_SECRETS_PROD_ADDR=$(secrets_addr)" \
		"LIGO_TEST_SECRETS_PROD_AUDIENCE=$(secrets_audience)" \
		"LIGO_TEST_LDAP_URL=$LDAP_URL" \
		"LIGO_TEST_LDAP_BASE=$LDAP_BASE" \
		"LIGO_TEST_LDAP_BIND_PASS=$(ldap_password ligo-admin-auth)" \
		"LIGO_TEST_LDAP_OLIVIA_PASS=$(ldap_password olivia)" \
		"LIGO_TEST_LDAP_LIVIA_PASS=$(ldap_password livia)" \
		"LIGO_TEST_LDAP_IDP_PASS=$(ldap_password ligo-idp)" \
		"LIGO_TEST_TARGET_ADMIN_PASS=$(password target-admin)" \
		"LIGO_TEST_PLUGIN_DIR=$LIGO_PLUGINS"
	local name
	for name in amy alan anne pat gus gail ivan sue; do
		printf 'LIGO_TEST_LDAP_%s_PASS=%s\n' "$(tr '[:lower:]' '[:upper:]' <<<"$name")" "$(ldap_password "$name")"
	done
	for name in "${LAB_PLUGINS[@]}"; do
		[[ -f "$LAB_STATE_DIR/plugins/$name" ]] &&
			echo "LIGO_TEST_$(tr '[:lower:]-' '[:upper:]_' <<<"${name#ligo-plugin-}")_SHA256=$(sha256sum "$LAB_STATE_DIR/plugins/$name" | cut -d' ' -f1)"
	done
	return 0
}

# cmd_deploy: the lab tests and the plugins.
cmd_deploy() {
	deploy_tests
	deploy_plugins
}

# deploy_tests: builds the lab tests (static, linux/amd64) and copies them to
# every ligo host, owned by ligo.
deploy_tests() {
	require_lab
	inner_exists ligo1 || die "ligo1 does not exist: lab.sh up --scenario identity"
	section "Deploy"
	local out="$LAB_STATE_DIR/tests" pkg name host
	rm -rf "${out:?}" && mkdir -p "$out"
	for pkg in $(lab_packages); do
		name="$(tr '/' '_' <<<"${pkg#./}").test"
		(cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags 'integration lab' -o "$out/$name" "$pkg") ||
			die "cannot build the tests of $pkg"
		info "built $pkg"
	done
	for host in $(ligo_hosts); do
		inner_exec "$host" sh -c "rm -rf $LIGO_TESTS && install -d -o ligo -g ligo $LIGO_TESTS /etc/ligo-lab"
		inner_push "$LAB_STATE_DIR/pki/ca.crt" "$host" /etc/ligo-lab/ca.crt 0644
		for name in "$out"/*.test; do
			inner_push "$name" "$host" "$LIGO_TESTS/${name##*/}" 0755
		done
		inner_exec "$host" chown -R ligo:ligo "$LIGO_TESTS"
		info "copied $(find "$out" -name '*.test' | wc -l) test binaries to $host:$LIGO_TESTS"
	done
}

# deploy_plugins: builds the lab plugins and installs them on every ligo
# host as production expects (root:root, 0755, §5.3 rule 3); then registers
# each plugin's SPIRE entry under each host's node alias, which selects on its
# hash, and its objects on the secrets backend. Both change with every build, so every deploy
# applies them.
deploy_plugins() {
	local out="$LAB_STATE_DIR/plugins" uid name sum host
	rm -rf "${out:?}" && mkdir -p "$out"
	for name in "${LAB_PLUGINS[@]}"; do
		local src="./test/lab/plugins/$name"
		[[ -d "$REPO_DIR/cmd/plugins/$name" ]] && src="./cmd/plugins/$name"
		(cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$out/$name" "$src") ||
			die "cannot build the plugin $name"
	done
	for host in $(ligo_hosts); do
		uid="$(env_get ".$host.ligo_uid")"
		if inner_exec "$host" systemctl -q is-active ligo 2>/dev/null; then
			inner_exec "$host" systemctl stop ligo
			warn "the ligo service on $host is stopped: its plugins are replaced; lab.sh serve install starts it again"
		fi
		inner_exec "$host" install -d -o root -g root -m 0755 /usr/lib/ligo "$LIGO_PLUGINS"
		for name in "${LAB_PLUGINS[@]}"; do
			inner_push "$out/$name" "$host" "$LIGO_PLUGINS/$name" 0755
			sum="$(sha256sum "$out/$name" | cut -d' ' -f1)"
			plugin_entry prod "ligo/plugin/${name#ligo-plugin-}" "${name#ligo-plugin-}-prod" "$uid" "$sum" "$host"
			plugin_svid_wait prod "$name" "$uid" "$host"
			info "plugin $name installed in $host:$LIGO_PLUGINS (sha256 ${sum:0:12}…); the agent issues its SVID, selected by that hash"
		done
	done
	pg_target
	plugin_bao labprobe lab-admin "$LAB_STATE_DIR/passwords/labprobe"
	plugin_bao postgres lab_target_admin "$LAB_STATE_DIR/passwords/target-admin"
	ldap_password ligo-idp >/dev/null
	plugin_bao openldap "cn=ligo-idp,ou=services,$LDAP_BASE" "$LAB_STATE_DIR/passwords/ldap-ligo-idp"
	store_vault_bao
}

# store_vault_bao: on the secrets backend, the database secrets engine and its
# connection lab-pg to the database ledger, the ligo-plugin-vault plugin's role and
# policy, and the lab-only role the tests check its work with
# (.specs/ligo-test-environment.md, ligo-plugin-vault).
store_vault_bao() {
	local server aud
	server="$(secrets_host)" aud="$(secrets_audience)"
	secrets_cli secrets list -format=json | jq -e '."database/"' >/dev/null || secrets_cli secrets enable database >/dev/null
	# the password goes through stdin, never on a command line
	tr -d "\n" <"$LAB_STATE_DIR/passwords/target-admin" | secrets_cli write database/config/lab-pg \
		plugin_name=postgresql-database-plugin allowed_roles="binding-*" username=lab_target_admin password=- \
		connection_url="postgresql://{{username}}:{{password}}@pg.ligo.lab:5432/ledger?sslmode=verify-full&sslrootcert=$(server_ca "$server")" \
		>/dev/null || die "$server: cannot configure the database connection lab-pg"
	inner_exec "$server" sh -c 'cat >/root/ligo-plugin-vault.hcl' <<'HCL'
# ligo-plugin-vault: the objects it keeps per binding, and nothing else
path "kv/data/bindings/*" {
  capabilities = ["create", "update", "read"]
}
path "kv/metadata/bindings/*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "sys/policies/acl/binding-*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "database/roles/binding-*" {
  capabilities = ["create", "update", "read", "delete"]
}
path "sys/leases/revoke-prefix/database/creds/binding-*" {
  capabilities = ["update", "sudo"]
}
path "auth/jwt-spiffe/role/binding-*" {
  capabilities = ["create", "update", "read", "delete"]
  allowed_parameters = {
    "token_policies" = ["binding-*"]
    "*" = []
  }
}
HCL
	secrets_cli policy write ligo-plugin-vault /root/ligo-plugin-vault.hcl >/dev/null
	secrets_cli write auth/jwt-spiffe/role/ligo-plugin-vault role_type=jwt user_claim=sub \
		bound_subject="spiffe://prod.lab/ligo/plugin/vault" bound_audiences="$aud" \
		token_policies=ligo-plugin-vault token_ttl=15m token_max_ttl=1h >/dev/null ||
		die "$server: cannot write the role ligo-plugin-vault"
	inner_exec "$server" sh -c 'cat >/root/lab-standins-check.hcl' <<'HCL'
# lab only: the tests read what ligo-plugin-vault wrote, and the target admin's
# credential, to cause drift that reconciliation repairs
path "kv/data/bindings/*" {
  capabilities = ["read"]
}
path "kv/data/ligo/bootstrap/postgres" {
  capabilities = ["read"]
}
path "database/creds/binding-*" {
  capabilities = ["read"]
}
HCL
	secrets_cli policy write lab-standins-check /root/lab-standins-check.hcl >/dev/null
	secrets_cli write auth/jwt-spiffe/role/lab-standins-check role_type=jwt user_claim=sub \
		bound_subject="spiffe://prod.lab/ns/sys/sa/ligo" bound_audiences="$aud" \
		token_policies=lab-standins-check token_ttl=5m token_max_ttl=15m >/dev/null ||
		die "$server: cannot write the role lab-standins-check"
}

# plugin_svid_wait ZONE NAME UID HOST: waits until the zone's agent on HOST
# issues the plugin's SVID to the plugin's binary run as the user ligo (a new
# entry reaches the agents at their next sync); the binary asks the agent
# itself, so the agent attests exactly what it will attest for the plugin.
plugin_svid_wait() {
	local zone="$1" name="$2" uid="$3" host="$4"
	for _ in $(seq 1 30); do
		lxd exec lxd -- lxc exec "$host" --user "$uid" -- "$LIGO_PLUGINS/$name" -svids "unix:///run/spire/$zone/agent.sock" 2>/dev/null |
			grep -qx "spiffe://$zone.lab/ligo/plugin/${name#ligo-plugin-}" && return
		sleep 1
	done
	die "the $zone agent on $host does not issue the SVID of the plugin $name after 30s (uid $uid)"
}

# plugin_entry ZONE PATH HINT UID SHA256 HOST: the plugin's entry under
# HOST's node alias, replaced when the binary's hash changed.
plugin_entry() {
	local zone="$1" id="spiffe://$1.lab/$2" hint="$3" uid="$4" sum="$5" parent="spiffe://$1.lab/node/$6" entry out
	# captured first: grep -q would cut the pipe, which pipefail reports as a failure
	out="$(spire "$zone" entry show -parentID "$parent" -spiffeID "$id" 2>/dev/null)" || true
	grep -q "unix:sha256:$sum" <<<"$out" && return
	for entry in $(awk '/^Entry ID/ {print $4}' <<<"$out"); do
		spire "$zone" entry delete -entryID "$entry" >/dev/null
	done
	spire "$zone" entry create -parentID "$parent" -spiffeID "$id" -hint "$hint" \
		-selector "unix:uid:$uid" -selector "unix:sha256:$sum" >/dev/null || die "cannot register $id"
}

# plugin_bao NAME USER PASSWORD_FILE: on the secrets backend, the plugin's bootstrap
# credential (USER and the password in PASSWORD_FILE, created if missing),
# the policy that reads it and the JWT role of the plugin's SVID.
plugin_bao() {
	local name="$1" user="$2" file="$3" server aud
	server="$(secrets_host)" aud="$(secrets_audience)"
	[[ -f "$file" ]] || (umask 077 && openssl rand -hex 16 >"$file")
	# the password goes through stdin, never on a command line
	tr -d "\n" <"$file" | secrets_cli kv put -mount=kv "ligo/bootstrap/$name" username="$user" password=- >/dev/null ||
		die "$server: cannot write the bootstrap credential of $name"
	inner_exec "$server" sh -c "cat >/root/ligo-plugin-$name.hcl" <<HCL
# the bootstrap credential of $name, read only
path "kv/data/ligo/bootstrap/$name" {
  capabilities = ["read"]
}
HCL
	secrets_cli policy write "ligo-plugin-$name" "/root/ligo-plugin-$name.hcl" >/dev/null
	secrets_cli write "auth/jwt-spiffe/role/ligo-plugin-$name" role_type=jwt user_claim=sub \
		bound_subject="spiffe://prod.lab/ligo/plugin/$name" bound_audiences="$aud" \
		token_policies="ligo-plugin-$name" token_ttl=15m token_max_ttl=1h >/dev/null ||
		die "$server: cannot write the role ligo-plugin-$name"
}

# test_on HOST [-run REGEX]: deploys, then runs the lab tests (TestLab*, or
# REGEX) of every lab test binary on HOST as the user ligo; fails if any
# fails.
test_on() {
	local host="$1" run=(-test.run '^TestLab')
	shift
	while (($#)); do
		case "$1" in
		-run) run=(-test.run "$2") && shift 2 ;;
		*) die "test --on $host: unknown argument $1" ;;
		esac
	done
	cmd_deploy
	section "Tests on $host"
	local uid envs=() line name failed=0
	uid="$(env_get ".$host.ligo_uid")"
	while IFS= read -r line; do
		envs+=(--env "$line")
	done < <(env_ligo)
	for name in $(inner_exec "$host" sh -c "ls $LIGO_TESTS"); do
		info "$name"
		lxd exec lxd -- lxc exec "$host" --user "$uid" --cwd "$LIGO_TESTS" "${envs[@]}" -- \
			"$LIGO_TESTS/$name" -test.count=1 -test.v "${run[@]}" | sed 's/^/        /' || failed=1
	done
	((failed == 0)) || die "lab tests failed on $host"
	info "lab tests passed on $host"
}
