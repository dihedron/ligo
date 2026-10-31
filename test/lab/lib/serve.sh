# shellcheck shell=bash
# The ligo service on ligo1: ligo serve as production runs it, against its
# own database (.specs/ligo-test-environment.md, "The ligo service on ligo1").

LIGO1_E2E=/home/ligo/e2e
SERVE_DB=ligo_serve

cmd_serve() {
	require_lab
	inner_exists ligo1 || die "ligo1 does not exist: lab.sh up --scenario identity"
	case "${1:-status}" in
	install) serve_install ;;
	start) inner_exec ligo1 systemctl start ligo && serve_wait ;;
	stop) inner_exec ligo1 systemctl stop ligo ;;
	reload) inner_exec ligo1 systemctl reload ligo ;;
	status) inner_exec ligo1 systemctl --no-pager status ligo || true ;;
	logs) inner_exec ligo1 journalctl --no-pager -u ligo ;;
	test) serve_test ;;
	*) die "serve: install, start, stop, reload, status, logs or test" ;;
	esac
}

# serve_install: the database, then (after deploy, for the plugins) the
# binary, the configuration and the unit; starts ligo and waits for it.
serve_install() {
	section "ligo serve on ligo1"
	serve_db
	# the plugins it runs are rebuilt, and their hashes go into server.yaml
	inner_exec ligo1 systemctl stop ligo 2>/dev/null || true
	cmd_deploy
	local out="$LAB_STATE_DIR/ligo"
	(cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$out" ./cmd/ligo) || die "cannot build ligo"
	inner_push "$out" ligo1 /usr/local/bin/ligo 0755
	inner_exec ligo1 install -d -o root -g ligo -m 0750 /etc/ligo
	serve_config | inner_exec ligo1 sh -c 'cat >/etc/ligo/server.yaml && chown root:ligo /etc/ligo/server.yaml && chmod 0640 /etc/ligo/server.yaml'
	serve_env | inner_exec ligo1 sh -c 'umask 027 && cat >/etc/ligo/ligo.env && chown root:ligo /etc/ligo/ligo.env && chmod 0640 /etc/ligo/ligo.env'
	serve_unit | inner_exec ligo1 sh -c 'cat >/etc/systemd/system/ligo.service'
	inner_exec ligo1 systemctl daemon-reload
	inner_exec ligo1 systemctl enable ligo >/dev/null 2>&1
	inner_exec ligo1 systemctl restart ligo
	serve_wait
	info "ligo serves on ligo1:9443 (database $SERVE_DB)"
	serve_cli_users
}

# CLI_USERS: the users on ligo1 that run the CLI, and their SPIFFE IDs on
# the prod agent (unix:uid only, like the core entry).
CLI_USERS=("ligo-ops ops/olga" "ligo-approver ops/dora")

# serve_cli_users: the users, their entries, and a wait until the agent
# issues each its SVID.
serve_cli_users() {
	local pair user id uid
	for pair in "${CLI_USERS[@]}"; do
		user="${pair%% *}" id="spiffe://prod.lab/${pair#* }"
		inner_exec ligo1 id -u "$user" >/dev/null 2>&1 || inner_exec ligo1 useradd -m -s /bin/bash "$user"
		uid="$(inner_exec ligo1 id -u "$user")"
		spire prod entry show -spiffeID "$id" 2>/dev/null | grep -q "unix:uid:$uid" ||
			spire prod entry create -parentID "spiffe://prod.lab/node/ligo1" -spiffeID "$id" -selector "unix:uid:$uid" >/dev/null ||
			die "cannot register $id"
		for _ in $(seq 1 30); do
			lxd exec lxd -- lxc exec ligo1 --user "$uid" -- "$SPIRE_PREFIX/bin/spire-agent" api fetch x509 \
				-socketPath /run/spire/prod/agent.sock 2>/dev/null | grep -q "SPIFFE ID:.*$id" && break
			sleep 1
		done
		lxd exec lxd -- lxc exec ligo1 --user "$uid" -- "$SPIRE_PREFIX/bin/spire-agent" api fetch x509 \
			-socketPath /run/spire/prod/agent.sock 2>/dev/null | grep -q "SPIFFE ID:.*$id" || die "the prod agent does not issue $id to $user"
		info "CLI user $user on ligo1 holds $id"
	done
}

# cli USER ARGS: runs the ligo CLI on ligo1 as USER (ligo-ops,
# ligo-approver, or ligo for olivia's Basic credentials), against the
# service, with the prod agent's socket.
cli() {
	local user="$1" uid
	shift
	uid="$(inner_exec ligo1 id -u "$user" </dev/null)" # not the caller's stdin: it may be a manifest for ligo
	lxd exec lxd -- lxc exec ligo1 --user "$uid" --cwd /tmp --env LIGO_SERVER_URL=https://ligo1.ligo.lab:9443 \
		--env LIGO_SPIFFE_SOCKET=unix:///run/spire/prod/agent.sock -- /usr/local/bin/ligo "$@"
}

# cli_approve KIND NAME: ligo-approver approves every side of the
# request awaiting it for KIND NAME, until it is applied.
cli_approve() {
	local json id sha side status
	json="$(cli ligo-approver -o json cr list --awaiting-me --kind "$1" --name "$2")" || die "cr list $1 $2"
	id="$(jq -r '.items[0].id // empty' <<<"$json")"
	sha="$(jq -r '.items[0].payloadSha256' <<<"$json")"
	[[ -n "$id" ]] || die "nothing awaits ligo-approver for $1 $2"
	for side in $(jq -r '.items[0].awaitingApproval[]' <<<"$json"); do
		status="$(cli ligo-approver -o json cr approve "$id" --sha256 "$sha" --side "$side" -m e2e | jq -r '.[0].changeRequest.status')" ||
			die "cr approve $id --side $side"
		[[ "$status" == APPLIED ]] && break
	done
	info "CLI: $1 $2 approved ($id, $status)"
}

# cli_phase NAME PHASE: waits until the binding NAME is in PHASE ("" for
# gone).
cli_phase() {
	local phase=""
	for _ in $(seq 1 60); do
		phase="$(cli ligo-ops -o json get binding "$1" 2>/dev/null | jq -r '.status.phase')" || phase=""
		[[ "$phase" == "$2" ]] && return
		sleep 1
	done
	die "binding $1 is ${phase:-gone}, not ${2:-gone}"
}

# serve_cli: the CLI e2e (.specs/ligo-test-environment.md).
serve_cli() {
	section "CLI e2e of ligo serve"
	local x target source binding out revision pw
	x="$(openssl rand -hex 4)" target="e2e-cli-ledger-$x" source="e2e-cli-src-$x" binding="e2e-cli-$x"
	cli ligo-ops apply -f - <<YAML || die "apply the target"
kind: Target
metadata: {name: $target, platform: pg-ledger, scope: dc/corp-prod/ledger}
definition: {database: ledger, schema: ledger}
accessLevels: [{name: read, grants: {roles: [LEDGER_RO_ROLE]}}]
networkFlows: [{name: ledger, purpose: DATA, protocol: TCP, destination: pg.ligo.lab, ports: [5432], tls: true, serverName: pg.ligo.lab}]
visibility: {mode: PRIVATE}
YAML
	cli_approve target "$target"
	out="$(cli ligo-ops apply -f - <<YAML
kind: Source
metadata: {name: $source}
identity:
  trustDomain: prod.lab
  svidRegex: '^spiffe://prod\.lab/ns/cli/sa/w$x\$'
  sampleSpiffeIds: ['spiffe://prod.lab/ns/cli/sa/w$x']
visibility: {mode: PRIVATE}
---
{kind: Binding, name: $binding, source: $source, target: $target, accessLevel: read}
YAML
)" || die "apply the source and its binding"
	grep -q "ligo cr approve" <<<"$out" || die "apply printed no approver command: $out"
	local json
	json="$(cli ligo-approver -o json cr list --awaiting-me --kind binding --name "$binding")" || die "cr list $binding"
	if out="$(cli ligo-approver cr approve "$(jq -r '.items[0].id' <<<"$json")" --sha256 "$(jq -r '.items[0].payloadSha256' <<<"$json")" \
		--side "$(jq -r '.items[0].awaitingApproval[0]' <<<"$json")" -m early 2>&1)"; then
		die "the binding was approved before its source"
	fi
	grep -q dependency-pending <<<"$out" || die "approving the binding early: $out"
	info "CLI: the binding waits for its source (dependency-pending)"
	cli_approve source "$source"
	cli_approve binding "$binding"
	cli_phase "$binding" ACTIVE
	# captured first: grep -q would cut the pipe, which pipefail reports as a failure
	out="$(cli ligo-ops flows "$binding")" || die "flows of $binding"
	grep -q "target:$target" <<<"$out" || die "flows of $binding: $out"
	info "CLI: $binding is ACTIVE, with its flows"
	pw="$LIGO1_E2E/olivia.pw"
	ldap_password olivia | inner_exec ligo1 sh -c "umask 077 && cat >$pw && chown ligo:ligo $pw"
	out="$(cli ligo get binding "$binding" --username olivia --password-file "$pw")" || die "olivia cannot read $binding"
	grep -q "$binding" <<<"$out" || die "olivia reads: $out"
	info "CLI: olivia reads $binding with LDAP Basic credentials"
	revision="$(cli ligo-ops -o json get binding "$binding" | jq -r '.metadata.revision')"
	cli ligo-ops delete binding "$binding" -r "$revision" >/dev/null || die "delete $binding"
	cli_approve binding "$binding"
	cli_phase "$binding" ""
	[[ "$(cli ligo-approver -o json audit verify | jq -r .valid)" == true ]] || die "audit verify"
	info "CLI: $binding revoked and deleted; the audit chain verifies"
}

# serve_db: the database ligo_serve, once, migrated as ligo_migrator from
# the lab host through the proxy.
serve_db() {
	if [[ "$(pg_superuser -tAc "select 1 from pg_database where datname = '$SERVE_DB'")" != 1 ]]; then
		pg_superuser -q -f - <"$LAB_DIR/sql/serve-db.sql" || die "pg: cannot create the database $SERVE_DB"
		info "database $SERVE_DB created"
	fi
	(cd "$REPO_DIR" && LIGO_MIGRATOR_DSN="$(pg_dsn migrator "" "" "$SERVE_DB")" go run ./cmd/ligo migrate) ||
		die "cannot migrate $SERVE_DB"
	info "database $SERVE_DB migrated"
}

# serve_wait: waits until the admin listener accepts connections.
serve_wait() {
	for _ in $(seq 1 60); do
		inner_exec ligo1 ss -Hltn 'sport = :9443' 2>/dev/null | grep -q LISTEN && return
		sleep 1
	done
	inner_exec ligo1 journalctl --no-pager -u ligo -n 30 >&2 || true
	die "ligo does not listen on :9443 after 60s"
}

# serve_env: the unit's environment file: the DSNs of ligo_serve, the LDAP
# bind password, the replica's ID and the lab CA for the Transit client.
serve_env() {
	local role upper
	for role in app reader dbos; do
		upper="$(tr '[:lower:]' '[:upper:]' <<<"$role")"
		printf 'LIGO_%s_DSN=%s\n' "$upper" "$(pg_dsn "$role" pg.ligo.lab /etc/ligo-lab/ca.crt "$SERVE_DB")"
	done
	printf '%s\n' "LIGO_LDAP_BIND_PASSWORD=$(ldap_password ligo-admin-auth)" "LIGO_INSTANCE_ID=ligo1" "SSL_CERT_FILE=/etc/ligo-lab/ca.crt"
}

serve_unit() {
	cat <<'UNIT'
# ligo serve (lab): see .specs/ligo-test-environment.md
[Unit]
Description=ligo, the SPIFFE binding lifecycle service
After=network-online.target spire-agent-prod.service spire-agent-test.service
Wants=network-online.target

[Service]
User=ligo
Group=ligo
EnvironmentFile=/etc/ligo/ligo.env
ExecStart=/usr/local/bin/ligo serve -c /etc/ligo/server.yaml
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
}

# serve_config: server.yaml for the lab, with the deployed plugins' hashes.
serve_config() {
	local aud="https://bao-prod.ligo.lab" bao="https://bao-prod.ligo.lab:$BAO_PORT" tp sv
	tp="$(sha256sum "$LAB_STATE_DIR/plugins/target-postgres" | cut -d' ' -f1)"
	sv="$(sha256sum "$LAB_STATE_DIR/plugins/store-vault" | cut -d' ' -f1)"
	cat <<YAML
# ligo serve on ligo1 (lab), generated by test/lab/lab.sh serve install
service:
  application_version: "lab"
  instance_id_env: LIGO_INSTANCE_ID
  workload_advertise: { destination: "ligo1.ligo.lab", port: 8443, server_name: "ligo1.ligo.lab" }
zones:
  - { name: prod, trust_domain: prod.lab, spiffe_workload_socket: "unix:///run/spire/prod/agent.sock" }
  - { name: test, trust_domain: test.lab, spiffe_workload_socket: "unix:///run/spire/test/agent.sock" }
core_identity:
  zone: prod
  svid_selector: { match_expr: 'path == "/ns/sys/sa/ligo"', jwt_audience: ["$aud"] }
server:
  workload_listener:
    listen_address: "0.0.0.0:8443"
    tls_source: spiffe
    auth_modes: [x509_svid, jwt_svid]
    accepted_trust_domains: [prod.lab]
    expected_jwt_audience: "spiffe://prod.lab/ns/sys/sa/ligo"
  admin_listener:
    listen_address: "0.0.0.0:9443"
    tls_source: spiffe
    client_svid_auth: { enabled: true, accepted_trust_domains: [prod.lab] }
    allow_basic_auth: true
admin_auth:
  ldap:
    url: "$LDAP_URL"
    ca_cert_file: /etc/ligo-lab/ca.crt
    service_bind_dn: "cn=ligo-admin-auth,ou=services,$LDAP_BASE"
    service_bind_password_env: LIGO_LDAP_BIND_PASSWORD
    user_base_dn: "ou=users,$LDAP_BASE"
    user_filter: "(&(objectClass=inetOrgPerson)(uid=%s))"
    group_membership_filter: "(member=%s)"
authorization:
  bindings:
    - { spiffe_id: "spiffe://prod.lab/ops/olga", role: operator, scopes: ["dc/corp-prod/*"] }
    - { spiffe_id: "spiffe://prod.lab/ops/dora", role: approver, scopes: ["dc/corp-prod/*"] }
    - { ldap_group_dn: "cn=ligo-viewers,ou=groups,$LDAP_BASE", role: viewer, scopes: ["*"] }
    - { ldap_group_dn: "cn=ligo-operators-prod,ou=groups,$LDAP_BASE", role: viewer, scopes: ["*"] }
  approval:
    required_scopes: ["dc/corp-prod/*"]
    require_distinct_approvers_across_scopes: false
    change_request_ttl: 72h
governance:
  source_scopes:
    - { trust_domain: prod.lab, mode: static, scope: "dc/corp-prod" }
  interconnects:
    default_cross_scope: deny
    rules:
      - { name: dc-to-apps, from: ["dc/corp-prod"], to: ["dc/corp-prod/*"], action: allow }
break_glass:
  min_justification_length: 20
storage:
  postgres: { app_dsn_env: LIGO_APP_DSN, reader_dsn_env: LIGO_READER_DSN, dbos_dsn_env: LIGO_DBOS_DSN }
secret_sealing:
  provider: vault-transit
  vault_transit: { address: "$bao", auth_mount: jwt-spiffe, role: ligo-sealer, jwt_audience: "$aud", mount: transit, key_name: ligo-interstage }
plugins:
  directory: "$LIGO1_PLUGINS"
identity_providers:
  - type: target-local.v1
    builtin: true
    instances: [ { name: local-prod, zone: prod } ]
secret_stores:
  - type: vault.v1
    binary: store-vault
    sha256: "$sv"
    instances:
      - name: vault-prod
        zone: prod
        svid_selector: { match_expr: 'path == "/ligo/plugin/store-vault"', jwt_audience: ["$aud"] }
        config:
          address: "$bao"
          auth_mount: jwt-spiffe
          role: ligo-plugin-store-vault
          db_connection: lab-pg
          ca_file: /etc/ligo-lab/ca.crt
          allowed_endpoints: ["bao-prod.ligo.lab:$BAO_PORT"]
        network_flows:
          - { name: vault, purpose: CREDENTIALS, protocol: TCP, destination: "bao-prod.ligo.lab", ports: [$BAO_PORT], tls: true, server_name: "bao-prod.ligo.lab" }
platform_providers:
  - type: postgres.v1
    binary: target-postgres
    sha256: "$tp"
    platforms:
      - name: pg-ledger
        zone: prod
        scope: "dc/corp-prod"
        display_name: "Lab PostgreSQL ledger"
        allowed_source_trust_domains: [prod.lab]
        network_flows:
          - { name: postgres, purpose: DATA, protocol: TCP, destination: "pg.ligo.lab", ports: [5432], tls: true, server_name: "pg.ligo.lab" }
        identity_provider: { type: target-local.v1, instance: local-prod }
        secret_store: { type: vault.v1, instance: vault-prod, secret_storage_strategy: vault-static }
        svid_selector: { match_expr: 'path == "/ligo/plugin/target-postgres"', jwt_audience: ["$aud"] }
        config:
          host: pg.ligo.lab
          port: 5432
          database: ledger
          grantable_roles: [LEDGER_RO_ROLE, LEDGER_RW_ROLE]
          ca_file: /etc/ligo-lab/ca.crt
          allowed_endpoints: ["pg.ligo.lab:5432"]
          bootstrap_credential:
            source: vault
            address: "$bao"
            auth_mount: jwt-spiffe
            role: ligo-plugin-target-postgres
            jwt_audience: "$aud"
            kv_path: kv/data/ligo/bootstrap/target-postgres
YAML
}

# serve_admins: mints on spire-prod, for one hour, with the prod.lab bundle,
# into ligo1:$LIGO1_E2E for the user ligo: the X.509-SVIDs of olga
# (operator) and dora (approver), and of the e2e's workload w$E2E_SUFFIX,
# which its source matches, and v$E2E_SUFFIX, which it does not; and a
# JWT-SVID of the workload for ligo's workload listener, within its
# max_token_ttl.
serve_admins() {
	local who dir="/root/e2e" f
	local -A ids=([olga]=ops/olga [dora]=ops/dora [workload]="ns/e2e/sa/w$E2E_SUFFIX" [stranger]="ns/e2e/sa/v$E2E_SUFFIX")
	inner_exec spire-prod sh -c "rm -rf $dir && mkdir -m 0700 $dir"
	for who in "${!ids[@]}"; do
		inner_exec spire-prod mkdir -m 0700 "$dir/$who"
		spire prod x509 mint -spiffeID "spiffe://prod.lab/${ids[$who]}" -ttl 1h -write "$dir/$who" >/dev/null 2>&1 ||
			die "spire-prod: cannot mint the SVID of $who"
	done
	inner_exec ligo1 sh -c "rm -rf $LIGO1_E2E && install -d -o ligo -g ligo -m 0700 $LIGO1_E2E"
	for who in "${!ids[@]}"; do
		for f in svid.pem key.pem bundle.pem; do
			inner_exec spire-prod cat "$dir/$who/$f" | inner_exec ligo1 sh -c "cat >$LIGO1_E2E/$who-$f && chown ligo:ligo $LIGO1_E2E/$who-$f && chmod 0600 $LIGO1_E2E/$who-$f"
		done
	done
	spire prod jwt mint -spiffeID "spiffe://prod.lab/${ids[workload]}" -audience "spiffe://prod.lab/ns/sys/sa/ligo" -ttl 10m |
		inner_exec ligo1 sh -c "tr -d '\n' >$LIGO1_E2E/workload-jwt && chown ligo:ligo $LIGO1_E2E/workload-jwt && chmod 0600 $LIGO1_E2E/workload-jwt" ||
		die "spire-prod: cannot mint the JWT-SVID of the workload"
	inner_exec spire-prod rm -rf "$dir"
}

# serve_e2e RUN: runs the e2e tests matching RUN as the user ligo on ligo1.
serve_e2e() {
	local uid envs=() line
	uid="$(env_get .ligo1.ligo_uid)"
	while IFS= read -r line; do
		envs+=(--env "$line")
	done < <(env_ligo1)
	envs+=(--env "LIGO_E2E_ADMIN=https://ligo1.ligo.lab:9443" --env "LIGO_E2E_WORKLOAD=https://ligo1.ligo.lab:8443" --env "LIGO_E2E_DIR=$LIGO1_E2E"
		--env "LIGO_E2E_SUFFIX=$E2E_SUFFIX")
	lxd exec lxd -- lxc exec ligo1 --user "$uid" --cwd "$LIGO1_TESTS" "${envs[@]}" -- \
		"$LIGO1_TESTS/internal_command_serve.test" -test.count=1 -test.v -test.run "$1" | sed 's/^/        /'
}

# serve_test: the e2e of the service, with the lifecycle checks between its
# two halves (.specs/ligo-test-environment.md).
serve_test() {
	deploy_tests # not the plugins: the running service holds them, and server.yaml their hashes
	section "e2e of ligo serve"
	E2E_SUFFIX="$(openssl rand -hex 4)"
	serve_admins
	serve_e2e '^TestServeE2EApply$' || die "TestServeE2EApply failed"
	serve_e2e '^TestServeE2EWorkload$' || die "TestServeE2EWorkload failed"
	local since
	since="$(inner_exec ligo1 date '+%Y-%m-%d %H:%M:%S')"
	inner_exec ligo1 systemctl reload ligo
	sleep 2
	inner_exec ligo1 journalctl --no-pager -u ligo --since "$since" | grep -q "SIGHUP: directory CA reloaded" ||
		die "reload: the journal does not show the directory CA reload"
	info "reload: the directory CA was reloaded"
	since="$(inner_exec ligo1 date '+%Y-%m-%d %H:%M:%S')"
	local start end
	start="$(date +%s)"
	inner_exec ligo1 systemctl stop ligo
	end="$(date +%s)"
	inner_exec ligo1 journalctl --no-pager -u ligo --since "$since" | grep -q '"msg":"shutting down"' ||
		die "stop: the journal does not show the drain"
	[[ "$(inner_exec ligo1 systemctl show -p ExecMainStatus --value ligo)" == 0 ]] || die "stop: ligo exited with a failure"
	((end - start <= 30)) || die "stop: took $((end - start))s"
	info "stop: drained and exited 0 in $((end - start))s"
	inner_exec ligo1 systemctl start ligo
	serve_wait
	info "start: ligo serves again"
	serve_e2e '^TestServeE2ERestarted$' || die "TestServeE2ERestarted failed"
	serve_cli
	info "e2e of ligo serve passed"
}
