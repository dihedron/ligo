# shellcheck shell=bash
# The ligo service on every ligo host (ligo1, and ligo2 with ha): ligo serve
# as production runs it, the replicas sharing one database
# (.specs/ligo-test-environment.md, "The ligo service on ligo1" and "The
# second replica ligo2").

LIGO1_E2E=/home/ligo/e2e
LIGO_E2E_SECRETS=/home/ligo/e2e-secrets # outside LIGO1_E2E, which serve_admins empties
SERVE_DB=ligo_serve
LAB_ACCOUNTS="" # non-empty: server.yaml with governance.accounts (serve_test_accounts)

# cmd_serve [--on HOST|all] ACTION: start, stop, reload, status and logs act
# on HOST or on every ligo host (all, the default); install and test always
# act on every one, since the plugins they deploy are shared.
cmd_serve() {
	require_lab
	inner_exists ligo1 || die "ligo1 does not exist: lab.sh up --scenario identity"
	local hosts host
	hosts="$(ligo_hosts | xargs)"
	if [[ "${1:-}" == --on ]]; then
		[[ "${2:-}" == all ]] || { ligo_host "${2:-}" && hosts="$2"; }
		shift 2
	fi
	case "${1:-status}" in
	install) serve_install ;;
	test) serve_test ;;
	test-ha) serve_test_ha ;;
	test-otel) serve_test_otel ;;
	test-webhook) serve_test_webhook ;;
	test-faults) serve_test_faults ;;
	test-accounts) serve_test_accounts ;;
	test-accounts-chaos) serve_test_accounts_chaos ;;
	start | stop | reload | status | logs)
		for host in $hosts; do
			case "$1" in
			start) inner_exec "$host" systemctl start ligo && serve_wait "$host" ;;
			stop) inner_exec "$host" systemctl stop ligo ;;
			reload) inner_exec "$host" systemctl reload ligo ;;
			status) inner_exec "$host" systemctl --no-pager status ligo || true ;;
			logs) inner_exec "$host" journalctl --no-pager -u ligo ;;
			esac
		done
		;;
	*) die "serve: install, start, stop, reload, status, logs, test, test-ha, test-otel, test-webhook, test-faults, test-accounts or test-accounts-chaos" ;;
	esac
}

# serve_install: the database, then (after deploy, for the plugins) the
# binary, the configuration and the unit on every ligo host; starts ligo
# there and waits for it.
serve_install() {
	section "ligo serve on $(ligo_hosts | xargs)"
	serve_db
	local host
	# the plugins it runs are rebuilt, and their hashes go into server.yaml
	for host in $(ligo_hosts); do
		inner_exec "$host" systemctl stop ligo 2>/dev/null || true
	done
	cmd_deploy
	local out="$LAB_STATE_DIR/ligo"
	(cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$out" ./cmd/ligo) || die "cannot build ligo"
	for host in $(ligo_hosts); do
		inner_push "$out" "$host" /usr/local/bin/ligo 0755
		inner_exec "$host" install -d -o root -g ligo -m 0750 /etc/ligo
		serve_config "$host" | inner_exec "$host" sh -c 'cat >/etc/ligo/server.yaml && chown root:ligo /etc/ligo/server.yaml && chmod 0640 /etc/ligo/server.yaml'
		serve_env "$host" | inner_exec "$host" sh -c 'umask 027 && cat >/etc/ligo/ligo.env && chown root:ligo /etc/ligo/ligo.env && chmod 0640 /etc/ligo/ligo.env'
		serve_unit | inner_exec "$host" sh -c 'cat >/etc/systemd/system/ligo.service'
		inner_exec "$host" systemctl daemon-reload
		inner_exec "$host" systemctl enable ligo >/dev/null 2>&1
		inner_exec "$host" systemctl restart ligo
		serve_wait "$host"
		info "ligo serves on $host:9443 (database $SERVE_DB, executor $host)"
		serve_proxy "$host"
	done
	serve_cli_users
}

# ui_port HOST: the lab VM's port that publishes HOST's admin listener:
# 9443 for ligo1, 9444 for ligo2.
ui_port() { printf '%d' $((9442 + ${1#ligo})); }

# serve_proxy HOST: HOST's admin listener, and with it the web UI, on the lab
# VM's address, as pg's proxy publishes PostgreSQL (.specs/ligo-echo-target.md).
serve_proxy() {
	local host="$1" port
	port="$(ui_port "$host")"
	if ! inner config device get "$host" admin-ui type >/dev/null 2>&1; then
		inner config device add "$host" admin-ui proxy nat=true \
			listen="tcp:$(lxd_ip):$port" connect="tcp:$(inner_ip "$host"):9443" >/dev/null ||
			die "cannot publish $host:9443 on the lab VM"
	fi
	info "the web UI of $host is at https://$(lxd_ip):$port/ui/login (ligo's SVID: the browser warns once)"
}

# CLI_USERS: the users on ligo1 that run the CLI, and their SPIFFE IDs on
# the prod agent (unix:uid only, like the core entry).
CLI_USERS=("ligo-ops ops/olga" "ligo-approver ops/dora")

# serve_cli_users: the CLI users and their SVIDs.
serve_cli_users() {
	local pair
	for pair in "${CLI_USERS[@]}"; do
		ligo1_user "${pair%% *}" "spiffe://prod.lab/${pair#* }"
		info "CLI user ${pair%% *} on ligo1 holds spiffe://prod.lab/${pair#* }"
	done
}

# ligo1_user USER ID: host_user on ligo1.
ligo1_user() { host_user ligo1 "$@"; }

# host_user HOST USER ID: the user on HOST, its entry under the node alias
# (unix:uid only), and a wait until the prod agent issues it ID.
host_user() {
	local host="$1" user="$2" id="$3" uid out parent="spiffe://prod.lab/node/$1"
	inner_exec "$host" id -u "$user" >/dev/null 2>&1 || inner_exec "$host" useradd -m -s /bin/bash "$user"
	uid="$(inner_exec "$host" id -u "$user")"
	# captured first: grep -q would cut the pipe, which pipefail reports as a failure
	out="$(spire prod entry show -parentID "$parent" -spiffeID "$id" 2>/dev/null)" || true
	grep -q "unix:uid:$uid" <<<"$out" ||
		spire prod entry create -parentID "$parent" -spiffeID "$id" -selector "unix:uid:$uid" >/dev/null ||
		die "cannot register $id"
	for _ in $(seq 1 30); do
		out="$(lxd exec lxd -- lxc exec "$host" --user "$uid" -- "$SPIRE_PREFIX/bin/spire-agent" api fetch x509 \
			-socketPath /run/spire/prod/agent.sock 2>/dev/null)" || true
		grep -q "SPIFFE ID:.*$id" <<<"$out" && return
		sleep 1
	done
	die "the prod agent does not issue $id to $user"
}

# CLI_SERVER: the admin listener the CLI calls; CLI_HOST: where the CLI runs.
CLI_SERVER=ligo1.ligo.lab
CLI_HOST=ligo1

# cli USER ARGS: runs the ligo CLI on CLI_HOST as USER (ligo-ops,
# ligo-approver, or ligo for olivia's Basic credentials), against the
# service at CLI_SERVER, with the prod agent's socket.
cli() {
	local user="$1" uid
	shift
	uid="$(inner_exec "$CLI_HOST" id -u "$user" </dev/null)" # not the caller's stdin: it may be a manifest for ligo
	lxd exec lxd -- lxc exec "$CLI_HOST" --user "$uid" --cwd /tmp --env "LIGO_SERVER_URL=https://$CLI_SERVER:9443" \
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

# serve_cli: the CLI e2e (.specs/ligo-test-environment.md), against
# CLI_SERVER.
serve_cli() {
	section "CLI e2e of ligo serve ($CLI_SERVER)"
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

# serve_wait HOST: waits until HOST's admin listener accepts connections.
serve_wait() {
	local host="$1" out
	for _ in $(seq 1 60); do
		# captured first: grep -q would cut the pipe, which pipefail reports as a failure
		out="$(inner_exec "$host" ss -Hltn 'sport = :9443' 2>/dev/null)" || true
		grep -q LISTEN <<<"$out" && return
		sleep 1
	done
	inner_exec "$host" journalctl --no-pager -u ligo -n 30 >&2 || true
	die "ligo on $host does not listen on :9443 after 60s"
}

# serve_env HOST: the unit's environment file: the DSNs of ligo_serve, the
# LDAP bind password and the replica's ID, HOST (its DBOS executor ID).
serve_env() {
	local host="$1"
	local role upper
	for role in app reader dbos; do
		upper="$(tr '[:lower:]' '[:upper:]' <<<"$role")"
		printf 'LIGO_%s_DSN=%s\n' "$upper" "$(pg_dsn "$role" pg.ligo.lab /etc/ligo-lab/ca.crt "$SERVE_DB")"
	done
	printf '%s\n' "LIGO_LDAP_BIND_PASSWORD=$(ldap_password ligo-admin-auth)" "LIGO_INSTANCE_ID=$host"
	hooks_env
}

# serve_unit: the unit the package ships, for the binary where the lab puts it.
serve_unit() { sed 's|^ExecStart=/usr/bin/ligo |ExecStart=/usr/local/bin/ligo |' "$REPO_DIR/packaging/ligo.service"; }

# With LAB_ACCOUNTS, prod.lab's sources belong to accounts, so that a workload
# can read its credential from the store (.specs/ligo-tenancy.md §9.4), and the
# root is tenants/ because cloud/fin-01, of the topologies, breaks the account
# grammar. The two forms exclude each other, as a trust domain has one extractor.
serve_prod_scope() {
	if [[ -n "$LAB_ACCOUNTS" ]]; then
		echo "- { trust_domain: prod.lab, mode: path_template, path_regex: '^/acct/([a-z0-9]+)/project/([a-z0-9]+)/', scope_template: 'tenants/\${1}/app/\${2}' }"
	else
		echo '- { trust_domain: prod.lab, mode: static, scope: "dc/corp-prod" }'
	fi
}

serve_accounts_config() {
	[[ -n "$LAB_ACCOUNTS" ]] || return 0
	local base="ou=accounts,$LDAP_BASE"
	cat <<YAML
  accounts:
    scope: "tenants/{account}"
    source_scope: "tenants/{account}/app/{project}"
    target_scope: "tenants/{account}/data/{tenancy}"
    ldap_groups:
      search_base: "$base"
      roles:
        - { group_dn: "cn=operators,ou={account},$base", role: operator, scope: "tenants/{account}/*" }
        - { group_dn: "cn=approvers,ou={account},$base", role: approver, scope: "tenants/{account}/*" }
        - { group_dn: "cn=approvers,ou={project},ou={account},$base", role: approver, scope: "tenants/{account}/app/{project}" }
YAML
}

serve_accounts_platform() {
	[[ -n "$LAB_ACCOUNTS" ]] || return 0
	local aud="$1" bao="$2"
	cat <<YAML
      - name: pg-shared
        realm: prod
        scope: "platform/shared"
        target_scopes: ["tenants/*"]
        namespace_template: "{account}_{tenancy}"
        display_name: "Lab PostgreSQL shared by the accounts"
        allowed_source_trust_domains: [prod.lab]
        network_flows:
          - { name: postgres, purpose: DATA, protocol: TCP, destination: "pg.ligo.lab", ports: [5432], tls: true, server_name: "pg.ligo.lab" }
        identity_provider: { type: target-local.v1, instance: local-prod }
        secret_store: { type: vault.v1, instance: vault-prod, secret_storage_strategy: vault-static }
        svid_selector: { match_expr: 'path == "/ligo/plugin/postgres"', jwt_audience: ["$aud"], allow_shared_svid: true }
        config:
          host: pg.ligo.lab
          port: 5432
          database: ledger
          grantable_role_templates: ["{namespace}_read", "{namespace}_write"]
          ca_file: /etc/ligo-lab/ca.crt
          allowed_endpoints: ["pg.ligo.lab:5432"]
          bootstrap_credential:
            source: vault
            address: "$bao"
            auth_mount: jwt-spiffe
            role: ligo-plugin-postgres
            jwt_audience: "$aud"
            kv_path: kv/data/ligo/bootstrap/postgres
YAML
}

# serve_config HOST: server.yaml for HOST, with the deployed plugins' hashes.
# serve_observability: traces to the collector, with the otel scenario.
serve_observability() {
	inner_exists otel || return 0
	printf 'observability:\n  tracing: { otlp_endpoint: "otel.ligo.lab:%s", ca_cert_file: /etc/ligo-lab/ca.crt }\n' "$OTEL_PORT"
}

# workload_advertise is the same on every replica, so that each serves the
# same "ligo" flow (and ETag): lb with the lb scenario, else ligo1. With lb,
# external_origin is lb's published address and the replicas' files are the
# same; without, it is the web UI's address through HOST's proxy.
serve_config() {
	local host="$1" advertise=ligo1.ligo.lab origin
	origin="https://$(lxd_ip):$(ui_port "$host")"
	if inner_exists lb; then
		advertise=lb.ligo.lab origin="https://$(lxd_ip):$LB_PORT"
	fi
	local aud bao host_name tp sv te ol
	aud="$(secrets_audience)" bao="$(secrets_addr)" host_name="$(secrets_host).ligo.lab"
	ol="$(sha256sum "$LAB_STATE_DIR/plugins/ligo-plugin-openldap" | cut -d' ' -f1)"
	tp="$(sha256sum "$LAB_STATE_DIR/plugins/ligo-plugin-postgres" | cut -d' ' -f1)"
	sv="$(sha256sum "$LAB_STATE_DIR/plugins/ligo-plugin-vault" | cut -d' ' -f1)"
	te="$(sha256sum "$LAB_STATE_DIR/plugins/ligo-plugin-echo" | cut -d' ' -f1)"
	cat <<YAML
# ligo serve (lab), generated by test/lab/lab.sh serve install
service:
  application_version: "lab"
  instance_id_env: LIGO_INSTANCE_ID
  workload_advertise: { destination: "$advertise", port: 8443, server_name: "$advertise" }
$(serve_observability)
$(hooks_notifications)
realms:
  - { name: prod, trust_domain: prod.lab, spiffe_workload_socket: "unix:///run/spire/prod/agent.sock" }
  - { name: test, trust_domain: test.lab, spiffe_workload_socket: "unix:///run/spire/test/agent.sock" }
core_identity:
  realm: prod
  svid_selector: { match_expr: 'path == "/ns/sys/sa/ligo"', jwt_audience: ["$aud"] }
server:
  metrics_listener: { listen_address: "127.0.0.1:9090" }
  workload_listener:
    listen_address: "0.0.0.0:8443"
    tls_source: spiffe
    auth_modes: [x509_svid, jwt_svid]
    accepted_trust_domains: [prod.lab, test.lab]
    expected_jwt_audience: "spiffe://prod.lab/ns/sys/sa/ligo"
  admin_listener:
    listen_address: "0.0.0.0:9443"
    external_origin: "$origin"   # the web UI through the lab VM's proxy (.specs/ligo-echo-target.md)
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
    # the HA e2e: a second approver (AC-50), and an administrator for maintenance (AC-26)
    - { spiffe_id: "spiffe://prod.lab/ops/sam", role: approver, scopes: ["dc/corp-prod/*"] }
    - { spiffe_id: "spiffe://prod.lab/ops/ada", role: admin.full_access, scopes: ["*"] }
    # the topologies' e2e: two tenancies and an Information Security party (ADR-13, ADR-14)
    - { spiffe_id: "spiffe://prod.lab/ops/paula", role: operator, scopes: ["cloud/fin-01/payments"] }
    - { spiffe_id: "spiffe://prod.lab/ops/pia", role: approver, scopes: ["cloud/fin-01/payments"] }
    - { spiffe_id: "spiffe://prod.lab/ops/hana", role: operator, scopes: ["cloud/fin-01/hr", "cloud/fin-01/ledger"] }
    - { spiffe_id: "spiffe://prod.lab/ops/sean", role: approver, scopes: ["sec/infosec"] }
    # the accounts' e2e: the shared platform's approver (.specs/ligo-tenancy.md §9.3)
    - { spiffe_id: "spiffe://prod.lab/ops/peter", role: approver, scopes: ["platform/shared"] }
    - { spiffe_id: "spiffe://prod.lab/ops/rita", role: approver, scopes: ["tenants/*"] }   # test-accounts-chaos
    - { ldap_group_dn: "cn=ligo-account-admins,ou=groups,$LDAP_BASE", role: account_admin }
    - { ldap_group_dn: "cn=ligo-viewers,ou=groups,$LDAP_BASE", role: viewer, scopes: ["*"] }
    - { ldap_group_dn: "cn=ligo-operators-prod,ou=groups,$LDAP_BASE", role: viewer, scopes: ["*"] }
    # the web UI's echo guide: carol files, dave approves (.specs/ligo-echo-target.md)
    - { ldap_group_dn: "cn=ledger-dbas,ou=groups,$LDAP_BASE", role: operator, scopes: ["dc/corp-prod/*"] }
    - { ldap_group_dn: "cn=ligo-approvers-prod,ou=groups,$LDAP_BASE", role: approver, scopes: ["dc/corp-prod/*"] }
    - { ldap_group_dn: "cn=ligo-breakglass-prod,ou=groups,$LDAP_BASE", role: break_glass, scopes: ["dc/corp-prod/*"] } # livia
  approval:
    required_scopes: ["dc/corp-prod/*", "cloud/fin-01/payments"$([[ -n "$LAB_ACCOUNTS" ]] && echo ', "tenants/*", "platform/*"')]
    require_distinct_approvers_across_scopes: $([[ -n "$LAB_ACCOUNTS" ]] && echo true || echo false)
    change_request_ttl: 72h
governance:
$(serve_accounts_config)
  source_scopes:
    $(serve_prod_scope)
    - { trust_domain: test.lab, mode: path_template, path_regex: '^/acct/([a-z0-9-]+)/tenant/([a-z0-9-]+)/', scope_template: 'cloud/\${1}/\${2}' }
  interconnects:
    default_cross_scope: deny
    rules:
      - { name: dc-to-apps, from: ["dc/corp-prod"], to: ["dc/corp-prod/*"], action: allow }
      - { name: cloud-within-account, from: ["cloud/fin-01/*"], to: ["cloud/fin-01/*"], action: allow }
      - { name: cloud-to-dc, from: ["cloud/fin-01/*"], to: ["dc/corp-prod/*"], action: allow, additional_approvals: [ { name: security, scope: "sec/infosec" } ] }
      - { name: dc-to-cloud, from: ["dc/corp-prod"], to: ["cloud/fin-01/*"], action: allow }
      - { name: accounts, from: ["tenants/*"], to: ["tenants/*"], action: allow }
break_glass:
  min_justification_length: 20
  policies:
    - { scopes: ["dc/corp-prod/*"], default_ttl: 1h, max_ttl: 4h, max_open: 3, warn_before: 15m }
storage:
  postgres: { app_dsn_env: LIGO_APP_DSN, reader_dsn_env: LIGO_READER_DSN, dbos_dsn_env: LIGO_DBOS_DSN }
secret_sealing:
  provider: vault-transit
  vault_transit: { address: "$bao", auth_mount: jwt-spiffe, role: ligo-sealer, jwt_audience: "$aud", mount: transit, key_name: ligo-interstage,
    ca_cert_file: /etc/ligo-lab/ca.crt }
plugins:
  directory: "$LIGO_PLUGINS"
identity_providers:
  - type: target-local.v1
    builtin: true
    instances: [ { name: local-prod, realm: prod } ]
  - type: svid.v1
    builtin: true
    instances: [ { name: svid-prod, realm: prod } ]
  - type: delegated-dynamic.v1
    builtin: true
    instances: [ { name: dynamic-prod, realm: prod } ]
  - type: openldap.v1
    binary: ligo-plugin-openldap
    sha256: "$ol"
    instances:
      - name: openldap-prod
        realm: prod
        svid_selector: { match_expr: 'path == "/ligo/plugin/openldap"', jwt_audience: ["$aud"] }
        config:
          url: "$LDAP_URL"
          service_ou_dn: "ou=ligo-accounts,$LDAP_BASE"
          allowed_endpoints: ["ldap.ligo.lab:636"]
          ca_file: /etc/ligo-lab/ca.crt
          bootstrap_credential:
            source: vault
            address: "$bao"
            auth_mount: jwt-spiffe
            role: ligo-plugin-openldap
            jwt_audience: "$aud"
            kv_path: kv/data/ligo/bootstrap/openldap
secret_stores:
  - type: none.v1
    builtin: true
    instances: [ { name: none-prod, realm: prod } ]
  - type: vault.v1
    binary: ligo-plugin-vault
    sha256: "$sv"
    instances:
      - name: vault-prod
        realm: prod
        svid_selector: { match_expr: 'path == "/ligo/plugin/vault"', jwt_audience: ["$aud"] }
        config:
          address: "$bao"
          auth_mount: jwt-spiffe
          role: ligo-plugin-vault
          db_connection: lab-pg
          ca_file: /etc/ligo-lab/ca.crt
          workload_jwt_audience: "$aud"
          allowed_endpoints: ["$host_name:$BAO_PORT"]
        network_flows:
          - { name: vault, purpose: CREDENTIALS, protocol: TCP, destination: "$host_name", ports: [$BAO_PORT], tls: true, server_name: "$host_name" }
platform_providers:
  - type: postgres.v1
    binary: ligo-plugin-postgres
    sha256: "$tp"
    platforms:
      - name: pg-ledger
        realm: prod
        scope: "dc/corp-prod"
        display_name: "Lab PostgreSQL ledger"
        allowed_source_trust_domains: [prod.lab, test.lab]
        network_flows:
          - { name: postgres, purpose: DATA, protocol: TCP, destination: "pg.ligo.lab", ports: [5432], tls: true, server_name: "pg.ligo.lab" }
        identity_provider: { type: target-local.v1, instance: local-prod }
        secret_store: { type: vault.v1, instance: vault-prod, secret_storage_strategy: vault-static }
        svid_selector: { match_expr: 'path == "/ligo/plugin/postgres"', jwt_audience: ["$aud"], allow_shared_svid: true }   # both platforms are one plugin's instances
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
            role: ligo-plugin-postgres
            jwt_audience: "$aud"
            kv_path: kv/data/ligo/bootstrap/postgres
      - name: pg-ledger-cloud
        realm: prod
        scope: "cloud/fin-01/ledger"
        target_scopes: ["cloud/fin-01/*"]
        display_name: "Lab PostgreSQL ledger, owned by a tenancy"
        allowed_source_trust_domains: [prod.lab, test.lab]
        network_flows:
          - { name: postgres, purpose: DATA, protocol: TCP, destination: "pg.ligo.lab", ports: [5432], tls: true, server_name: "pg.ligo.lab" }
        identity_provider: { type: target-local.v1, instance: local-prod }
        secret_store: { type: vault.v1, instance: vault-prod, secret_storage_strategy: vault-static }
        svid_selector: { match_expr: 'path == "/ligo/plugin/postgres"', jwt_audience: ["$aud"], allow_shared_svid: true }   # both platforms are one plugin's instances
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
            role: ligo-plugin-postgres
            jwt_audience: "$aud"
            kv_path: kv/data/ligo/bootstrap/postgres
      - name: pg-ledger-dynamic
        realm: prod
        scope: "dc/corp-prod"
        display_name: "Lab PostgreSQL ledger, credentials on demand"
        allowed_source_trust_domains: [prod.lab]
        network_flows:
          - { name: postgres, purpose: DATA, protocol: TCP, destination: "pg.ligo.lab", ports: [5432], tls: true, server_name: "pg.ligo.lab" }
        identity_provider: { type: delegated-dynamic.v1, instance: dynamic-prod }
        secret_store: { type: vault.v1, instance: vault-prod, secret_storage_strategy: vault-dynamic }
        svid_selector: { match_expr: 'path == "/ligo/plugin/postgres"', jwt_audience: ["$aud"], allow_shared_svid: true }   # both platforms are one plugin's instances
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
            role: ligo-plugin-postgres
            jwt_audience: "$aud"
            kv_path: kv/data/ligo/bootstrap/postgres
      - name: pg-ledger-ldap
        realm: prod
        scope: "dc/corp-prod"
        display_name: "Lab PostgreSQL ledger, accounts in the directory"
        allowed_source_trust_domains: [prod.lab]
        network_flows:
          - { name: postgres, purpose: DATA, protocol: TCP, destination: "pg.ligo.lab", ports: [5432], tls: true, server_name: "pg.ligo.lab" }
        identity_provider: { type: openldap.v1, instance: openldap-prod }
        secret_store: { type: vault.v1, instance: vault-prod, secret_storage_strategy: vault-static }
        svid_selector: { match_expr: 'path == "/ligo/plugin/postgres"', jwt_audience: ["$aud"], allow_shared_svid: true }   # both platforms are one plugin's instances
        config:
          host: pg.ligo.lab
          port: 5432
          database: ledger
          directory_group: ligo_ldap
          grantable_roles: [LEDGER_RO_ROLE, LEDGER_RW_ROLE, LEDGER_GONE_ROLE]   # LEDGER_GONE_ROLE: AC-10, serve_ldap_e2e_lab_test.go
          ca_file: /etc/ligo-lab/ca.crt
          allowed_endpoints: ["pg.ligo.lab:5432"]
          bootstrap_credential:
            source: vault
            address: "$bao"
            auth_mount: jwt-spiffe
            role: ligo-plugin-postgres
            jwt_audience: "$aud"
            kv_path: kv/data/ligo/bootstrap/postgres
$(serve_accounts_platform "$aud" "$bao")
  - type: echo.v1
    binary: ligo-plugin-echo
    sha256: "$te"
    platforms:   # the echo target (.specs/ligo-echo-target.md)
      - name: echo-svid
        realm: prod
        scope: "dc/corp-prod"
        display_name: "Lab echo server, admits SVIDs"
        allowed_source_trust_domains: [prod.lab]
        identity_provider: { type: svid.v1, instance: svid-prod }
        secret_store: { type: none.v1, instance: none-prod, secret_storage_strategy: svid }
        svid_selector: { match_expr: 'path == "/ligo/plugin/echo"', allow_shared_svid: true }   # both platforms are one plugin's instances
        config:
          data_address: "ligo1.ligo.lab:7101"
          control_address: "ligo1.ligo.lab:7102"
          server_id: "spiffe://prod.lab/ns/lab/sa/echo-server"
          mode: svid
          ca_file: /etc/ligo-lab/ca.crt
          allowed_endpoints: ["ligo1.ligo.lab:7101"]
      - name: echo-local
        realm: prod
        scope: "dc/corp-prod"
        display_name: "Lab echo server, admits users with a password"
        allowed_source_trust_domains: [prod.lab]
        identity_provider: { type: target-local.v1, instance: local-prod }
        secret_store: { type: vault.v1, instance: vault-prod, secret_storage_strategy: vault-static }
        svid_selector: { match_expr: 'path == "/ligo/plugin/echo"', allow_shared_svid: true }   # both platforms are one plugin's instances
        config:
          data_address: "ligo1.ligo.lab:7201"
          control_address: "ligo1.ligo.lab:7202"
          server_id: "spiffe://prod.lab/ns/lab/sa/echo-server"
          mode: password
          ca_file: /etc/ligo-lab/ca.crt
          allowed_endpoints: ["ligo1.ligo.lab:7201"]
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
	local load="ns/e2e/sa/w$E2E_SUFFIX"
	[[ -z "$LAB_ACCOUNTS" ]] || load="acct/acme/project/app01/sa/w$E2E_SUFFIX"
	local -A ids=([olga]=ops/olga [dora]=ops/dora [sam]=ops/sam [ada]=ops/ada [paula]=ops/paula [pia]=ops/pia [hana]=ops/hana [sean]=ops/sean [peter]=ops/peter [rita]=ops/rita
		[workload]="$load" [stranger]="ns/e2e/sa/v$E2E_SUFFIX" [dcload]="ns/topo/sa/w$E2E_SUFFIX")
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
	spire prod jwt mint -spiffeID "spiffe://prod.lab/${ids[workload]}" -audience "$(secrets_audience)" -ttl 10m |
		inner_exec ligo1 sh -c "tr -d '\n' >$LIGO1_E2E/workload-store-jwt && chown ligo:ligo $LIGO1_E2E/workload-store-jwt && chmod 0600 $LIGO1_E2E/workload-store-jwt" ||
		die "spire-prod: cannot mint the workload's JWT-SVID for the secrets backend"
	inner_exec spire-prod rm -rf "$dir"
	# the tenancy's workloads, as the registrar tenants cannot influence would register them (lab: minted)
	inner_exec spire-test sh -c "rm -rf $dir && mkdir -m 0700 $dir"
	spire test x509 mint -spiffeID "spiffe://test.lab/acct/fin-01/tenant/payments/ns/topo/sa/w$E2E_SUFFIX" -ttl 1h -write "$dir" >/dev/null 2>&1 ||
		die "spire-test: cannot mint the SVID of the tenancy's workload"
	for f in svid.pem key.pem; do
		inner_exec spire-test cat "$dir/$f" | inner_exec ligo1 sh -c "cat >$LIGO1_E2E/cloudload-$f && chown ligo:ligo $LIGO1_E2E/cloudload-$f && chmod 0600 $LIGO1_E2E/cloudload-$f"
	done
	inner_exec spire-test rm -rf "$dir"
}

# serve_e2e RUN HOST [OTHER]: runs the e2e tests matching RUN as the user
# ligo on ligo1, against the admin listener of HOST and, for the HA e2e, the
# admin and workload listeners of OTHER (default HOST).
serve_e2e() {
	local host="$2" other="${3:-$2}" uid envs=() line
	uid="$(env_get .ligo1.ligo_uid)"
	while IFS= read -r line; do
		envs+=(--env "$line")
	done < <(env_ligo)
	envs+=(--env "LIGO_E2E_ADMIN=https://$host.ligo.lab:9443" --env "LIGO_E2E_ADMIN2=https://$other.ligo.lab:9443"
		--env "LIGO_E2E_WORKLOAD=https://$other.ligo.lab:8443" --env "LIGO_E2E_DIR=$LIGO1_E2E" --env "LIGO_E2E_SECRETS=$LIGO_E2E_SECRETS"
		--env "LIGO_E2E_SUFFIX=$E2E_SUFFIX" --env "LIGO_E2E_TRACE=${E2E_TRACE:-}")
	lxd exec lxd -- lxc exec ligo1 --user "$uid" --cwd "$LIGO_TESTS" "${envs[@]}" -- \
		"$LIGO_TESTS/internal_command_serve.test" -test.count=1 -test.v -test.run "$1" | sed 's/^/        /'
}

# serve_test: the e2e of the service, with the lifecycle checks of ligo1
# between its two halves (.specs/ligo-test-environment.md). With ligo2, the
# binding is created through ligo1 and served, then revoked, through ligo2,
# and each replica ran workflows as its own DBOS executor.
serve_test() {
	deploy_tests # not the plugins: the running service holds them, and server.yaml their hashes
	section "e2e of ligo serve"
	local other
	other="$(ligo_hosts | tail -1)" # ligo2, or ligo1 alone
	E2E_SUFFIX="$(openssl rand -hex 4)"
	serve_admins
	serve_e2e '^TestServeE2EApply$' ligo1 || die "TestServeE2EApply failed"
	serve_e2e '^TestServeE2EWorkload$' "$other" || die "TestServeE2EWorkload failed on $other"
	local since
	since="$(inner_exec ligo1 date '+%Y-%m-%d %H:%M:%S')"
	inner_exec ligo1 systemctl reload ligo
	sleep 2
	inner_exec ligo1 journalctl --no-pager -u ligo --since "$since" | grep "SIGHUP: directory CA reloaded" >/dev/null ||
		die "reload: the journal does not show the directory CA reload"
	info "reload: the directory CA was reloaded"
	since="$(inner_exec ligo1 date '+%Y-%m-%d %H:%M:%S')"
	local start end
	start="$(date +%s)"
	inner_exec ligo1 systemctl stop ligo
	end="$(date +%s)"
	inner_exec ligo1 journalctl --no-pager -u ligo --since "$since" | grep '"msg":"shutting down"' >/dev/null ||
		die "stop: the journal does not show the drain"
	[[ "$(inner_exec ligo1 systemctl show -p ExecMainStatus --value ligo)" == 0 ]] || die "stop: ligo exited with a failure"
	((end - start <= 30)) || die "stop: took $((end - start))s"
	info "stop: drained and exited 0 in $((end - start))s"
	inner_exec ligo1 systemctl start ligo
	serve_wait ligo1
	info "start: ligo serves again"
	serve_e2e '^TestServeE2ERestarted$' "$other" || die "TestServeE2ERestarted failed on $other"
	serve_cli
	serve_test_ldap "$other"
	serve_test_topologies "$other"
	if inner_exists lb; then
		section "e2e through lb"
		E2E_SUFFIX="$(openssl rand -hex 4)" # new resources, and a fresh workload JWT-SVID
		serve_admins
		serve_e2e '^TestServeE2EApply$' lb || die "TestServeE2EApply failed through lb"
		serve_e2e '^TestServeE2EWorkload$' lb || die "TestServeE2EWorkload failed through lb"
		CLI_SERVER=lb.ligo.lab serve_cli
		lb_check
	fi
	local executors
	executors="$(pg_superuser -d "$SERVE_DB" -tAc "select string_agg(distinct executor_id, ' ' order by executor_id) from dbos.workflow_status")"
	[[ " $executors " == *" ligo1 "* && " $executors " == *" $other "* ]] || die "workflows ran as executors \"$executors\", not on every replica"
	info "workflows ran as the executors $executors"
	serve_scan_secrets
	info "e2e of ligo serve passed"
}

# serve_test_ldap OTHER: the openldap.v1 e2e (.specs/ligo-openldap-plugin.md,
# OL-11 to OL-14 and AC-10): the tests on ligo1, then what they cannot read
# from there: the audit entries and every replica's journal.
serve_test_ldap() {
	section "e2e of openldap.v1"
	local before after
	E2E_SUFFIX="$(openssl rand -hex 4)" # a new workload: the one before saw its binding revoked
	serve_admins
	before="$(serve_sql "select count(*) from audit_log where action = 'DELETE_COMPLETED'")"
	serve_e2e '^TestServeLDAP' ligo1 "$1" || die "TestServeLDAP failed"
	after="$(serve_sql "select count(*) from audit_log where action = 'DELETE_COMPLETED'")"
	((after - before == 2)) || die "OL-13, AC-10: $((after - before)) DELETE_COMPLETED entries, want 2"
	info "e2e of openldap.v1 passed"
}

# serve_test_topologies OTHER: the four topologies of ADR-13, each bound,
# served to its workload and revoked; a pair no rule allows is refused.
serve_test_topologies() {
	section "e2e of the four topologies"
	local before after
	before="$(serve_sql "select count(*) from audit_log where action = 'DELETE_COMPLETED'")"
	serve_e2e '^TestServe(Topologies|DynamicCredentials)$' ligo1 "$1" || die "TestServeTopologies or TestServeDynamicCredentials failed"
	after="$(serve_sql "select count(*) from audit_log where action = 'DELETE_COMPLETED'")"
	((after - before == 5)) || die "the topologies: $((after - before)) DELETE_COMPLETED entries, want 5"
	info "e2e of the four topologies passed"
}

# serve_accounts_install: the baseline, with server.yaml for accounts.
serve_accounts_install() {
	[[ "$(ligo_hosts | xargs)" == "ligo1 ligo2" ]] || die "the accounts' suites need ligo2: lab.sh up --scenario ha"
	inner_exists hooks || die "the accounts' suites need the receiver: lab.sh up --scenario webhook"
	LAB_ACCOUNTS=yes
	lab_reset
	ldap_seed # a baseline older than the accounts' entries lacks them
	serve_install
	deploy_tests
	E2E_SUFFIX="$(openssl rand -hex 4)"
	serve_admins
}

# serve_chaos_directory: a unit per account of the scale test, and sue in all
# their approvers' groups.
serve_chaos_directory() {
	local base="ou=accounts,$LDAP_BASE" hash i name
	hash="$(inner_exec ldap slappasswd -h '{SSHA}' -s "$(ldap_password sue)")"
	{
		printf 'dn: uid=sue,ou=users,%s\nobjectClass: inetOrgPerson\nuid: sue\ncn: Sue Everywhere\nsn: Everywhere\nuserPassword: %s\n\n' "$LDAP_BASE" "$hash"
		for ((i = 0; i < 300; i++)); do
			printf -v name 'scale%03d' "$i"
			printf 'dn: ou=%s,%s\nobjectClass: organizationalUnit\nou: %s\n\n' "$name" "$base" "$name"
			printf 'dn: cn=approvers,ou=%s,%s\nobjectClass: groupOfNames\ncn: approvers\nmember: uid=sue,ou=users,%s\n\n' "$name" "$base" "$LDAP_BASE"
		done
	} | inner_exec ldap sh -c 'ldapadd -c -Q -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1' || true
}

# serve_chaos_kills: kills a random replica every few seconds until stopped; each
# comes back through its unit.
serve_chaos_kills() {
	local host
	while :; do
		sleep $((15 + RANDOM % 16)) # a replica takes 15 to 25s to come back
		host="ligo$((1 + RANDOM % 2))"
		inner_exec "$host" systemctl kill -s KILL ligo 2>/dev/null || true
		info "killed ligo on $host"
	done
}

# serve_chaos_settle: records how fast the directory answers, and the lab VM's
# load, until three quick answers in a row: restarts load this one machine.
serve_chaos_settle() {
	local i start ms quick=0
	for i in $(seq 1 60); do
		start="$(date +%s%N)"
		ldapsearch_as ligo-admin-auth -b "ou=users,$LDAP_BASE" "(uid=ivan)" dn >/dev/null 2>&1 || true
		ms=$((($(date +%s%N) - start) / 1000000))
		info "directory ${ms}ms, load $(lxd exec lxd -- cut -d' ' -f1 /proc/loadavg)"
		if ((ms < 2000)); then quick=$((quick + 1)); else quick=0; fi
		((quick >= 3)) && return 0
		sleep 5
	done
	die "the directory stayed slow"
}

# serve_chaos_marker NAME: a file the running test waits for.
serve_chaos_marker() { inner_exec ligo1 sh -c "touch $LIGO1_E2E/$1 && chown ligo:ligo $LIGO1_E2E/$1"; }

# serve_test_accounts_chaos: the accounts at scale, racing under killed replicas,
# with PostgreSQL restarted under the registries' listeners, and with the
# directory down. Not part of release-run. Leaves the lab as test-accounts does.
serve_test_accounts_chaos() {
	serve_accounts_install
	serve_chaos_directory

	section "Hundreds of accounts"
	serve_e2e '^TestAccountsChaosScale$' ligo1 ligo2 || die "TestAccountsChaosScale failed"

	section "Retiring races approving, with replicas killed"
	local killer rc=0 host
	serve_chaos_kills &
	killer=$!
	serve_e2e '^TestAccountsChaosRace$' ligo1 ligo2 || rc=1
	kill "$killer" 2>/dev/null || true
	wait "$killer" 2>/dev/null || true
	for host in ligo1 ligo2; do
		inner_exec "$host" systemctl reset-failed ligo 2>/dev/null || true
		inner_exec "$host" systemctl start ligo
		serve_wait "$host"
	done
	((rc == 0)) || die "TestAccountsChaosRace failed"
	serve_chaos_settle
	local bad
	bad="$(serve_sql "select count(*) from sources s join accounts a on a.name = s.account where a.status = 'RETIRED' and s.state <> 'RETIRED'")"
	[[ "$bad" == 0 ]] || die "$bad sources on retired accounts"
	[[ "$(cli ligo-approver -o json audit verify | jq -r .valid)" == true ]] || die "audit verify"
	info "no source on a retired account; the audit chain verifies"

	section "PostgreSQL restarted under the listeners"
	local v before=()
	v="$(pg_version)"
	serve_e2e '^TestAccountsChaosBeforeRestart$' ligo1 ligo2 || die "TestAccountsChaosBeforeRestart failed"
	for host in ligo1 ligo2; do before+=("$(inner_exec "$host" systemctl show -p NRestarts --value ligo)"); done
	inner_exec pg systemctl stop "postgresql@$v-main"
	sleep 10
	inner_exec pg systemctl start "postgresql@$v-main"
	serve_e2e '^TestAccountsChaosAfterRestart$' ligo1 ligo2 || die "TestAccountsChaosAfterRestart failed"
	local i=0
	for host in ligo1 ligo2; do
		[[ "$(inner_exec "$host" systemctl show -p NRestarts --value ligo)" == "${before[$i]}" ]] || die "ligo on $host restarted during the outage"
		i=$((i + 1))
	done

	section "The directory down"
	local pid
	serve_e2e '^TestAccountsChaosDirectory$' ligo1 ligo2 &
	pid=$!
	for _ in $(seq 1 300); do
		inner_exec ligo1 test -e "$LIGO1_E2E/session-ready" && break
		sleep 0.2
	done
	serve_sql "update admin_sessions set authz_checked_at = now() - interval '1 day' where username = 'alan'" >/dev/null
	inner_exec ldap systemctl stop slapd
	serve_chaos_marker directory-down
	for _ in $(seq 1 300); do
		inner_exec ligo1 test -e "$LIGO1_E2E/session-checked" && break
		sleep 0.2
	done
	inner_exec ldap systemctl start slapd
	serve_chaos_marker directory-up
	wait "$pid" || die "TestAccountsChaosDirectory failed"
	info "the accounts' chaos passed; lab.sh reset and serve install before any other suite"
}

# serve_test_accounts: accounts on a shared PostgreSQL (.specs/ligo-tenancy.md
# §11, TN-7, 10, 12, 15, 18). It needs its own server.yaml and leaves accounts
# in the database, so it starts from the baseline, and the suites that follow
# need lab.sh reset and serve install.
serve_test_accounts() {
	serve_accounts_install
	section "e2e of accounts"
	inner_exec hooks truncate -s 0 "$HOOKS_LOG"
	serve_e2e '^TestServeAccounts$' ligo1 ligo2 || die "TestServeAccounts failed"
	hooks_drained
	local event=BINDING_TARGET_DECIDED_BY_PLATFORM got hook
	for hook in oncall dba elsewhere; do
		got="$(inner_exec hooks cat "$HOOKS_LOG" | jq -s --arg h "$hook" --arg e "$event" '[.[] | select(.hook == $h) | .body | fromjson | select(.event == $e)] | length')"
		case "$hook" in
		elsewhere) [[ "$got" == 0 ]] || die "TN-12: the source's account received $got $event" ;;
		*) [[ "$got" == 1 ]] || die "TN-12: $hook received $got $event, want 1" ;;
		esac
	done
	info "TN-12: $event reached the target's account, not the source's"
	serve_scan_secrets 2
	info "e2e of accounts passed; lab.sh reset and serve install before any other suite"
}

# serve_scan_secrets [MIN]: INV-03 and OL-14: the at least MIN passwords the e2e read from the
# store are nowhere in ligo_serve, DBOS's checkpoints included, or in the
# journal of ligo and its plugins on any replica. Only counts are printed.
serve_scan_secrets() {
	local dir host found
	dir="$(umask 077 && mktemp -d)"
	inner_exec ligo1 cat "$LIGO_E2E_SECRETS" >"$dir/secrets"
	(($(wc -l <"$dir/secrets") >= ${1:-3})) || { rm -rf "$dir"; die "INV-03: the e2e recorded no passwords"; }
	lxd exec lxd -- lxc exec pg -- sudo -u postgres pg_dump -d "$SERVE_DB" >"$dir/haystack" ||
		{ rm -rf "$dir"; die "INV-03: cannot dump $SERVE_DB"; }
	for host in $(ligo_hosts); do
		inner_exec "$host" journalctl --no-pager -u ligo >>"$dir/haystack" ||
			{ rm -rf "$dir"; die "INV-03: cannot read the journal of $host"; }
	done
	found="$(grep -c -F -f "$dir/secrets" "$dir/haystack" || true)"
	info "INV-03: $(wc -l <"$dir/secrets") passwords, $(wc -l <"$dir/haystack") lines searched, $found found"
	rm -rf "$dir"
	inner_exec ligo1 rm -f "$LIGO_E2E_SECRETS"
	[[ "$found" == 0 ]] || die "OL-14: a password is in the database or in a journal"
}

# serve_test_faults: the faults of §11.1 rule 3 that stop a service: the
# secrets backend under a binding's sealing (AC-09), and PostgreSQL under
# bindings in flight. Each service is started again whatever the test did.
serve_test_faults() {
	deploy_tests
	section "the secrets backend stopped (AC-09)"
	local other server unit rc=0
	other="$(ligo_hosts | tail -1)"
	E2E_SUFFIX="$(openssl rand -hex 4)"
	serve_admins
	serve_e2e '^TestServeFaultWarm$' ligo1 "$other" || die "TestServeFaultWarm failed"
	server="$(secrets_host)"
	unit=openbao
	[[ "$(secrets_backend)" == vault ]] && unit=vault
	inner_exec "$server" systemctl stop "$unit"
	serve_e2e '^TestServeFaultTransitDown$' ligo1 "$other" || rc=1
	inner_exec "$server" systemctl start "$unit"
	bao_wait "$server"
	bao_unseal "$server"
	((rc == 0)) || die "TestServeFaultTransitDown failed"
	serve_e2e '^TestServeFaultTransitBack$' ligo1 "$other" || die "TestServeFaultTransitBack failed"
	[[ "$(serve_sql "select count(*) from audit_log where resource_name = 'fault-seal-$E2E_SUFFIX' and action = 'APPLY_STARTED' and attempt = 2")" == 1 ]] ||
		die "AC-09: the retry was not attempt 2"

	section "PostgreSQL stopped under bindings in flight"
	local v inflight="" pid host before=()
	v="$(pg_version)"
	for host in $(ligo_hosts); do
		before+=("$(inner_exec "$host" systemctl show -p NRestarts --value ligo)")
	done
	serve_e2e '^TestServeFaultDatabase$' ligo1 "$other" &
	pid=$!
	for _ in $(seq 1 600); do
		inflight="$(serve_sql "select count(*) from bindings where name like 'fdb-$E2E_SUFFIX-%' and phase = 'PROVISIONING'")"
		[[ "$inflight" -gt 0 ]] && break
		sleep 0.1
	done
	inner_exec pg systemctl stop "postgresql@$v-main"
	info "PostgreSQL stopped with $inflight bindings in flight"
	sleep 10
	inner_exec pg systemctl start "postgresql@$v-main"
	wait "$pid" || die "TestServeFaultDatabase failed"
	[[ "$inflight" -gt 0 ]] || die "no binding was in flight when PostgreSQL stopped: the test proved nothing"
	local i=0
	for host in $(ligo_hosts); do
		[[ "$(inner_exec "$host" systemctl show -p NRestarts --value ligo)" == "${before[$i]}" ]] ||
			die "ligo on $host restarted during the outage"
		i=$((i + 1))
	done
	info "every binding converged and no replica restarted"
	info "the faults passed"
}

# serve_sql SQL: one value from ligo_serve, as the superuser.
serve_sql() { pg_superuser -d "$SERVE_DB" -tAc "$1"; }

# executor_field ID FIELD: a field of ID's row in ligo executors list, 0
# without a row.
executor_field() {
	cli ligo-admin -o json executors list | jq -r --arg id "$1" --arg f "$2" '[.items[]? | select(.executor == $id)][0][$f] // 0'
}

# serve_test_ha: the HA e2e on ligo1 and ligo2 (.specs/ligo-test-environment.md,
# "The HA tests"): with both up, AC-26, AC-50 and AC-77; with ligo1 stopped,
# ligo2 alone runs the sweeper, a workflow and the propagator; then ligo1,
# killed mid-workflow, recovers its own workflow; then ligo1, frozen
# mid-workflow, loses power and ligo2 recovers its workflow (§10.2).
serve_test_ha() {
	inner_exists ligo2 || die "serve test-ha needs ligo2: lab.sh up --scenario ha"
	deploy_tests
	section "HA e2e of ligo serve"
	E2E_SUFFIX="$(openssl rand -hex 4)"
	serve_admins
	serve_e2e '^TestServeHA(Maintenance|ConcurrentApproval|RetireRace)$' ligo1 ligo2 || die "the HA tests with both replicas failed"
	[[ "$(serve_sql "select count(*) from audit_log where action = 'SYSTEM_MAINTENANCE_ENABLED' and snapshot->>'reason' = 'ha e2e AC-26'")" -ge 1 ]] ||
		die "AC-26: SYSTEM_MAINTENANCE_ENABLED is not audited"
	info "AC-26: SYSTEM_MAINTENANCE_ENABLED audited"

	section "ligo2 alone"
	inner_exec ligo1 systemctl stop ligo
	serve_e2e '^TestServeHAAloneFile$' ligo2 ligo2 || die "TestServeHAAloneFile failed"
	serve_sql "update change_requests set expires_at = now() - interval '1 second' where resource_name = 'ha-exp-$E2E_SUFFIX' and status = 'PENDING'" >/dev/null
	local status=""
	for _ in $(seq 1 90); do
		status="$(serve_sql "select status from change_requests where resource_name = 'ha-exp-$E2E_SUFFIX'")"
		[[ "$status" == EXPIRED ]] && break
		sleep 1
	done
	[[ "$status" == EXPIRED ]] || die "ligo2's sweeper did not expire the request (status $status)"
	info "ligo2's sweeper expired a request while ligo1 was down"
	serve_e2e '^TestServeHAAloneApply$' ligo2 ligo2 || die "TestServeHAAloneApply failed"
	info "ligo2 alone applied a binding and propagated a narrowing"
	inner_exec ligo1 systemctl start ligo
	serve_wait ligo1

	section "ligo1 killed mid-workflow"
	serve_e2e '^TestServeHAKill$' ligo1 ligo2 || die "TestServeHAKill failed"
	local executors
	executors="$(serve_sql "select string_agg(w.executor_id || ':' || w.status, ' ') from bindings b join dbos.workflow_status w on w.workflow_uuid = b.workflow_id where b.name = 'ha-k-$E2E_SUFFIX'")"
	[[ "$executors" == "ligo1:SUCCESS" ]] || die "the killed replica's workflow: $executors, not ligo1:SUCCESS"
	serve_wait ligo1
	info "ligo1 recovered its own workflow after the kill ($executors)"

	section "ligo1 loses power, ligo2 recovers its workflow"
	local CLI_HOST=ligo2 CLI_SERVER=ligo2.ligo.lab # ligo1 is about to go
	host_user ligo2 ligo-ops spiffe://prod.lab/ops/olga
	host_user ligo2 ligo-admin spiffe://prod.lab/ops/ada
	serve_e2e '^TestServeHARecoverFrozen$' ligo1 ligo2 || die "TestServeHARecoverFrozen failed"
	# QEMU dies and the guest's kernel sends no FIN or RST: only PostgreSQL's
	# keepalives can end the sessions
	inner stop ligo1 --force
	local cut=$SECONDS pending out live="" audited
	local recoveries="select count(*) from audit_log where action = 'SYSTEM_EXECUTOR_RECOVERED' and snapshot->>'executor' = 'ligo1'"
	pending="$(executor_field ligo1 pending)" || die "executors list"
	((pending >= 1)) || die "executors list shows no pending workflow of ligo1"
	if out="$(cli ligo-admin executors recover ligo1 --yes 2>&1 </dev/null)"; then
		die "ligo1 was recovered with its sessions alive: $out"
	fi
	grep -q executor-alive <<<"$out" || die "recovering with sessions alive: $out"
	info "CLI: ligo1 has $pending pending, refused while its sessions live"
	while ((SECONDS - cut < 180)); do
		live="$(executor_field ligo1 liveSessions)" || live=""
		[[ "$live" == 0 ]] && break
		sleep 5
	done
	[[ "$live" == 0 ]] || die "ligo1's sessions outlived the power cut by 180s: check PostgreSQL's TCP keepalives (lib/pg.sh)"
	((SECONDS - cut >= 60)) || die "ligo1's sessions ended after $((SECONDS - cut))s: not the keepalives' doing"
	info "ligo1's sessions ended $((SECONDS - cut))s after the power cut"
	audited="$(serve_sql "$recoveries")"
	local announced=0
	inner_exists hooks && announced="$(hooks_count SYSTEM_EXECUTOR_RECOVERED)"
	if out="$(cli ligo-admin executors recover ligo1 <<<wrong 2>&1)"; then
		die "a wrong confirmation recovered ligo1: $out"
	fi
	grep -q "not confirmed" <<<"$out" || die "a wrong confirmation: $out"
	[[ "$(executor_field ligo1 pending)" == "$pending" && "$(serve_sql "$recoveries")" == "$audited" ]] ||
		die "a wrong confirmation changed something"
	cli ligo-admin executors recover ligo1 <<<ligo1 || die "executors recover ligo1"
	[[ "$(serve_sql "$recoveries")" == "$((audited + 1))" ]] || die "SYSTEM_EXECUTOR_RECOVERED is not audited once"
	if inner_exists hooks; then
		hooks_drained
		[[ "$(hooks_count SYSTEM_EXECUTOR_RECOVERED)" == "$((announced + 3))" ]] || die "SYSTEM_EXECUTOR_RECOVERED did not reach the three webhooks"
		info "SYSTEM_EXECUTOR_RECOVERED reached the three webhooks"
	fi
	local recovered="ha-g-$E2E_SUFFIX" row after
	cli_phase "$recovered" ACTIVE
	row="select w.executor_id || ':' || w.status || ':' || w.updated_at from bindings b join dbos.workflow_status w on w.workflow_uuid = b.workflow_id where b.name = '$recovered'"
	for _ in $(seq 1 10); do # ACTIVE comes just before the workflow's end
		executors="$(serve_sql "$row")"
		[[ "$executors" == ligo2:SUCCESS:* ]] && break
		sleep 1
	done
	[[ "$executors" == ligo2:SUCCESS:* ]] || die "the recovered workflow: $executors, not on ligo2"
	inner_start ligo1
	inner_wait ligo1
	spire_check ligo1
	serve_wait ligo1
	sleep 5
	after="$(serve_sql "$row")"
	[[ "$after" == "$executors" ]] || die "ligo1 came back and touched the recovered workflow: $after, was $executors"
	info "ligo2 ran ligo1's workflow, audited; ligo1 came back and left it alone"
	info "HA e2e of ligo serve passed"
}
