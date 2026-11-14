# shellcheck shell=bash
# Instances at run time (.specs/ligo-instances.md): the lab's platforms,
# identity provider and secret store instances, filed through the CLI as
# change requests and approved by a second person, and their e2e
# (lab.sh serve test-instances).

# instance_bounds TYPE: the endpoints the lab's instances of TYPE may use.
instance_bounds() {
	local vault="$(secrets_host).ligo.lab:$BAO_PORT"
	case "$1" in
	openldap.v1) echo "[\"ldap.ligo.lab:636\", \"$vault\"]" ;;
	vault.v1) echo "[\"$vault\"]" ;;
	postgres.v1) echo "[\"pg.ligo.lab:5432\", \"$vault\"]" ;;
	echo.v1) echo '["ligo1.ligo.lab:7101", "ligo1.ligo.lab:7102", "ligo1.ligo.lab:7201", "ligo1.ligo.lab:7202"]' ;;
	esac
}

# lab_instances: the lab's instances, one JSON document per line, with the
# lab CA inline (ca_pem) and the secret store of the backend in use.
lab_instances() {
	local aud bao host ca
	aud="$(secrets_audience)" bao="$(secrets_addr)" host="$(secrets_host).ligo.lab"
	ca="$(jq -Rs . <"$LAB_STATE_DIR/pki/ca.crt")"
	local boot='{"source": "vault", "address": "'"$bao"'", "auth_mount": "jwt-spiffe", "role": "ligo-plugin-postgres", "jwt_audience": "'"$aud"'", "kv_path": "kv/data/ligo/bootstrap/postgres"}'
	local pgflow='[{"name": "postgres", "purpose": "DATA", "protocol": "TCP", "destination": "pg.ligo.lab", "ports": [5432], "tls": true, "serverName": "pg.ligo.lab"}]'
	local pgsel='{"matchExpr": "path == \"/ligo/plugin/postgres\"", "jwtAudience": ["'"$aud"'"], "allowSharedSvid": true}'
	pg() { # pg NAME JURISDICTION DISPLAY IDP-TYPE IDP STORE-STRATEGY EXTRA-CONFIG EXTRA-FIELDS
		jq -cn --arg name "$1" --arg j "$2" --arg d "$3" --arg it "$4" --arg i "$5" --arg st "$6" --argjson ca "$ca" \
			--argjson boot "$boot" --argjson flows "$pgflow" --argjson sel "$pgsel" --argjson extra "$7" --argjson fields "$8" \
			'{kind: "Platform", metadata: {name: $name, jurisdiction: $j, realm: "prod", displayName: $d}, type: "postgres.v1",
			  allowedSourceTrustDomains: ["prod.lab"], networkFlows: $flows,
			  identityProvider: {type: $it, instance: $i}, secretStore: {type: "vault.v1", instance: "vault-prod", secretStorageStrategy: $st},
			  svidSelector: $sel,
			  config: ({host: "pg.ligo.lab", port: 5432, database: "ledger", grantable_roles: ["LEDGER_RO_ROLE", "LEDGER_RW_ROLE"],
			    ca_pem: $ca, allowed_endpoints: ["pg.ligo.lab:5432"], bootstrap_credential: $boot} + $extra)} + $fields'
	}
	jq -cn '{kind: "IdentityProvider", metadata: {name: "local-prod", jurisdiction: "dc/corp-prod", realm: "prod"}, type: "target-local.v1"}'
	jq -cn '{kind: "IdentityProvider", metadata: {name: "svid-prod", jurisdiction: "dc/corp-prod", realm: "prod"}, type: "svid.v1"}'
	jq -cn '{kind: "IdentityProvider", metadata: {name: "dynamic-prod", jurisdiction: "dc/corp-prod", realm: "prod"}, type: "delegated-dynamic.v1"}'
	jq -cn --arg url "$LDAP_URL" --arg ou "ou=ligo-accounts,$LDAP_BASE" --arg aud "$aud" --arg bao "$bao" --argjson ca "$ca" \
		'{kind: "IdentityProvider", metadata: {name: "openldap-prod", jurisdiction: "dc/corp-prod", realm: "prod"}, type: "openldap.v1",
		  svidSelector: {matchExpr: "path == \"/ligo/plugin/openldap\"", jwtAudience: [$aud]},
		  config: {url: $url, service_ou_dn: $ou, allowed_endpoints: ["ldap.ligo.lab:636"], ca_pem: $ca,
		    bootstrap_credential: {source: "vault", address: $bao, auth_mount: "jwt-spiffe", role: "ligo-plugin-openldap", jwt_audience: $aud,
		      kv_path: "kv/data/ligo/bootstrap/openldap"}}}'
	jq -cn '{kind: "SecretStore", metadata: {name: "none-prod", jurisdiction: "dc/corp-prod", realm: "prod"}, type: "none.v1"}'
	jq -cn --arg aud "$aud" --arg bao "$bao" --arg host "$host" --argjson port "$BAO_PORT" --argjson ca "$ca" \
		'{kind: "SecretStore", metadata: {name: "vault-prod", jurisdiction: "dc/corp-prod", realm: "prod"}, type: "vault.v1",
		  svidSelector: {matchExpr: "path == \"/ligo/plugin/vault\"", jwtAudience: [$aud], allowSharedSvid: true},
		  config: {address: $bao, auth_mount: "jwt-spiffe", role: "ligo-plugin-vault", db_connection: "lab-pg", ca_pem: $ca,
		    workload_jwt_audience: $aud, allowed_endpoints: ["\($host):\($port)"]},
		  networkFlows: [{name: "vault", purpose: "CREDENTIALS", protocol: "TCP", destination: $host, ports: [$port], tls: true, serverName: $host}]}'
	if has_namespaces; then # the same server, inside a namespace; the plugin's SVID is shared within dc/corp-prod (rule 7)
		jq -cn --arg aud "$aud" --arg bao "$bao" --arg host "$host" --argjson port "$BAO_PORT" --argjson ca "$ca" --arg ns "$LAB_NAMESPACE" \
			'{kind: "SecretStore", metadata: {name: "vault-ns", jurisdiction: "dc/corp-prod", realm: "prod"}, type: "vault.v1",
			  svidSelector: {matchExpr: "path == \"/ligo/plugin/vault\"", jwtAudience: [$aud], allowSharedSvid: true},
			  config: {address: $bao, namespace: $ns, auth_mount: "jwt-spiffe", role: "ligo-plugin-vault", ca_pem: $ca,
			    workload_jwt_audience: $aud, allowed_endpoints: ["\($host):\($port)"]},
			  networkFlows: [{name: "vault", purpose: "CREDENTIALS", protocol: "TCP", destination: $host, ports: [$port], tls: true, serverName: $host}]}'
	fi
	pg pg-ledger dc/corp-prod "Lab PostgreSQL ledger" target-local.v1 local-prod vault-static '{}' '{"allowedSourceTrustDomains": ["prod.lab", "test.lab"]}'
	pg pg-ledger-cloud cloud/fin-01/ledger "Lab PostgreSQL ledger, owned by a tenancy" target-local.v1 local-prod vault-static '{}' \
		'{"targetJurisdictions": ["cloud/fin-01/*"], "allowedSourceTrustDomains": ["prod.lab", "test.lab"]}'
	# a lease of 90s: a workload that watches re-reads its credential after 60s (TestServeClientSDK)
	pg pg-ledger-dynamic dc/corp-prod "Lab PostgreSQL ledger, credentials on demand" delegated-dynamic.v1 dynamic-prod vault-dynamic '{"credential_ttl": "90s"}' '{}'
	# LEDGER_GONE_ROLE: AC-10, serve_ldap_e2e_lab_test.go
	pg pg-ledger-ldap dc/corp-prod "Lab PostgreSQL ledger, accounts in the directory" openldap.v1 openldap-prod vault-static \
		'{"directory_group": "ligo_ldap", "grantable_roles": ["LEDGER_RO_ROLE", "LEDGER_RW_ROLE", "LEDGER_GONE_ROLE"]}' '{}'
	if [[ -n "$LAB_ACCOUNTS" ]]; then
		pg pg-shared platform/shared "Lab PostgreSQL shared by the accounts" target-local.v1 local-prod vault-static \
			'{"grantable_role_templates": ["{namespace}_read", "{namespace}_write"]}' \
			'{"targetJurisdictions": ["tenants/*"], "namespaceTemplate": "{account}_{tenancy}"}' |
			jq -c 'del(.config.grantable_roles)'
	fi
	local name mode store port control platforms="echo-svid:svid:none-prod echo-local:password:vault-prod"
	# echo-ns: the password server again, its passwords kept in the namespace
	if has_namespaces; then platforms="$platforms echo-ns:password:vault-ns"; fi
	for name in $platforms; do # the echo target (.specs/ligo-echo-target.md)
		IFS=: read -r name mode store <<<"$name"
		port=7101 control=7102
		[[ "$mode" == svid ]] || port=7201 control=7202
		jq -cn --arg name "$name" --arg mode "$mode" --arg store "$store" --arg data "ligo1.ligo.lab:$port" --arg control "ligo1.ligo.lab:$control" --argjson ca "$ca" \
			'{kind: "Platform", metadata: {name: $name, jurisdiction: "dc/corp-prod", realm: "prod",
			    displayName: (if $mode == "svid" then "Lab echo server, admits SVIDs" else "Lab echo server, admits users with a password (\($store))" end)},
			  type: "echo.v1", allowedSourceTrustDomains: ["prod.lab"],
			  identityProvider: (if $mode == "svid" then {type: "svid.v1", instance: "svid-prod"} else {type: "target-local.v1", instance: "local-prod"} end),
			  secretStore: (if $mode == "svid" then {type: "none.v1", instance: $store, secretStorageStrategy: "svid"}
			    else {type: "vault.v1", instance: $store, secretStorageStrategy: "vault-static"} end),
			  svidSelector: {matchExpr: "path == \"/ligo/plugin/echo\"", allowSharedSvid: true},
			  config: {data_address: $data, control_address: $control, server_id: "spiffe://prod.lab/ns/lab/sa/echo-server", mode: $mode,
			    ca_pem: $ca, allowed_endpoints: [$data]}}'
	done
}

# kind_path KIND: the CLI's name of a manifest kind.
kind_path() { case "$1" in IdentityProvider) echo identity-provider ;; SecretStore) echo secret-store ;; Platform) echo platform ;; esac; }

# instance_file USER DOC: files one instance definition as USER: a creation,
# or an update of the current revision.
instance_file() {
	local user="$1" doc="$2" kind name rev
	kind="$(kind_path "$(jq -r .kind <<<"$doc")")" name="$(jq -r .metadata.name <<<"$doc")"
	rev="$(cli "$user" -o json get "$kind" "$name" 2>/dev/null </dev/null | jq -r '.revision // empty')" || rev=""
	[[ -z "$rev" ]] || doc="$(jq -c --argjson r "$rev" '. + {expectedRevision: $r}' <<<"$doc")"
	cli "$user" apply -f - <<<"$doc" >/dev/null || die "apply $kind $name"
}

# approve_all USER KIND: USER approves every side awaiting it of KIND's
# change requests.
approve_all() {
	local json n i id sha side
	json="$(cli "$1" -o json cr list --awaiting-me --kind "$2" --page-size 200)" || die "cr list $2"
	n="$(jq '.items | length' <<<"$json")"
	for ((i = 0; i < n; i++)); do
		id="$(jq -r ".items[$i].id" <<<"$json")" sha="$(jq -r ".items[$i].payloadSha256" <<<"$json")"
		for side in $(jq -r ".items[$i].awaitingApproval[]" <<<"$json"); do
			cli "$1" cr approve "$id" --sha256 "$sha" --side "$side" -m "lab" >/dev/null || die "cr approve $id"
		done
	done
	info "$n $2 request(s) approved by $1"
}

# INSTANCE_FILER, INSTANCE_APPROVER: the CLI users that file and decide the
# lab's instances (CLI_USERS).
INSTANCE_FILER=ligo-platform
INSTANCE_APPROVER=ligo-platform-approver

# serve_instances: files the lab's instances, identity providers and
# secret stores first, and has them approved, then platforms; waits until
# every platform serves on every replica.
serve_instances() {
	section "instances (.specs/ligo-instances.md)"
	local docs kind doc host name
	docs="$(lab_instances)"
	for kind in IdentityProvider SecretStore Platform; do
		# fd 3: cli's lxc exec reads stdin, and would eat the documents
		while IFS= read -r doc <&3; do
			if [[ "$(jq -r .kind <<<"$doc")" == "$kind" ]]; then instance_file "$INSTANCE_FILER" "$doc"; fi
		done 3<<<"$docs"
		approve_all "$INSTANCE_APPROVER" "$(kind_path "$kind")"
		listed "$(kind_path "$kind")" "$(jq -r --arg k "$kind" 'select(.kind == $k) | .metadata.name' <<<"$docs" | xargs)"
	done
	for host in $(ligo_hosts); do
		for name in $(jq -r 'select(.kind == "Platform" and (.type != "echo.v1")) | .metadata.name' <<<"$docs"); do
			platform_serves "$host" "$name" || die "platform $name does not serve on $host"
		done
		info "every platform serves on $host"
	done
}

# listed KIND NAMES: waits up to 30s until ligo1 lists every one of NAMES
# among the KIND instances in force (its registry has loaded them).
listed() {
	local out name missing
	for _ in $(seq 1 30); do
		out="$(cli ligo-ops -o json list "$1s" </dev/null 2>/dev/null)" || out='{}'
		missing=""
		for name in $2; do
			jq -e --arg n "$name" '.items[]? | select(.name == $n)' <<<"$out" >/dev/null || missing="$missing $name"
		done
		[[ -z "$missing" ]] && return 0
		sleep 1
	done
	die "$1 not in force:$missing"
}

# platform_serves HOST NAME: waits up to 60s until HOST lists platform NAME
# as serving.
platform_serves() {
	local out
	for _ in $(seq 1 60); do
		out="$(CLI_SERVER="$1.ligo.lab" cli ligo-ops -o json platform list 2>/dev/null)" || out='{}'
		[[ "$(jq -r --arg n "$2" '.items[]? | select(.name == $n) | .health.serving' <<<"$out")" == true ]] && return 0
		sleep 1
	done
	return 1
}

# shared_svid_refusals X: rule 7 refuses an SVID shared across jurisdictions
# when its type's shared_svids does not list it (the echo SVID), and any
# sharing by an instance that does not opt in (.specs/ligo-instances.md §6).
shared_svid_refusals() {
	local x="$1" doc out
	doc="$(lab_instances | jq -c --arg n "echo-cloud-$x" 'select(.metadata.name == "echo-svid") | .metadata.name = $n | .metadata.jurisdiction = "cloud/fin-01/ledger"')"
	if out="$(cli "$INSTANCE_FILER" apply -f - <<<"$doc" 2>&1)"; then
		die "an echo platform in cloud/fin-01/ledger was filed on the echo SVID of dc/corp-prod"
	fi
	grep -q shared_svids <<<"$out" || die "echo across jurisdictions: $out"
	info "the echo SVID, not in shared_svids, is refused across jurisdictions (rule 7)"
	doc="$(lab_instances | jq -c --arg n "pg-optout-$x" 'select(.metadata.name == "pg-ledger") | .metadata.name = $n | .svidSelector.allowSharedSvid = false')"
	if out="$(cli "$INSTANCE_FILER" apply -f - <<<"$doc" 2>&1)"; then
		die "a platform that does not opt in was filed on the shared PostgreSQL SVID"
	fi
	grep -q allowSharedSvid <<<"$out" || die "opt-out: $out"
	info "an instance that does not opt in cannot share the PostgreSQL SVID (ADR-03)"
}

# started HOST: when ligo last started on HOST.
started() { inner_exec "$1" systemctl show ligo -p ActiveEnterTimestampMonotonic --value; }

# serve_test_instances: a platform added, changed and used with no restart,
# its bounds tightened, its retirement refused while in use, an endpoint
# outside the type's instance_bounds refused, and a drift quarantined and
# cleared (.specs/ligo-instances.md §12).
serve_test_instances() {
	section "instances at run time"
	local x name doc host out target before=() i=0
	x="$(openssl rand -hex 3)" name="pg-extra-$x" target="extra-ledger-$x"
	for host in $(ligo_hosts); do before+=("$(started "$host")"); done
	doc="$(lab_instances | jq -c --arg n "$name" 'select(.metadata.name == "pg-ledger") | .metadata.name = $n | .metadata.displayName = "e2e"')"
	instance_file "$INSTANCE_FILER" "$doc"
	approve_all "$INSTANCE_APPROVER" platform
	for host in $(ligo_hosts); do
		platform_serves "$host" "$name" || die "$name does not serve on $host"
	done
	info "platform $name serves on every replica: it shares the PostgreSQL SVID with pg-ledger-cloud's jurisdiction, as shared_svids lists it (ADR-03)"
	shared_svid_refusals "$x"
	cli ligo-ops apply -f - <<YAML >/dev/null || die "apply the target on $name"
kind: Target
metadata: {name: $target, platform: $name, jurisdiction: dc/corp-prod/ledger}
definition: {database: ledger, schema: ledger}
accessLevels: [{name: read, grants: {roles: [LEDGER_RO_ROLE]}}, {name: write, grants: {roles: [LEDGER_RO_ROLE, LEDGER_RW_ROLE]}}]
visibility: {mode: PRIVATE}
YAML
	cli_approve target "$target"
	info "target $target published on $name: its plugin validated it"
	# tightened bounds: the write level falls outside, and is reported
	instance_file "$INSTANCE_FILER" "$(jq -c '.config.grantable_roles = ["LEDGER_RO_ROLE"]' <<<"$doc")"
	approve_all "$INSTANCE_APPROVER" platform
	for _ in $(seq 1 30); do
		out="$(serve_sql "select count(*) from audit_log where action = 'SYSTEM_PRIVILEGE_BOUND_VIOLATIONS' and snapshot::text like '%$target%'")"
		[[ "$out" -ge 1 ]] && break
		sleep 1
	done
	[[ "$out" -ge 1 ]] || die "no SYSTEM_PRIVILEGE_BOUND_VIOLATIONS for $target after tightening $name"
	info "tightened bounds reported $target's write level"
	# retirement refused while the target is on it
	local rev
	rev="$(cli "$INSTANCE_FILER" -o json get platform "$name" | jq -r .revision)"
	if out="$(cli "$INSTANCE_FILER" delete platform "$name" -r "$rev" 2>&1)"; then
		die "retired $name while $target is on it"
	fi
	grep -q instance-in-use <<<"$out" || die "retire $name: $out"
	info "retiring $name is refused while in use"
	# an endpoint outside the type's instance_bounds
	if out="$(cli "$INSTANCE_FILER" apply -f - <<<"$(jq -c --arg n "evil-$x" '.metadata.name = $n | .config.host = "evil.example" | .config.allowed_endpoints = ["pg.ligo.lab:5432", "evil.example:5432"]' <<<"$doc")" 2>&1)"; then
		die "an instance outside instance_bounds was filed"
	fi
	grep -q instance_bounds <<<"$out" || die "outside the bounds: $out"
	info "an endpoint outside instance_bounds is refused"
	# drift: a row edited in the database is quarantined, and a new request clears it
	serve_sql "update instances set definition = jsonb_set(definition, '{metadata,displayName}', '\"tampered\"') where name = '$name'" >/dev/null
	for _ in $(seq 1 60); do
		out="$(serve_sql "select count(*) from audit_log where action = 'SYSTEM_INSTANCE_DRIFT' and resource_name = '$name'")"
		[[ "$out" -ge 1 ]] && break
		sleep 1
	done
	[[ "$out" -ge 1 ]] || die "no SYSTEM_INSTANCE_DRIFT for $name"
	sleep 3 # the other replica's load
	for host in $(ligo_hosts); do
		out="$(CLI_SERVER="$host.ligo.lab" cli ligo-ops -o json platform list | jq --arg n "$name" '[.items[] | select(.name == $n)] | length')"
		[[ "$out" == 0 ]] || die "the drifted $name is still offered on $host"
	done
	info "the edited row of $name is quarantined"
	instance_file "$INSTANCE_FILER" "$(jq -c '.config.grantable_roles = ["LEDGER_RO_ROLE"]' <<<"$doc")"
	approve_all "$INSTANCE_APPROVER" platform
	platform_serves ligo1 "$name" || die "$name not back after a new request"
	info "a new request ends the quarantine"
	for host in $(ligo_hosts); do
		[[ "$(started "$host")" == "${before[$i]}" ]] || die "ligo restarted on $host"
		i=$((i + 1))
	done
	info "no replica restarted"
}
