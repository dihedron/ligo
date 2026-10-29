# shellcheck shell=bash
# The PostgreSQL container of the storage scenario.

# pg_cloud_init: the VM's cloud-init user data.
pg_cloud_init() {
	cat <<'YAML'
#cloud-config
package_update: true
packages: [postgresql]
YAML
}

pg_up() {
	section "PostgreSQL (pg)"
	if ! inner_exists pg; then
		inner_init pg -c limits.memory="$LAB_PG_MEMORY" -c boot.autostart=true \
			-c cloud-init.user-data="$(pg_cloud_init)" -d eth0,ipv4.address="$(pg_ip)" >/dev/null
		info "container pg created from $LAB_IMAGE"
	fi
	inner_start pg
	info "waiting for cloud-init (packages)..."
	inner_wait pg
	pg_configure
	pg_roles
	pg_target
	pg_proxy
	pg_wait_ready
}

# pg_proxy publishes PostgreSQL on the lab VM's lab address, for the tests on
# the lab host; nat mode keeps the client's address.
pg_proxy() {
	if ! inner config device get pg postgres type >/dev/null 2>&1; then
		inner config device add pg postgres proxy nat=true \
			listen="tcp:$(lxd_ip):5432" connect="tcp:$(pg_ip):5432" >/dev/null
	fi
	info "PostgreSQL published on $(lxd_ip):5432"
}

# pg_version: the major version of the installed PostgreSQL cluster.
pg_version() { inner_exec pg pg_lsclusters -h | awk 'NR==1 {print $1}'; }

# pg_configure installs the certificates and the TLS-only configuration.
pg_configure() {
	local v conf
	v="$(pg_version)"
	[[ -n "$v" ]] || die "pg: no PostgreSQL cluster found"
	conf="/etc/postgresql/$v/main"
	inner_exec pg mkdir -p /etc/postgresql/ligo-lab /etc/ligo-lab
	inner_push "$LAB_STATE_DIR/pki/pg.crt" pg /etc/postgresql/ligo-lab/server.crt 0644
	inner_push "$LAB_STATE_DIR/pki/pg.key" pg /etc/postgresql/ligo-lab/server.key 0600
	inner_push "$LAB_STATE_DIR/pki/ca.crt" pg /etc/ligo-lab/ca.crt 0644
	inner_exec pg chown postgres:postgres /etc/postgresql/ligo-lab/server.crt /etc/postgresql/ligo-lab/server.key
	inner_exec pg sh -c "cat >$conf/conf.d/ligo-lab.conf" <<CONF
# ligo lab (test/lab): TLS only, on the lab address
listen_addresses = '$(pg_ip)'
ssl = on
ssl_cert_file = '/etc/postgresql/ligo-lab/server.crt'
ssl_key_file = '/etc/postgresql/ligo-lab/server.key'
ssl_min_protocol_version = 'TLSv1.3'
password_encryption = 'scram-sha-256'
CONF
	inner_exec pg sh -c "cat >$conf/pg_hba.conf" <<HBA
# ligo lab (test/lab): the superuser over the Unix socket, the ligo roles
# over TLS from the inner network and, through the proxy, the lab network
local   all   postgres                                              peer
hostssl all   ligo_migrator,ligo_app,ligo_reader,ligo_dbos   $LAB_INNER_SUBNET   scram-sha-256
hostssl all   ligo_migrator,ligo_app,ligo_reader,ligo_dbos   $LAB_SUBNET         scram-sha-256
HBA
	inner_exec pg systemctl restart "postgresql@$v-main"
	info "PostgreSQL $v configured: TLS only on $(pg_ip):5432"
}

# pg_superuser ARGS: psql as postgres over the Unix socket.
pg_superuser() { lxd exec lxd -- lxc exec pg -- sudo -u postgres psql -X "$@"; }

# pg_roles creates the roles and the database once (sql/roles.sql).
pg_roles() {
	if [[ "$(pg_superuser -tAc "select 1 from pg_database where datname = 'ligo'")" == 1 ]]; then
		info "database ligo and its roles exist"
		return
	fi
	pg_superuser -q -v migrator_password="$(password migrator)" -v app_password="$(password app)" \
		-v reader_password="$(password reader)" -v dbos_password="$(password dbos)" -f - <"$LAB_DIR/sql/roles.sql"
	info "database ligo and roles ligo_migrator, ligo_app, ligo_reader, ligo_dbos created"
}

# pg_target creates the target database of the target-postgres stand-in
# (sql/target.sql, idempotent) and lets any role reach that database, and
# only it, over TLS from the inner network, as a workload would.
pg_target() {
	local file="$LAB_STATE_DIR/passwords/target-admin" v hba
	[[ -f "$file" ]] || (umask 077 && openssl rand -hex 16 >"$file")
	pg_superuser -q -v admin_password="$(cat "$file")" -f - <"$LAB_DIR/sql/target.sql" >/dev/null ||
		die "pg: cannot create the target database ledger"
	v="$(pg_version)"
	hba="/etc/postgresql/$v/main/pg_hba.conf"
	if ! inner_exec pg grep -q '^hostssl ledger' "$hba"; then
		inner_exec pg sh -c "echo 'hostssl ledger all $LAB_INNER_SUBNET scram-sha-256' >>$hba"
		inner_exec pg systemctl reload "postgresql@$v-main"
	fi
	info "target database ledger ready (target-postgres)"
}

# pg_dsn ROLE [HOST ROOTCERT]: the DSN of ligo_ROLE, verifying the server with
# the lab CA; by default from the lab host, through the proxy.
pg_dsn() {
	printf 'postgres://ligo_%s:%s@%s:5432/ligo?sslmode=verify-full&sslrootcert=%s' \
		"$1" "$(password "$1")" "${2:-$(lxd_ip)}" "${3:-$LAB_STATE_DIR/pki/ca.crt}"
}

# pg_psql ROLE ARGS: psql in the VM as ligo_ROLE, over TLS to the lab
# address, verifying the certificate.
pg_psql() {
	local role="$1"
	shift
	lxd exec lxd -- lxc exec pg -- psql -X "$(pg_dsn "$role" "$(pg_ip)" /etc/ligo-lab/ca.crt)" "$@"
}

# pg_wait_ready waits until every role connects over TLS.
pg_wait_ready() {
	local role i
	for role in migrator app reader dbos; do
		for i in $(seq 1 30); do
			pg_psql "$role" -tAc 'select 1' >/dev/null 2>&1 && break
			sleep 1
		done
		pg_psql "$role" -tAc 'select 1' >/dev/null || die "pg: ligo_$role cannot connect over TLS"
	done
	info "every role connects over TLS (verify-full)"
}

# pg_record writes env.json.
pg_record() {
	local version fingerprint
	version="$(pg_superuser -tAc 'show server_version')"
	fingerprint="$(inner config get pg volatile.base_image)"
	jq -n --arg scenarios "$LAB_SCENARIOS" --arg image "$LAB_IMAGE" --arg fingerprint "$fingerprint" \
		--arg pg "$version" --arg ip "$(pg_ip)" --arg published "$(lxd_ip):5432" --arg inner_lxd "$(inner version 2>/dev/null | awk '/Server version/ {print $3}')" --arg driver "$(lxc storage show "$LAB_STORAGE_POOL" | awk '/^driver:/ {print $2}')" \
		--arg ca "$(sha256sum "$LAB_STATE_DIR/pki/ca.crt" | cut -d' ' -f1)" \
		--arg cert "$(sha256sum "$LAB_STATE_DIR/pki/pg.crt" | cut -d' ' -f1)" \
		--arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		'{scenarios: $scenarios, recorded_at: $at, storage_driver: $driver, inner_lxd: $inner_lxd,
		  pg: {image: $image, image_fingerprint: $fingerprint, version: $pg, address: $ip, published: $published,
		       ca_sha256: $ca, cert_sha256: $cert}}' >"$LAB_STATE_DIR/env.json.new"
	# keep what the other scenarios and the snapshot recorded
	if [[ -f "$LAB_STATE_DIR/env.json" ]]; then
		jq -s '.[1] + .[0]' \
			"$LAB_STATE_DIR/env.json.new" "$LAB_STATE_DIR/env.json" >"$LAB_STATE_DIR/env.json.merged"
		mv "$LAB_STATE_DIR/env.json.merged" "$LAB_STATE_DIR/env.json.new"
	fi
	mv "$LAB_STATE_DIR/env.json.new" "$LAB_STATE_DIR/env.json"
}
