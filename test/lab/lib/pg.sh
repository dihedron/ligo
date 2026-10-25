# shellcheck shell=bash
# The PostgreSQL VM of the storage scenario.

# pg_cloud_init: the VM's cloud-init user data.
pg_cloud_init() {
	cat <<'YAML'
#cloud-config
package_update: true
packages: [postgresql]
YAML
}

pg_up() {
	section "PostgreSQL VM (pg)"
	if ! vm_exists pg; then
		lxd init "$LAB_IMAGE" pg --vm \
			-c limits.cpu="$LAB_PG_CPUS" -c limits.memory="$LAB_PG_MEMORY" \
			-c cloud-init.user-data="$(pg_cloud_init)" \
			-d root,size="$LAB_PG_DISK" \
			-d eth0,ipv4.address="$(pg_ip)" >/dev/null
		info "VM pg created from $LAB_IMAGE"
	else
		pg_check_size
	fi
	vm_running pg || lxd start pg
	info "waiting for cloud-init (packages)..."
	vm_wait pg
	pg_configure
	pg_roles
	pg_wait_ready
}

# pg_check_size warns when the existing VM differs from the size settings.
pg_check_size() {
	local cpus memory
	cpus="$(lxd config get pg limits.cpu)"
	memory="$(lxd config get pg limits.memory)"
	[[ "$cpus" == "$LAB_PG_CPUS" && "$memory" == "$LAB_PG_MEMORY" ]] ||
		warn "VM pg has $cpus vCPU(s) and $memory, the settings ask for $LAB_PG_CPUS and $LAB_PG_MEMORY: \"down\" then \"up\" to apply them"
}

# pg_version: the major version of the installed PostgreSQL cluster.
pg_version() { lxd exec pg -- pg_lsclusters -h | awk 'NR==1 {print $1}'; }

# pg_configure installs the certificates and the TLS-only configuration.
pg_configure() {
	local v conf
	v="$(pg_version)"
	[[ -n "$v" ]] || die "pg: no PostgreSQL cluster found"
	conf="/etc/postgresql/$v/main"
	lxd exec pg -- mkdir -p /etc/postgresql/ligo-lab /etc/ligo-lab
	lxd file push "$LAB_STATE_DIR/pki/pg.crt" pg/etc/postgresql/ligo-lab/server.crt --uid 0 --gid 0 --mode 0644 >/dev/null
	lxd file push "$LAB_STATE_DIR/pki/pg.key" pg/etc/postgresql/ligo-lab/server.key --uid 0 --gid 0 --mode 0600 >/dev/null
	lxd file push "$LAB_STATE_DIR/pki/ca.crt" pg/etc/ligo-lab/ca.crt --uid 0 --gid 0 --mode 0644 >/dev/null
	lxd exec pg -- chown postgres:postgres /etc/postgresql/ligo-lab/server.crt /etc/postgresql/ligo-lab/server.key
	lxd exec pg -- sh -c "cat >$conf/conf.d/ligo-lab.conf" <<CONF
# ligo lab (test/lab): TLS only, on the lab address
listen_addresses = '$(pg_ip)'
ssl = on
ssl_cert_file = '/etc/postgresql/ligo-lab/server.crt'
ssl_key_file = '/etc/postgresql/ligo-lab/server.key'
ssl_min_protocol_version = 'TLSv1.3'
password_encryption = 'scram-sha-256'
CONF
	lxd exec pg -- sh -c "cat >$conf/pg_hba.conf" <<HBA
# ligo lab (test/lab): the superuser over the Unix socket, the ligo roles
# over TLS from the lab network only
local   all   postgres                                              peer
hostssl all   ligo_migrator,ligo_app,ligo_reader,ligo_dbos   $LAB_SUBNET   scram-sha-256
HBA
	lxd exec pg -- systemctl restart "postgresql@$v-main"
	info "PostgreSQL $v configured: TLS only on $(pg_ip):5432"
}

# pg_superuser ARGS: psql as postgres over the Unix socket.
pg_superuser() { lxd exec pg -- sudo -u postgres psql -X "$@"; }

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

# pg_dsn ROLE [ROOTCERT]: the DSN of ligo_ROLE, verifying the server with the
# lab CA (default: the host's copy).
pg_dsn() {
	printf 'postgres://ligo_%s:%s@%s:5432/ligo?sslmode=verify-full&sslrootcert=%s' \
		"$1" "$(password "$1")" "$(pg_ip)" "${2:-$LAB_STATE_DIR/pki/ca.crt}"
}

# pg_psql ROLE ARGS: psql in the VM as ligo_ROLE, over TLS to the lab
# address, verifying the certificate.
pg_psql() {
	local role="$1"
	shift
	lxd exec pg -- psql -X "$(pg_dsn "$role" /etc/ligo-lab/ca.crt)" "$@"
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
	fingerprint="$(lxd config get pg volatile.base_image)"
	jq -n --arg scenarios "$LAB_SCENARIOS" --arg image "$LAB_IMAGE" --arg fingerprint "$fingerprint" \
		--arg pg "$version" --arg ip "$(pg_ip)" --arg driver "$(lxc storage show "$LAB_STORAGE_POOL" | awk '/^driver:/ {print $2}')" \
		--arg ca "$(sha256sum "$LAB_STATE_DIR/pki/ca.crt" | cut -d' ' -f1)" \
		--arg cert "$(sha256sum "$LAB_STATE_DIR/pki/pg.crt" | cut -d' ' -f1)" \
		--arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		'{scenarios: $scenarios, recorded_at: $at, storage_driver: $driver,
		  pg: {image: $image, image_fingerprint: $fingerprint, version: $pg, address: $ip,
		       ca_sha256: $ca, cert_sha256: $cert}}' >"$LAB_STATE_DIR/env.json.new"
	# keep when the snapshot was taken
	if [[ -f "$LAB_STATE_DIR/env.json" ]]; then
		jq -s '.[0] + (.[1] | {snapshot_at} | with_entries(select(.value != null)))' \
			"$LAB_STATE_DIR/env.json.new" "$LAB_STATE_DIR/env.json" >"$LAB_STATE_DIR/env.json.merged"
		mv "$LAB_STATE_DIR/env.json.merged" "$LAB_STATE_DIR/env.json.new"
	fi
	mv "$LAB_STATE_DIR/env.json.new" "$LAB_STATE_DIR/env.json"
}
