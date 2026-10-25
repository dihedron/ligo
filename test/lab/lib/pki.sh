# shellcheck shell=bash
# The lab PKI: a CA and the PostgreSQL server's certificate, and the role
# passwords. Everything stays in the state directory.

pki_up() {
	local dir="$LAB_STATE_DIR/pki"
	mkdir -p "$dir" "$LAB_STATE_DIR/passwords"
	chmod 0700 "$LAB_STATE_DIR" "$dir" "$LAB_STATE_DIR/passwords"
	if [[ ! -f "$dir/ca.crt" ]]; then
		openssl req -x509 -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
			-keyout "$dir/ca.key" -out "$dir/ca.crt" -days 3650 -subj "/CN=ligo lab CA" 2>/dev/null
		info "lab CA created"
	fi
	if [[ ! -f "$dir/pg.crt" ]]; then
		openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
			-keyout "$dir/pg.key" -out "$dir/pg.csr" -subj "/CN=pg.ligo.lab" 2>/dev/null
		openssl x509 -req -in "$dir/pg.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
			-days 365 -out "$dir/pg.crt" \
			-extfile <(printf 'subjectAltName=DNS:pg.ligo.lab,IP:%s,IP:%s\nextendedKeyUsage=serverAuth\n' "$(pg_ip)" "$(lxd_ip)") 2>/dev/null
		rm -f "${dir:?}/pg.csr"
		info "PostgreSQL server certificate issued for pg.ligo.lab, $(pg_ip) and $(lxd_ip)"
	fi
	chmod 0600 "$dir"/*.key
	local role
	for role in migrator app reader dbos; do
		if [[ ! -f "$LAB_STATE_DIR/passwords/$role" ]]; then
			(umask 077 && openssl rand -hex 24 >"$LAB_STATE_DIR/passwords/$role")
		fi
	done
}

# password ROLE: the password of ligo_ROLE.
password() { cat "$LAB_STATE_DIR/passwords/$1"; }

# pki_issue NAME SANS: issues a server certificate NAME.crt/.key from the lab
# CA, once, with SANS (an openssl subjectAltName value).
pki_issue() {
	local dir="$LAB_STATE_DIR/pki" name="$1" sans="$2"
	[[ -f "$dir/$name.crt" ]] && return
	openssl req -new -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
		-keyout "$dir/$name.key" -out "$dir/$name.csr" -subj "/CN=$name.ligo.lab" 2>/dev/null
	openssl x509 -req -in "$dir/$name.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -CAcreateserial \
		-days 365 -out "$dir/$name.crt" \
		-extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$sans") 2>/dev/null
	rm -f "${dir:?}/${name:?}.csr"
	chmod 0600 "$dir/$name.key"
	info "certificate issued for $name ($sans)"
}

# pki_client NAME: a self-signed client certificate NAME.crt/.key, once (the
# SPIRE servers' identities on the inner LXD).
pki_client() {
	local dir="$LAB_STATE_DIR/pki" name="$1"
	[[ -f "$dir/$name.crt" ]] && return
	(
		umask 077
		openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 730 -subj "/CN=$name" \
			-addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=clientAuth" \
			-keyout "$dir/$name.key" -out "$dir/$name.crt" 2>/dev/null
	)
	info "client certificate created for $name"
}
