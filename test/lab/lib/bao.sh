# shellcheck shell=bash
# The identity scenario's OpenBao: one server per zone, over TLS with the lab
# CA, Raft storage on one node, initialized and unsealed by the lab, and
# configured as ligo's operations would (.specs/ligo-test-environment.md,
# "OpenBao"). The unseal key and the root token stay in the state directory.

BAO_PORT=8200

# bao_state ZONE: the file with the zone's unseal key and root token.
bao_state() { echo "$LAB_STATE_DIR/bao-$1.json"; }

# bao ZONE ARGS: the bao CLI on the zone's server, as the root token (lab
# administration only).
bao() {
	local zone="$1"
	shift
	inner_exec "bao-$zone" env BAO_ADDR="https://127.0.0.1:$BAO_PORT" BAO_CACERT=/etc/openbao/lab-ca.crt \
		sh -c 'BAO_TOKEN="$(cat /root/.bao-root-token)" exec bao "$@"' bao "$@"
}

# bao_conf ZONE: OpenBao's configuration.
bao_conf() {
	cat <<CONF
ui            = false
disable_mlock = true
api_addr      = "https://bao-$1.ligo.lab:$BAO_PORT"
cluster_addr  = "https://bao-$1.ligo.lab:8201"

storage "raft" {
  path    = "/opt/openbao/data"
  node_id = "bao-$1"
}

listener "tcp" {
  address         = "0.0.0.0:$BAO_PORT"
  tls_cert_file   = "/opt/openbao/tls/tls.crt"
  tls_key_file    = "/opt/openbao/tls/tls.key"
  tls_min_version = "tls12"
}
CONF
}

# bao_release: the cached OpenBao .deb, verified against the release's
# checksums file.
bao_release() {
	local base="https://github.com/openbao/openbao/releases/download/v$LAB_OPENBAO_VERSION"
	local file="openbao_${LAB_OPENBAO_VERSION}_linux_amd64.deb" sha
	sha="$(curl -fsSL --proto '=https' "$base/checksums.txt" | awk -v f="$file" '$2 == f {print $1}')"
	[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "no published SHA-256 for $file"
	fetch "$base/$file" "$sha"
}

# bao_server_up ZONE: the zone's OpenBao, installed, initialized, unsealed
# and configured.
bao_server_up() {
	local zone="$1" name="bao-$1" tmp
	inner_container "$name" "$LAB_BAO_MEMORY"
	pki_issue "$name" "DNS:$name.ligo.lab,IP:$(inner_ip "$name"),IP:127.0.0.1"
	if ! inner_exec "$name" test -x /usr/bin/bao; then
		inner_push "$(bao_release)" "$name" /root/openbao.deb 0644
		inner_exec "$name" sh -ec "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/openbao.deb >/dev/null 2>&1; rm -f /root/openbao.deb"
		info "$name: OpenBao $LAB_OPENBAO_VERSION installed"
	fi
	tmp="$(mktemp -d)"
	bao_conf "$zone" >"$tmp/openbao.hcl"
	inner_push "$tmp/openbao.hcl" "$name" /etc/openbao/openbao.hcl 0640
	rm -rf "${tmp:?}"
	inner_push "$LAB_STATE_DIR/pki/$name.crt" "$name" /opt/openbao/tls/tls.crt 0644
	inner_push "$LAB_STATE_DIR/pki/$name.key" "$name" /opt/openbao/tls/tls.key 0600
	inner_push "$LAB_STATE_DIR/pki/ca.crt" "$name" /etc/openbao/lab-ca.crt 0644
	inner_exec "$name" sh -ec "
		chown -R openbao:openbao /etc/openbao /opt/openbao
		grep -q BAO_CACERT /etc/openbao/openbao.env || printf 'BAO_ADDR=https://127.0.0.1:$BAO_PORT\nBAO_CACERT=/etc/openbao/lab-ca.crt\n' >>/etc/openbao/openbao.env
		systemctl enable openbao >/dev/null 2>&1
		systemctl restart openbao"
	bao_wait "$zone"
	bao_init "$zone"
	bao_unseal "$zone"
	bao_configure "$zone"
	info "$name: OpenBao of zone $zone initialized, unsealed and configured"
}

# bao_status ZONE: "bao status" as JSON (exit status 2 means sealed).
bao_status() { inner_exec "bao-$1" env BAO_ADDR="https://127.0.0.1:$BAO_PORT" BAO_CACERT=/etc/openbao/lab-ca.crt bao status -format=json 2>/dev/null || true; }

# bao_wait ZONE: waits until the server answers (sealed or not).
bao_wait() {
	local i
	for i in $(seq 1 60); do
		bao_status "$1" | jq -e 'has("initialized")' >/dev/null 2>&1 && return
		sleep 1
	done
	die "bao-$1: OpenBao does not answer (lab.sh logs bao-$1 openbao)"
}

# bao_init ZONE: initializes the server once, with one unseal key, and keeps
# the key and the root token in the state directory (and the token in the
# container, for the bao helper).
bao_init() {
	local zone="$1" state
	state="$(bao_state "$zone")"
	if [[ "$(bao_status "$zone" | jq -r .initialized)" != true ]]; then
		(
			umask 077
			inner_exec "bao-$zone" env BAO_ADDR="https://127.0.0.1:$BAO_PORT" BAO_CACERT=/etc/openbao/lab-ca.crt \
				bao operator init -key-shares=1 -key-threshold=1 -format=json >"$state"
		) || die "bao-$zone: cannot initialize OpenBao"
		info "bao-$zone: initialized (unseal key and root token in $state)"
	fi
	[[ -s "$state" ]] || die "bao-$zone is initialized but $state is missing: lab.sh down, then up"
	local tmp
	tmp="$(mktemp)"
	jq -r .root_token "$state" >"$tmp"
	inner_push "$tmp" "bao-$zone" /root/.bao-root-token 0600
	rm -f "${tmp:?}"
}

# bao_unseal ZONE: unseals the server when it is sealed (after every start).
bao_unseal() {
	local zone="$1"
	[[ "$(bao_status "$zone" | jq -r .sealed)" == false ]] && return
	inner_exec "bao-$zone" env BAO_ADDR="https://127.0.0.1:$BAO_PORT" BAO_CACERT=/etc/openbao/lab-ca.crt \
		bao operator unseal "$(jq -r '.unseal_keys_b64[0]' "$(bao_state "$zone")")" >/dev/null ||
		die "bao-$zone: cannot unseal"
	local i
	for i in $(seq 1 30); do
		[[ "$(bao_status "$zone" | jq -r '.sealed')" == false ]] && bao "$zone" status >/dev/null 2>&1 && return
		sleep 1
	done
	die "bao-$zone: still sealed"
}

# bao_configure ZONE: the engines, the JWT auth trusting the zone's SPIRE,
# and, in prod, the role ligo-sealer (ADR-07): idempotent.
bao_configure() {
	local zone="$1"
	bao "$zone" secrets list -format=json | jq -e '."transit/"' >/dev/null || bao "$zone" secrets enable transit >/dev/null
	bao "$zone" read transit/keys/ligo-interstage >/dev/null 2>&1 || bao "$zone" write -f transit/keys/ligo-interstage >/dev/null
	bao "$zone" secrets list -format=json | jq -e '."kv/"' >/dev/null || bao "$zone" secrets enable -path=kv kv-v2 >/dev/null
	bao "$zone" auth list -format=json | jq -e '."jwt-spiffe/"' >/dev/null || bao "$zone" auth enable -path=jwt-spiffe jwt >/dev/null
	bao "$zone" write auth/jwt-spiffe/config \
		oidc_discovery_url="https://spire-$zone.ligo.lab:$OIDC_PORT" \
		oidc_discovery_ca_pem=@/etc/openbao/lab-ca.crt >/dev/null || die "bao-$zone: cannot configure the JWT auth"
	[[ "$zone" == prod ]] || return 0
	inner_exec "bao-$zone" sh -c 'cat >/root/ligo-sealer.hcl' <<'HCL'
# ligo's sealer (ADR-07): wrap and unwrap data keys, nothing else
path "transit/encrypt/ligo-interstage" {
  capabilities = ["update"]
}
path "transit/decrypt/ligo-interstage" {
  capabilities = ["update"]
}
HCL
	bao "$zone" policy write ligo-sealer /root/ligo-sealer.hcl >/dev/null
	bao "$zone" write auth/jwt-spiffe/role/ligo-sealer role_type=jwt user_claim=sub \
		bound_subject="spiffe://prod.lab/ns/sys/sa/ligo" bound_audiences="https://bao-prod.ligo.lab" \
		token_policies=ligo-sealer token_ttl=15m token_max_ttl=1h >/dev/null || die "bao-prod: cannot write the role ligo-sealer"
}

# bao_check: as the user ligo on ligo1, logs in to bao-prod with a JWT-SVID
# and wraps a key with Transit (step 3's done criterion).
bao_check() {
	local uid
	uid="$(env_get .ligo1.ligo_uid)"
	inner_exec ligo1 mkdir -p /etc/ligo-lab
	inner_push "$LAB_STATE_DIR/pki/ca.crt" ligo1 /etc/ligo-lab/ca.crt 0644
	lxd exec lxd -- lxc exec ligo1 --user "$uid" -- sh -ec '
		jwt="$(/opt/spire/bin/spire-agent api fetch jwt -audience https://bao-prod.ligo.lab -socketPath /run/spire/prod/agent.sock -output json | jq -r ".[0].svids[0].svid")"
		token="$(curl -fsS --cacert /etc/ligo-lab/ca.crt -X POST https://bao-prod.ligo.lab:8200/v1/auth/jwt-spiffe/login \
			-d "{\"role\":\"ligo-sealer\",\"jwt\":\"$jwt\"}" | jq -r .auth.client_token)"
		curl -fsS --cacert /etc/ligo-lab/ca.crt -H "X-Vault-Token: $token" -X POST \
			https://bao-prod.ligo.lab:8200/v1/transit/encrypt/ligo-interstage -d "{\"plaintext\":\"bGFiLWNoZWNr\"}" |
			jq -e ".data.ciphertext | startswith(\"vault:v\")" >/dev/null
		! curl -fsS --cacert /etc/ligo-lab/ca.crt -H "X-Vault-Token: $token" https://bao-prod.ligo.lab:8200/v1/kv/data/x >/dev/null 2>&1
	' || die "ligo1: the JWT-SVID login to bao-prod, or Transit, does not work"
	info "ligo1, user ligo: logged in to bao-prod with its JWT-SVID, encrypted with transit/ligo-interstage, denied elsewhere"
}

# identity_bao_up: both zones' OpenBao, then the check.
identity_bao_up() {
	section "OpenBao (prod, test)"
	local zone
	for zone in "${ZONES[@]}"; do
		bao_server_up "$zone"
	done
	bao_check
	env_set .openbao "$(jq -n --arg v "$LAB_OPENBAO_VERSION" '{version: $v}')"
}
