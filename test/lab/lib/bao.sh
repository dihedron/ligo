# shellcheck shell=bash
# The identity scenario's OpenBao: one server per realm, over TLS with the lab
# CA, Raft storage on one node, initialized and unsealed by the lab, and
# configured as ligo's operations would (.specs/ligo-test-environment.md,
# "OpenBao"). The unseal key and the root token stay in the state directory.
# The scenario vault adds HashiCorp Vault, set up the same way.

BAO_PORT=8200

# The backend the lab uses, recorded by lab.sh secrets: openbao, or vault
# (scenario vault). Only its servers run: anything still pointing at the other
# fails (.specs/ligo-test-environment.md, "HashiCorp Vault").
secrets_backend() { env_get '.secrets // "openbao"'; }

# secrets_host: the selected backend's server of realm prod.
secrets_host() { if [[ "$(secrets_backend)" == vault ]]; then echo vault-prod; else echo bao-prod; fi; }

# secrets_audience: its JWT audience; secrets_addr: its address.
secrets_audience() { echo "https://$(secrets_host).ligo.lab"; }
secrets_addr() { echo "$(secrets_audience):$BAO_PORT"; }

# server_ca SERVER: where SERVER keeps the lab CA.
server_ca() { case "$1" in vault-*) echo /etc/vault/lab-ca.crt ;; *) echo /etc/openbao/lab-ca.crt ;; esac; }

# bao_state SERVER: the file with the server's unseal key and root token.
bao_state() { echo "$LAB_STATE_DIR/$1.json"; }

# server_cli SERVER ARGS: the server's CLI, as the root token once it has one
# (lab administration only).
server_cli() {
	local server="$1"
	shift
	case "$server" in
	vault-*)
		inner_exec "$server" env VAULT_ADDR="https://127.0.0.1:$BAO_PORT" VAULT_CACERT="$(server_ca "$server")" \
			sh -c 'VAULT_TOKEN="$(cat /root/.bao-root-token 2>/dev/null)" exec vault "$@"' vault "$@"
		;;
	*)
		inner_exec "$server" env BAO_ADDR="https://127.0.0.1:$BAO_PORT" BAO_CACERT="$(server_ca "$server")" \
			sh -c 'BAO_TOKEN="$(cat /root/.bao-root-token 2>/dev/null)" exec bao "$@"' bao "$@"
		;;
	esac
}

# bao REALM ARGS: the bao CLI on the realm's OpenBao.
bao() {
	local realm="$1"
	shift
	server_cli "bao-$realm" "$@"
}

# secrets_cli ARGS: the CLI on the selected backend's server of realm prod.
secrets_cli() { server_cli "$(secrets_host)" "$@"; }

# bao_conf REALM: OpenBao's configuration.
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

# bao_server_up REALM: the realm's OpenBao, installed, initialized, unsealed
# and configured.
bao_server_up() {
	local realm="$1" name="bao-$1" tmp
	inner_container "$name" "$LAB_BAO_MEMORY"
	pki_issue "$name" "DNS:$name.ligo.lab,IP:$(inner_ip "$name"),IP:127.0.0.1"
	if ! inner_exec "$name" test -x /usr/bin/bao; then
		inner_push "$(bao_release)" "$name" /root/openbao.deb 0644
		inner_exec "$name" sh -ec "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /root/openbao.deb >/dev/null 2>&1; rm -f /root/openbao.deb"
		info "$name: OpenBao $LAB_OPENBAO_VERSION installed"
	fi
	tmp="$(mktemp -d)"
	bao_conf "$realm" >"$tmp/openbao.hcl"
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
	bao_wait "$name"
	bao_init "$name"
	bao_unseal "$name"
	bao_configure "$name"
	info "$name: OpenBao of realm $realm initialized, unsealed and configured"
}

# bao_status SERVER: "status" as JSON (exit status 2 means sealed).
bao_status() { server_cli "$1" status -format=json 2>/dev/null || true; }

# bao_wait SERVER: waits until the server answers (sealed or not).
bao_wait() {
	local i
	for i in $(seq 1 60); do
		bao_status "$1" | jq -e 'has("initialized")' >/dev/null 2>&1 && return
		sleep 1
	done
	die "$1 does not answer (lab.sh logs $1 <unit>)"
}

# bao_init SERVER: initializes the server once, with one unseal key, and keeps
# the key and the root token in the state directory (and the token in the
# container, for server_cli).
bao_init() {
	local server="$1" state
	state="$(bao_state "$server")"
	if [[ "$(bao_status "$server" | jq -r .initialized)" != true ]]; then
		(
			umask 077
			server_cli "$server" operator init -key-shares=1 -key-threshold=1 -format=json >"$state"
		) || die "$server: cannot initialize"
		info "$server: initialized (unseal key and root token in $state)"
	fi
	[[ -s "$state" ]] || die "$server is initialized but $state is missing: lab.sh down, then up"
	local tmp
	tmp="$(mktemp)"
	jq -r .root_token "$state" >"$tmp"
	inner_push "$tmp" "$server" /root/.bao-root-token 0600
	rm -f "${tmp:?}"
}

# bao_unseal SERVER: unseals the server when it is sealed (after every start),
# and waits until it serves: on Raft it needs a moment to become leader.
bao_unseal() {
	local server="$1"
	if [[ "$(bao_status "$server" | jq -r .sealed)" != false ]]; then
		server_cli "$server" operator unseal "$(jq -r '.unseal_keys_b64[0]' "$(bao_state "$server")")" >/dev/null ||
			die "$server: cannot unseal"
	fi
	local i
	for i in $(seq 1 30); do
		server_cli "$server" secrets list >/dev/null 2>&1 && return
		sleep 1
	done
	die "$server: still sealed, or without a leader"
}

# bao_configure SERVER: the engines, the JWT auth trusting the realm's SPIRE,
# and, in prod, the role ligo-sealer (ADR-07): idempotent.
bao_configure() {
	local server="$1" realm="${1##*-}"
	server_cli "$server" secrets list -format=json | jq -e '."transit/"' >/dev/null || server_cli "$server" secrets enable transit >/dev/null
	server_cli "$server" read transit/keys/ligo-interstage >/dev/null 2>&1 || server_cli "$server" write -f transit/keys/ligo-interstage >/dev/null
	server_cli "$server" secrets list -format=json | jq -e '."kv/"' >/dev/null || server_cli "$server" secrets enable -path=kv kv-v2 >/dev/null
	server_cli "$server" auth list -format=json | jq -e '."jwt-spiffe/"' >/dev/null || server_cli "$server" auth enable -path=jwt-spiffe jwt >/dev/null
	server_cli "$server" write auth/jwt-spiffe/config \
		oidc_discovery_url="https://spire-$realm.ligo.lab:$OIDC_PORT" \
		oidc_discovery_ca_pem="@$(server_ca "$server")" >/dev/null || die "$server: cannot configure the JWT auth"
	[[ "$realm" == prod ]] || return 0
	# the ed25519 key that signs audit checkpoints (§4.3)
	server_cli "$server" read transit/keys/ligo-audit >/dev/null 2>&1 || server_cli "$server" write transit/keys/ligo-audit type=ed25519 >/dev/null
	inner_exec "$server" sh -c 'cat >/root/ligo-sealer.hcl' <<'HCL'
# ligo's sealer (ADR-07): wrap and unwrap data keys, sign audit checkpoints
# and read their public keys, nothing else
path "transit/encrypt/ligo-interstage" {
  capabilities = ["update"]
}
path "transit/decrypt/ligo-interstage" {
  capabilities = ["update"]
}
path "transit/sign/ligo-audit" {
  capabilities = ["update"]
}
path "transit/keys/ligo-audit" {
  capabilities = ["read"]
}
HCL
	server_cli "$server" policy write ligo-sealer /root/ligo-sealer.hcl >/dev/null
	server_cli "$server" write auth/jwt-spiffe/role/ligo-sealer role_type=jwt user_claim=sub \
		bound_subject="spiffe://prod.lab/ns/sys/sa/ligo" bound_audiences="https://$server.ligo.lab" \
		token_policies=ligo-sealer token_ttl=15m token_max_ttl=1h >/dev/null || die "$server: cannot write the role ligo-sealer"
}

# bao_check: as the user ligo on each ligo host, logs in to the selected
# backend's server of realm prod with a JWT-SVID and wraps a key with Transit
# (step 3's done criterion).
bao_check() {
	local host uid server
	server="$(secrets_host)"
	for host in $(ligo_hosts); do
		uid="$(env_get ".$host.ligo_uid")"
		inner_exec "$host" mkdir -p /etc/ligo-lab
		inner_push "$LAB_STATE_DIR/pki/ca.crt" "$host" /etc/ligo-lab/ca.crt 0644
		lxd exec lxd -- lxc exec "$host" --user "$uid" --env "S=$server.ligo.lab" -- sh -ec '
			jwt="$(/opt/spire/bin/spire-agent api fetch jwt -audience "https://$S" -socketPath /run/spire/prod/agent.sock -output json | jq -r ".[0].svids[0].svid")"
			token="$(curl -fsS --cacert /etc/ligo-lab/ca.crt -X POST "https://$S:8200/v1/auth/jwt-spiffe/login" \
				-d "{\"role\":\"ligo-sealer\",\"jwt\":\"$jwt\"}" | jq -r .auth.client_token)"
			curl -fsS --cacert /etc/ligo-lab/ca.crt -H "X-Vault-Token: $token" -X POST \
				"https://$S:8200/v1/transit/encrypt/ligo-interstage" -d "{\"plaintext\":\"bGFiLWNoZWNr\"}" |
				jq -e ".data.ciphertext | startswith(\"vault:v\")" >/dev/null
			curl -fsS --cacert /etc/ligo-lab/ca.crt -H "X-Vault-Token: $token" -X POST \
				"https://$S:8200/v1/transit/sign/ligo-audit" -d "{\"input\":\"bGFiLWNoZWNr\"}" |
				jq -e ".data.signature | startswith(\"vault:v\")" >/dev/null
			curl -fsS --cacert /etc/ligo-lab/ca.crt -H "X-Vault-Token: $token" "https://$S:8200/v1/transit/keys/ligo-audit" |
				jq -e ".data.type == \"ed25519\"" >/dev/null
			! curl -fsS --cacert /etc/ligo-lab/ca.crt -H "X-Vault-Token: $token" "https://$S:8200/v1/kv/data/x" >/dev/null 2>&1
		' || die "$host: the JWT-SVID login to $server, or Transit, does not work"
		info "$host, user ligo: logged in to $server with its JWT-SVID, encrypted with transit/ligo-interstage, signed with transit/ligo-audit, denied elsewhere"
	done
}

# vault_conf: HashiCorp Vault's configuration.
vault_conf() {
	cat <<CONF
ui            = false
disable_mlock = true
api_addr      = "https://vault-prod.ligo.lab:$BAO_PORT"
cluster_addr  = "https://vault-prod.ligo.lab:8201"

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-prod"
}

listener "tcp" {
  address         = "0.0.0.0:$BAO_PORT"
  tls_cert_file   = "/opt/vault/tls/tls.crt"
  tls_key_file    = "/opt/vault/tls/tls.key"
  tls_min_version = "tls12"
}
CONF
}

# vault_unit: Vault's systemd unit, as an unprivileged user.
vault_unit() {
	cat <<'UNIT'
[Unit]
Description=HashiCorp Vault (lab)
After=network-online.target

[Service]
User=vault
ExecStart=/usr/local/bin/vault server -config=/etc/vault/vault.hcl
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT
}

# vault_release: the cached Vault zip, verified against the release's checksums
# file.
vault_release() {
	local base="https://releases.hashicorp.com/vault/$LAB_VAULT_VERSION"
	local file="vault_${LAB_VAULT_VERSION}_linux_amd64.zip" sha
	sha="$(curl -fsSL --proto '=https' "$base/vault_${LAB_VAULT_VERSION}_SHA256SUMS" | awk -v f="$file" '$2 == f {print $1}')"
	[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "no published SHA-256 for $file"
	fetch "$base/$file" "$sha"
}

# vault_up: the container vault-prod with Vault, installed, initialized,
# unsealed and configured as OpenBao is. Realm prod only: nothing uses another.
vault_up() {
	section "HashiCorp Vault (prod)"
	local name=vault-prod tmp
	inner_container "$name" "$LAB_BAO_MEMORY"
	pki_issue "$name" "DNS:$name.ligo.lab,IP:$(inner_ip "$name"),IP:127.0.0.1"
	tmp="$(mktemp -d)"
	if ! inner_exec "$name" test -x /usr/local/bin/vault; then
		unzip -p "$(vault_release)" vault >"$tmp/vault"
		inner_push "$tmp/vault" "$name" /usr/local/bin/vault 0755
		info "$name: Vault $LAB_VAULT_VERSION installed"
	fi
	inner_exec "$name" sh -ec '
		id vault >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin vault
		install -d -m 0755 /etc/vault /opt/vault
		install -d -m 0700 /opt/vault/data /opt/vault/tls
		chown vault:vault /opt/vault/data /opt/vault/tls'
	vault_conf >"$tmp/vault.hcl"
	vault_unit >"$tmp/vault.service"
	inner_push "$tmp/vault.hcl" "$name" /etc/vault/vault.hcl 0644
	inner_push "$tmp/vault.service" "$name" /etc/systemd/system/vault.service 0644
	rm -rf "${tmp:?}"
	inner_push "$LAB_STATE_DIR/pki/$name.crt" "$name" /opt/vault/tls/tls.crt 0644
	inner_push "$LAB_STATE_DIR/pki/$name.key" "$name" /opt/vault/tls/tls.key 0600
	inner_push "$LAB_STATE_DIR/pki/ca.crt" "$name" /etc/vault/lab-ca.crt 0644
	inner_exec "$name" sh -ec '
		chown vault:vault /opt/vault/tls/tls.crt /opt/vault/tls/tls.key
		systemctl daemon-reload
		systemctl enable vault >/dev/null 2>&1
		systemctl restart vault'
	bao_wait "$name"
	bao_init "$name"
	bao_unseal "$name"
	bao_configure "$name"
	env_set .vault "$(jq -n --arg v "$LAB_VAULT_VERSION" '{version: $v}')"
	info "$name: Vault of realm prod initialized, unsealed and configured"
}

# secrets_apply: only the selected backend's servers run, unsealed.
secrets_apply() {
	local server keep=(bao-prod bao-test) stop=(vault-prod)
	if [[ "$(secrets_backend)" == vault ]]; then
		keep=(vault-prod) stop=(bao-prod bao-test)
	fi
	for server in "${keep[@]}"; do
		inner_exists "$server" || continue
		inner_start "$server"
		bao_wait "$server"
		bao_unseal "$server"
	done
	for server in "${stop[@]}"; do
		if inner_exists "$server" && inner_running "$server"; then
			inner stop "$server"
		fi
	done
}

# cmd_secrets [openbao|vault]: prints the backend, or selects one; ligo then
# needs lab.sh serve install, and a database without the other's sealed data
# (lab.sh reset first).
cmd_secrets() {
	case "${1:-}" in
	"") secrets_backend && return ;;
	openbao) ;;
	vault) inner_exists vault-prod || die "no Vault: lab.sh up --scenario vault" ;;
	*) die "secrets: openbao or vault" ;;
	esac
	env_set .secrets "$(jq -n --arg b "$1" '$b')"
	secrets_apply
	bao_check
	info "the backend is $1: run lab.sh serve install"
}

# identity_bao_up: both realms' OpenBao, Vault with its scenario, then the
# check on the selected backend.
identity_bao_up() {
	section "OpenBao (prod, test)"
	local realm
	for realm in "${REALMS[@]}"; do
		bao_server_up "$realm"
	done
	env_set .openbao "$(jq -n --arg v "$LAB_OPENBAO_VERSION" '{version: $v}')"
	if selected vault || inner_exists vault-prod; then
		vault_up
	fi
	secrets_apply
	bao_check
}
