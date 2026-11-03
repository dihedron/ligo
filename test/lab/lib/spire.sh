# shellcheck shell=bash
# The identity scenario's SPIRE: one server per trust domain (prod.lab,
# test.lab), each with its OIDC discovery provider, and each ligo host (ligo1,
# and ligo2 with ha) with one agent per trust domain, attested by
# lxd-spiffe's lxd_iid plugins through the inner LXD
# (.specs/ligo-test-environment.md, "SPIRE").

ZONES=(prod test)
SPIRE_PREFIX=/opt/spire
SPIRE_PORT=8081
OIDC_PORT=8008

# spire ZONE ARGS: spire-server on a zone's server.
spire() {
	local zone="$1"
	shift
	inner_exec "spire-$zone" "$SPIRE_PREFIX/bin/spire-server" "$@" -socketPath /run/spire/server/api.sock
}

# inner_container NAME MEMORY: creates an inner container with its fixed
# address, once, and starts it.
inner_container() {
	local name="$1" memory="$2"
	if ! inner_exists "$name"; then
		inner_init "$name" -c limits.memory="$memory" -c boot.autostart=true \
			-d eth0,ipv4.address="$(inner_ip "$name")" >/dev/null
		info "container $name created"
	fi
	inner_start "$name"
	inner_wait "$name"
}

# inner_lxd_fingerprint: the SHA-256 of the inner LXD's certificate (the pin).
inner_lxd_fingerprint() { inner query /1.0 | jq -r .environment.certificate_fingerprint; }

# spire_identity ZONE: the zone's SPIRE server identity on the inner LXD:
# group spire-ZONE with can_view and can_view_instances on project default,
# and can_view and can_access_files on each ligo host (file_pull).
spire_identity() {
	local zone="$1" group="spire-$1"
	pki_client "spire-$zone-lxd"
	if ! inner query /1.0/auth/groups | jq -e --arg g "/1.0/auth/groups/$group" 'index($g)' >/dev/null; then
		inner auth group create "$group" >/dev/null
	fi
	if ! inner auth identity list -f csv | grep -q "^tls,[^,]*,$group,"; then
		inner query -X POST /1.0/auth/identities/tls --data "$(jq -n --arg name "$group" --arg group "$group" \
			--rawfile cert "$LAB_STATE_DIR/pki/spire-$zone-lxd.crt" '{name: $name, certificate: $cert, groups: [$group]}')" >/dev/null ||
			die "cannot trust identity $group on the inner LXD"
	fi
	local entitlement
	for entitlement in can_view can_view_instances; do
		inner auth group permission add "$group" project default "$entitlement" >/dev/null 2>&1 || true
	done
	local host hosts
	hosts="$(ligo_hosts | wc -l)"
	for host in $(ligo_hosts); do
		for entitlement in can_view can_access_files; do
			inner auth group permission add "$group" instance "$host" "$entitlement" project=default >/dev/null 2>&1 || true
		done
	done
	inner query "/1.0/auth/groups/$group" | jq -e --argjson n "$((2 * hosts))" '[.permissions[] | select(.entity_type == "instance")] | length == $n' >/dev/null ||
		die "$group: the grants on the ligo hosts are missing"
}

# server_conf ZONE CHECKSUM: SPIRE Server's configuration.
server_conf() {
	local zone="$1"
	cat <<CONF
server {
  bind_address = "0.0.0.0"
  bind_port    = "$SPIRE_PORT"
  socket_path  = "/run/spire/server/api.sock"
  trust_domain = "$zone.lab"
  data_dir     = "/var/lib/spire/server"
  log_level    = "INFO"
  ca_ttl       = "168h"
  jwt_issuer   = "https://spire-$zone.ligo.lab:$OIDC_PORT"
}

plugins {
  DataStore "sql" {
    plugin_data {
      database_type     = "sqlite3"
      connection_string = "/var/lib/spire/server/datastore.sqlite3"
    }
  }
  KeyManager "disk" {
    plugin_data {
      keys_path = "/var/lib/spire/server/keys.json"
    }
  }
  NodeAttestor "lxd_iid" {
    plugin_cmd      = "/usr/bin/lxd-server-plugin"
    plugin_checksum = "$2"
    plugin_data {
      proof_mode = "file_pull"
      # the agent of this zone on each ligo host uses its own directory: they must match
      proof_dir  = "/run/spire/lxd-$zone"
      servers = {
        "inner" = {
          url                     = "https://$(inner_gateway):8443"
          client_cert_file        = "/etc/spire/lxd/client.crt"
          client_key_file         = "/etc/spire/lxd/client.key"
          server_cert_fingerprint = "sha256:$(inner_lxd_fingerprint)"
          projects                = ["default"]
        }
      }
    }
  }
}
CONF
}

# oidc_conf ZONE: the OIDC discovery provider's configuration: the zone's JWT
# keys over TLS with the lab CA's certificate, read from the server's socket.
oidc_conf() {
	cat <<CONF
log_level = "INFO"
domains   = ["spire-$1.ligo.lab", "$(inner_ip "spire-$1")"]
serving_cert_file {
  cert_file_path = "/etc/spire/oidc/server.crt"
  key_file_path  = "/etc/spire/oidc/server.key"
  addr           = ":$OIDC_PORT"
}
server_api {
  address = "unix:///run/spire/server/api.sock"
}
CONF
}

# unit DESCRIPTION USER EXEC [AFTER [RUNTIME-DIRECTORY]]: a systemd unit
# file; the runtime directory under /run is recreated on every start.
unit() {
	cat <<UNIT
[Unit]
Description=$1 (ligo lab)
After=network-online.target ${4:-}
Wants=network-online.target

[Service]
User=$2
ExecStart=$3
${5:+RuntimeDirectory=$5
RuntimeDirectoryPreserve=yes
}Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
}

# spire_server_up ZONE: the zone's SPIRE Server and OIDC discovery provider.
spire_server_up() {
	local zone="$1" name="spire-$1" tarball extras deb checksum tmp
	inner_container "$name" "$LAB_SPIRE_MEMORY"
	tarball="$(spire_release spire)"
	extras="$(spire_release spire-extras)"
	deb="$(lxd_spiffe_package lxd-server-plugin)"
	pki_issue "$name" "DNS:$name.ligo.lab,IP:$(inner_ip "$name")"
	if ! inner_exec "$name" test -x /usr/bin/lxd-server-plugin; then
		inner_push "$tarball" "$name" /root/spire.tar.gz 0644
		inner_push "$extras" "$name" /root/spire-extras.tar.gz 0644
		inner_push "$deb" "$name" /root/lxd-server-plugin.deb 0644
		inner_exec "$name" sh -ec "
			id spire >/dev/null 2>&1 || useradd --system --home /var/lib/spire --shell /usr/sbin/nologin spire
			mkdir -p $SPIRE_PREFIX /etc/spire/lxd /etc/spire/oidc /var/lib/spire/server
			tar -xzf /root/spire.tar.gz -C $SPIRE_PREFIX --strip-components=1
			tar -xzf /root/spire-extras.tar.gz -C $SPIRE_PREFIX --strip-components=1
			dpkg -i /root/lxd-server-plugin.deb >/dev/null
			rm -f /root/spire.tar.gz /root/spire-extras.tar.gz /root/lxd-server-plugin.deb"
		info "$name: SPIRE $LAB_SPIRE_VERSION and lxd-server-plugin $LAB_LXD_SPIFFE_VERSION installed"
	fi
	checksum="$(inner_exec "$name" sha256sum /usr/bin/lxd-server-plugin | cut -d' ' -f1)"
	inner_push "$LAB_STATE_DIR/pki/spire-$zone-lxd.crt" "$name" /etc/spire/lxd/client.crt 0444
	inner_push "$LAB_STATE_DIR/pki/spire-$zone-lxd.key" "$name" /etc/spire/lxd/client.key 0400
	inner_push "$LAB_STATE_DIR/pki/$name.crt" "$name" /etc/spire/oidc/server.crt 0444
	inner_push "$LAB_STATE_DIR/pki/$name.key" "$name" /etc/spire/oidc/server.key 0400
	tmp="$(mktemp -d)"
	server_conf "$zone" "$checksum" >"$tmp/server.conf"
	oidc_conf "$zone" >"$tmp/oidc.conf"
	unit "SPIRE Server $zone.lab" spire "$SPIRE_PREFIX/bin/spire-server run -config /etc/spire/server.conf" "" spire/server >"$tmp/spire-server.service"
	unit "SPIRE OIDC discovery provider $zone.lab" spire "$SPIRE_PREFIX/bin/oidc-discovery-provider -config /etc/spire/oidc.conf" spire-server.service >"$tmp/spire-oidc.service"
	inner_push "$tmp/server.conf" "$name" /etc/spire/server.conf 0644
	inner_push "$tmp/oidc.conf" "$name" /etc/spire/oidc.conf 0644
	inner_push "$tmp/spire-server.service" "$name" /etc/systemd/system/spire-server.service 0644
	inner_push "$tmp/spire-oidc.service" "$name" /etc/systemd/system/spire-oidc.service 0644
	rm -rf "${tmp:?}"
	inner_exec "$name" sh -ec "
		chown -R spire:spire /etc/spire /var/lib/spire
		systemctl daemon-reload
		systemctl enable spire-server spire-oidc >/dev/null 2>&1
		systemctl restart spire-server"
	local i
	for i in $(seq 1 60); do
		spire "$zone" healthcheck >/dev/null 2>&1 && break
		sleep 2
	done
	spire "$zone" healthcheck >/dev/null 2>&1 || die "$name: SPIRE Server is not healthy (lab.sh logs $name spire-server)"
	inner_exec "$name" systemctl restart spire-oidc
	info "$name: SPIRE Server of $zone.lab healthy; OIDC discovery on https://$name.ligo.lab:$OIDC_PORT"
}

# agent_conf ZONE CHECKSUM: the zone's SPIRE Agent on a ligo host.
agent_conf() {
	local zone="$1"
	cat <<CONF
agent {
  data_dir          = "/var/lib/spire/agent-$zone"
  log_level         = "INFO"
  server_address    = "spire-$zone.ligo.lab"
  server_port       = "$SPIRE_PORT"
  socket_path       = "/run/spire/$zone/agent.sock"
  trust_bundle_path = "/etc/spire/$zone/bundle.pem"
  trust_domain      = "$zone.lab"
}

plugins {
  NodeAttestor "lxd_iid" {
    plugin_cmd      = "/usr/bin/lxd-agent-plugin"
    plugin_checksum = "$2"
    plugin_data {
      claim {
        project = "default"
      }
      proof_dir = "/run/spire/lxd-$zone"
    }
  }
  KeyManager "disk" {
    plugin_data {
      directory = "/var/lib/spire/agent-$zone"
    }
  }
  WorkloadAttestor "unix" {
    plugin_data {
      # unix:sha256 selectors, which plugin entries use (§10.5)
      discover_workload_path = true
    }
  }
}
CONF
}

# ligo_vm_up HOST: the nested VM HOST (ligo1, ligo2) with the user ligo, SPIRE
# Agent and the agent plugin installed (the agents are configured by
# spire_agents_up). Its sizes are LAB_LIGO1_* or LAB_LIGO2_*.
ligo_vm_up() {
	local host="$1" var
	var="LAB_$(tr '[:lower:]' '[:upper:]' <<<"$host")"
	if ! inner_exists "$host"; then
		if [[ "$host" != ligo1 ]] && (($(size_mib "$(lxd config get lxd limits.memory)") < 8192)); then
			die "$host needs the VM lxd at 8GiB or more, it has $(lxd config get lxd limits.memory): lab.sh stop; lxc --project $LAB_PROJECT config set lxd limits.memory 8GiB; lab.sh start"
		fi
		local cpus="${var}_CPUS" memory="${var}_MEMORY" disk="${var}_DISK"
		inner_init "$host" --vm -c limits.cpu="${!cpus}" -c limits.memory="${!memory}" \
			-c boot.autostart=true -d root,size="${!disk}" -d eth0,ipv4.address="$(inner_ip "$host")" >/dev/null
		info "VM $host created (nested)"
	fi
	inner_start "$host"
	inner_wait "$host"
	inner_exec "$host" sh -c 'id ligo >/dev/null 2>&1 || useradd --create-home --shell /bin/bash ligo'
	inner_exec "$host" sh -c 'command -v jq >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq jq >/dev/null'
	if ! inner_exec "$host" test -x /usr/bin/lxd-agent-plugin; then
		inner_push "$(spire_release spire)" "$host" /root/spire.tar.gz 0644
		inner_push "$(lxd_spiffe_package lxd-agent-plugin)" "$host" /root/lxd-agent-plugin.deb 0644
		inner_exec "$host" sh -ec "
			mkdir -p $SPIRE_PREFIX
			tar -xzf /root/spire.tar.gz -C $SPIRE_PREFIX --strip-components=1
			dpkg -i /root/lxd-agent-plugin.deb >/dev/null
			rm -f /root/spire.tar.gz /root/lxd-agent-plugin.deb"
		info "$host: SPIRE Agent $LAB_SPIRE_VERSION and lxd-agent-plugin $LAB_LXD_SPIFFE_VERSION installed"
	fi
}

# spire_agents_up HOST: one agent per zone on HOST, as root (file_pull,
# lxd-spiffe FR-A7), with the zone's trust bundle.
spire_agents_up() {
	local host="$1" zone checksum tmp
	checksum="$(inner_exec "$host" sha256sum /usr/bin/lxd-agent-plugin | cut -d' ' -f1)"
	tmp="$(mktemp -d)"
	for zone in "${ZONES[@]}"; do
		spire "$zone" bundle show -format pem >"$tmp/bundle.pem"
		agent_conf "$zone" "$checksum" >"$tmp/agent.conf"
		unit "SPIRE Agent $zone.lab" root "$SPIRE_PREFIX/bin/spire-agent run -config /etc/spire/$zone/agent.conf" lxd-agent.service >"$tmp/unit"
		inner_exec "$host" mkdir -p "/etc/spire/$zone" "/var/lib/spire/agent-$zone"
		inner_push "$tmp/bundle.pem" "$host" "/etc/spire/$zone/bundle.pem" 0644
		inner_push "$tmp/agent.conf" "$host" "/etc/spire/$zone/agent.conf" 0644
		inner_push "$tmp/unit" "$host" "/etc/systemd/system/spire-agent-$zone.service" 0644
		inner_exec "$host" sh -ec "systemctl daemon-reload; systemctl enable spire-agent-$zone >/dev/null 2>&1; systemctl restart spire-agent-$zone"
	done
	rm -rf "${tmp:?}"
}

# spire_entries HOST: the node alias of HOST in each zone, and ligo's
# entries under it (§10.5): the core identity on prod, the bundle-access
# identity on test, both for the user ligo (lab deviation: unix:uid only).
# Each host has its own alias, and the same SPIFFE IDs under it.
spire_entries() {
	local host="$1" uuid uid zone id out
	uuid="$(inner config get "$host" volatile.uuid)"
	uid="$(inner_exec "$host" id -u ligo)"
	for zone in "${ZONES[@]}"; do
		spire "$zone" entry show -spiffeID "spiffe://$zone.lab/node/$host" 2>/dev/null | grep -q "lxd_iid:uuid:$uuid" ||
			spire "$zone" entry create -node -spiffeID "spiffe://$zone.lab/node/$host" \
				-selector lxd_iid:server:inner -selector "lxd_iid:uuid:$uuid" >/dev/null
	done
	for id in "prod ns/sys/sa/ligo" "test ns/sys/sa/ligo-bundles"; do
		zone="${id%% *}"
		# captured first: grep -q would cut the pipe, which pipefail reports as a failure
		out="$(spire "$zone" entry show -parentID "spiffe://$zone.lab/node/$host" -spiffeID "spiffe://$zone.lab/${id#* }" 2>/dev/null)" || true
		grep -q "unix:uid:$uid" <<<"$out" ||
			spire "$zone" entry create -parentID "spiffe://$zone.lab/node/$host" -spiffeID "spiffe://$zone.lab/${id#* }" \
				-selector "unix:uid:$uid" >/dev/null
	done
	env_set ".$host" "$(jq -n --arg uuid "$uuid" --argjson uid "$uid" --arg ip "$(inner_ip "$host")" '{uuid: $uuid, ligo_uid: $uid, address: $ip}')"
}

# spire_check HOST: as the user ligo on HOST, fetches an X.509-SVID and a
# JWT-SVID from each agent (step 2's done criterion).
spire_check() {
	local host="$1" zone uid out="" i
	uid="$(env_get ".$host.ligo_uid")"
	for zone in "${ZONES[@]}"; do
		for i in $(seq 1 60); do
			out="$(lxd exec lxd -- lxc exec "$host" --user "$uid" -- "$SPIRE_PREFIX/bin/spire-agent" api fetch x509 -socketPath "/run/spire/$zone/agent.sock" 2>/dev/null)" && break
			sleep 2
		done
		grep -q "SPIFFE ID:" <<<"$out" || die "$host: no X.509-SVID from the $zone agent (lab.sh logs $host spire-agent-$zone)"
		info "$host, user ligo: X.509-SVID $(awk '/SPIFFE ID:/ {print $3; exit}' <<<"$out")"
		lxd exec lxd -- lxc exec "$host" --user "$uid" -- "$SPIRE_PREFIX/bin/spire-agent" api fetch jwt -audience lab-check \
			-socketPath "/run/spire/$zone/agent.sock" 2>/dev/null | grep -q "token(" || die "$host: no JWT-SVID from the $zone agent"
		info "$host, user ligo: JWT-SVID from the $zone agent"
	done
}

# identity_spire_up: everything of SPIRE, in order.
identity_spire_up() {
	section "SPIRE (prod.lab, test.lab) with lxd-spiffe"
	local zone host
	for host in $(ligo_hosts); do
		ligo_vm_up "$host"
	done
	for zone in "${ZONES[@]}"; do
		spire_identity "$zone"
		spire_server_up "$zone"
	done
	for host in $(ligo_hosts); do
		spire_agents_up "$host"
		spire_entries "$host"
		spire_check "$host"
	done
	env_set .spire "$(jq -n --arg v "$LAB_SPIRE_VERSION" --arg l "$LAB_LXD_SPIFFE_VERSION" '{version: $v, lxd_spiffe: $l}')"
}
