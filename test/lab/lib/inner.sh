# shellcheck shell=bash
# The lab VM, "lxd", and the LXD that runs inside it: every server of the lab
# is an instance of that inner LXD (.specs/ligo-test-environment.md,
# "Architecture").

# lxd_vm_cloud_init: the lab VM's cloud-init user data: the inner LXD, with
# refreshes held so that its version cannot change during a session.
lxd_vm_cloud_init() {
	cat <<YAML
#cloud-config
package_update: true
snap:
  commands:
    - snap install lxd --channel=$LAB_INNER_LXD_CHANNEL
    - snap refresh --hold lxd
    - snap refresh --hold
YAML
}

# inner_preseed: the inner LXD's configuration: a pool on the VM's disk and
# the "inner" bridge (the API listener is set afterwards, on that bridge: the
# address must exist first).
inner_preseed() {
	cat <<YAML
storage_pools:
  - name: default
    driver: dir
networks:
  - name: inner
    type: bridge
    config:
      ipv4.address: $(inner_gateway)/24
      ipv4.nat: "true"
      ipv6.address: none
      dns.domain: ligo.lab
profiles:
  - name: default
    devices:
      root: {type: disk, path: /, pool: default}
      eth0: {type: nic, network: inner, name: eth0}
YAML
}

# inner ARGS: lxc on the inner LXD.
inner() { lxd exec lxd -- lxc "$@"; }

# inner_exec NAME ARGS: runs ARGS in an inner instance, as root.
inner_exec() {
	local name="$1"
	shift
	lxd exec lxd -- lxc exec "$name" -- "$@"
}

# inner_push FILE NAME PATH MODE: copies a file of the lab host into an inner
# instance, owned by root.
inner_push() {
	local tmp="/root/push.$$"
	lxd file push "$1" "lxd$tmp" --mode 0600 >/dev/null
	inner file push "$tmp" "$2$3" --uid 0 --gid 0 --mode "$4" >/dev/null
	lxd exec lxd -- rm -f "$tmp"
}

# inner_exists NAME / inner_running NAME
inner_exists() { inner info "$1" >/dev/null 2>&1; }
inner_running() { [[ "$(inner list "$1" -c s -f csv 2>/dev/null)" == RUNNING ]]; }

# inner_wait NAME: waits until an inner instance answers and cloud-init is
# done.
inner_wait() {
	local i
	for i in $(seq 1 120); do
		inner_exec "$1" true >/dev/null 2>&1 && break
		sleep 2
	done
	inner_exec "$1" cloud-init status --wait >/dev/null || die "$1: cloud-init failed (lab.sh logs $1)"
}

# lxd_vm_up creates the lab VM and initializes its inner LXD.
lxd_vm_up() {
	section "Lab VM (lxd) and its inner LXD"
	if ! vm_exists lxd; then
		lxd init "$LAB_IMAGE" lxd --vm \
			-c limits.cpu="$LAB_LXD_CPUS" -c limits.memory="$LAB_LXD_MEMORY" \
			-c cloud-init.user-data="$(lxd_vm_cloud_init)" \
			-d root,size="$LAB_LXD_DISK" \
			-d eth0,ipv4.address="$(lxd_ip)" >/dev/null
		info "VM lxd created from $LAB_IMAGE"
	else
		lxd_vm_check_size
	fi
	vm_running lxd || lxd start lxd
	info "waiting for cloud-init (inner LXD)..."
	vm_wait lxd
	if [[ "$(lxd exec lxd -- lxc network list -f csv 2>/dev/null | grep -c '^inner,')" == 0 ]]; then
		inner_preseed | lxd exec lxd -- lxd init --preseed
		info "inner LXD initialized: bridge inner ($LAB_INNER_SUBNET)"
	else
		info "inner LXD initialized"
	fi
	if [[ "$(inner config get core.https_address)" != "$(inner_gateway):8443" ]]; then
		inner config set core.https_address "$(inner_gateway):8443"
		info "inner LXD API on $(inner_gateway):8443 (the inner bridge only)"
	fi
}

# lxd_vm_check_size warns when the lab VM differs from the size settings.
lxd_vm_check_size() {
	local cpus memory
	cpus="$(lxd config get lxd limits.cpu)"
	memory="$(lxd config get lxd limits.memory)"
	[[ "$cpus" == "$LAB_LXD_CPUS" && "$memory" == "$LAB_LXD_MEMORY" ]] ||
		warn "VM lxd has $cpus vCPU(s) and $memory, the settings ask for $LAB_LXD_CPUS and $LAB_LXD_MEMORY: \"down\" then \"up\" to apply them"
}
