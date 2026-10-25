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

# inner_images: the lab image, container and VM, under local aliases of the
# inner LXD (lab-container, lab-vm), copied once: creating an instance from
# the "ubuntu:" remote makes the lxc client query it first, and that query
# has hung on this lab.
inner_images() {
	local kind alias args fingerprint
	for kind in container vm; do
		alias="lab-$kind"
		inner image info "$alias" >/dev/null 2>&1 && continue
		# an image of that kind already in the cache (from earlier instances)
		# gets the alias without a download
		fingerprint="$(inner image list -f json | jq -r --arg t "$([[ $kind == vm ]] && echo virtual-machine || echo container)" \
			'[.[] | select(.type == $t and ((.properties.os // "") | ascii_downcase) == "ubuntu")] | .[0].fingerprint // empty')"
		if [[ -n "$fingerprint" ]]; then
			inner image alias create "$alias" "$fingerprint" >/dev/null
			info "inner LXD: cached $kind image ${fingerprint:0:12} aliased as $alias"
			continue
		fi
		args=(image copy "$LAB_IMAGE" local: --alias "$alias")
		[[ "$kind" == vm ]] && args+=(--vm)
		lxd exec lxd -- timeout 900 lxc "${args[@]}" </dev/null >/dev/null ||
			lxd exec lxd -- timeout 900 lxc "${args[@]}" </dev/null >/dev/null ||
			die "cannot copy $LAB_IMAGE ($kind) into the inner LXD"
		info "inner LXD: $LAB_IMAGE ($kind) cached as $alias"
	done
}

# inner_init NAME ARGS: creates an inner instance from the local lab image
# (lab-vm with --vm among ARGS, lab-container otherwise), with an empty stdin
# (lxc init reads YAML from a stdin that is not a terminal), a timeout and
# one retry.
inner_init() {
	local name="$1" image=lab-container arg
	shift
	for arg in "$@"; do
		[[ "$arg" == --vm ]] && image=lab-vm
	done
	lxd exec lxd -- timeout 300 lxc init "$image" "$name" "$@" </dev/null >/dev/null && return
	warn "creating $name timed out: retrying once"
	inner delete "$name" --force >/dev/null 2>&1 || true
	lxd exec lxd -- timeout 300 lxc init "$image" "$name" "$@" </dev/null >/dev/null || die "cannot create $name"
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
		lxd init "$LAB_IMAGE" lxd --vm </dev/null \
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
	inner_images
}

# lxd_vm_check_size warns when the lab VM differs from the size settings.
lxd_vm_check_size() {
	local cpus memory
	cpus="$(lxd config get lxd limits.cpu)"
	memory="$(lxd config get lxd limits.memory)"
	[[ "$cpus" == "$LAB_LXD_CPUS" && "$memory" == "$LAB_LXD_MEMORY" ]] ||
		warn "VM lxd has $cpus vCPU(s) and $memory, the settings ask for $LAB_LXD_CPUS and $LAB_LXD_MEMORY: \"down\" then \"up\" to apply them"
}
