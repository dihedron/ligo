# shellcheck shell=bash
# The lab's LXD objects: storage pool, network, project and its profile.
# Every object carries user.ligo-lab=yes, so that the lab never takes over or
# removes what it did not create.

lxd_up() {
	section "LXD"
	if ! lxc storage show "$LAB_STORAGE_POOL" >/dev/null 2>&1; then
		local args=("$LAB_STORAGE_POOL" "$LAB_STORAGE_DRIVER")
		[[ "$LAB_STORAGE_DRIVER" == dir ]] || args+=("size=$LAB_STORAGE_SIZE")
		lxc storage create "${args[@]}" user.ligo-lab=yes >/dev/null
		info "storage pool $LAB_STORAGE_POOL created ($LAB_STORAGE_DRIVER)"
	else
		info "storage pool $LAB_STORAGE_POOL exists"
	fi
	if ! lxc network show "$LAB_NETWORK" >/dev/null 2>&1; then
		lxc network create "$LAB_NETWORK" \
			ipv4.address="$(lab_gateway)/24" ipv4.nat=true ipv6.address=none \
			dns.domain=ligo.lab user.ligo-lab=yes >/dev/null
		info "network $LAB_NETWORK created ($LAB_SUBNET)"
	else
		info "network $LAB_NETWORK exists"
	fi
	if ! lxc project show "$LAB_PROJECT" >/dev/null 2>&1; then
		lxc project create "$LAB_PROJECT" -c features.images=false -c features.profiles=true \
			-c user.ligo-lab=yes >/dev/null
		lxd profile device add default root disk path=/ pool="$LAB_STORAGE_POOL" >/dev/null
		lxd profile device add default eth0 nic network="$LAB_NETWORK" name=eth0 >/dev/null
		info "project $LAB_PROJECT created"
	else
		info "project $LAB_PROJECT exists"
	fi
}

# lxd_down removes the lab's objects; the VMs must be gone already.
lxd_down() {
	if lxc project show "$LAB_PROJECT" >/dev/null 2>&1; then
		lxd profile device remove default root >/dev/null 2>&1 || true
		lxd profile device remove default eth0 >/dev/null 2>&1 || true
		lxc project delete "$LAB_PROJECT" && info "project $LAB_PROJECT deleted"
	fi
	if [[ "$(lxc network get "$LAB_NETWORK" user.ligo-lab 2>/dev/null)" == yes ]]; then
		lxc network delete "$LAB_NETWORK" && info "network $LAB_NETWORK deleted"
	fi
	if [[ "$(lxc storage get "$LAB_STORAGE_POOL" user.ligo-lab 2>/dev/null)" == yes ]]; then
		lxc storage delete "$LAB_STORAGE_POOL" && info "storage pool $LAB_STORAGE_POOL deleted"
	fi
}

# vm_exists NAME / vm_running NAME
vm_exists() { lxd info "$1" >/dev/null 2>&1; }
vm_running() { [[ "$(lxd list "$1" -c s -f csv 2>/dev/null)" == RUNNING ]]; }

# vm_wait NAME: waits until the VM's agent answers and cloud-init is done.
vm_wait() {
	local i
	for i in $(seq 1 120); do
		lxd exec "$1" -- true >/dev/null 2>&1 && break
		sleep 2
	done
	lxd exec "$1" -- true >/dev/null 2>&1 || die "$1: the LXD agent does not answer"
	lxd exec "$1" -- cloud-init status --wait >/dev/null || die "$1: cloud-init failed (lab.sh logs $1)"
}
