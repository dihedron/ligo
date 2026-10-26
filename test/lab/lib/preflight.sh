# shellcheck shell=bash
# The preflight: checks that this machine can run the lab
# (.specs/ligo-test-environment.md, "Preflight").

# size_mib SIZE: a size such as 2GiB or 512MiB, in MiB.
size_mib() {
	case "$1" in
	*GiB) printf '%d' $((${1%GiB} * 1024)) ;;
	*MiB) printf '%d' "${1%MiB}" ;;
	*) die "size \"$1\" must end with GiB or MiB" ;;
	esac
}

preflight() {
	section "Preflight"
	preflight_host
	preflight_lxd
	preflight_resources
	preflight_software
	preflight_network
	if ((CHECK_FAILS > 0)); then
		die "preflight: $CHECK_FAILS check(s) failed"
	fi
	info "preflight passed ($CHECK_WARNS warning(s))"
}

preflight_host() {
	if [[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]]; then
		ok "Linux on x86-64"
	else
		fail "the lab needs Linux on x86-64, not $(uname -s) on $(uname -m)"
	fi
	if [[ -r /dev/kvm && -w /dev/kvm ]]; then
		ok "/dev/kvm usable"
	else
		fail "/dev/kvm missing or not usable: enable virtualization, and join the kvm group"
	fi
	local nested
	nested="$(cat /sys/module/kvm_amd/parameters/nested /sys/module/kvm_intel/parameters/nested 2>/dev/null | head -1 || true)"
	if [[ "$nested" == 1 || "$nested" == Y ]]; then
		ok "KVM nesting enabled (the lab's VMs run inside the lab VM)"
	else
		fail "KVM nesting is off: enable it (options kvm_amd nested=1, or kvm_intel nested=1) and reload the module"
	fi
}

preflight_lxd() {
	if ! command -v lxc >/dev/null; then
		fail "lxc not found: install LXD (sudo snap install lxd --channel=5.21/stable)"
		return
	fi
	if ! lxd_reachable; then
		fail "cannot reach the LXD daemon: sudo usermod -aG lxd $(id -un), then log in again"
		return
	fi
	local version
	version="$(lxc query /1.0 | jq -r .environment.server_version)"
	if [[ "$(printf '%s\n5.21\n' "$version" | sort -V | head -1)" == 5.21 ]]; then
		ok "LXD $version"
	else
		fail "LXD $version: the lab needs 5.21 or later"
	fi
	case "$LAB_STORAGE_DRIVER" in
	dir | btrfs) ok "storage driver $LAB_STORAGE_DRIVER" ;;
	zfs)
		if [[ -e /sys/module/zfs ]] || modinfo zfs >/dev/null 2>&1; then
			ok "storage driver zfs (kernel module available)"
		else
			fail "storage driver zfs: the host kernel has no zfs module (install zfsutils-linux, or use dir or btrfs)"
		fi
		;;
	*) fail "LAB_STORAGE_DRIVER must be dir, zfs or btrfs, not \"$LAB_STORAGE_DRIVER\"" ;;
	esac
	local pool
	if pool="$(lxc query "/1.0/storage-pools/$LAB_STORAGE_POOL" 2>/dev/null)"; then
		if [[ "$(jq -r '.config["user.ligo-lab"] // ""' <<<"$pool")" == yes ]]; then
			ok "storage pool $LAB_STORAGE_POOL is the lab's"
			[[ "$(jq -r .driver <<<"$pool")" == "$LAB_STORAGE_DRIVER" ]] ||
				warn "storage pool $LAB_STORAGE_POOL uses $(jq -r .driver <<<"$pool"), not $LAB_STORAGE_DRIVER: \"down\" then \"up\" to change it"
		else
			fail "storage pool $LAB_STORAGE_POOL exists and is not the lab's: set LAB_STORAGE_POOL"
		fi
	else
		ok "storage pool $LAB_STORAGE_POOL will be created"
	fi
}

preflight_resources() {
	local cpus mem_avail_mib need_mib disk_mib need_disk_mib
	cpus="$(nproc)"
	if ((LAB_LXD_CPUS <= cpus)); then
		ok "$LAB_LXD_CPUS vCPU(s) of $cpus"
	else
		warn "$LAB_LXD_CPUS vCPUs on a host with $cpus"
	fi
	mem_avail_mib=$(($(awk '/MemAvailable/ {print $2}' /proc/meminfo) / 1024))
	need_mib=$(($(size_mib "$LAB_LXD_MEMORY") + 2048))
	if lxd_reachable && vm_running lxd; then
		need_mib=2048
	fi
	if ((need_mib <= mem_avail_mib)); then
		ok "memory: ${need_mib} MiB needed, ${mem_avail_mib} MiB available"
	else
		fail "memory: ${need_mib} MiB needed, ${mem_avail_mib} MiB available"
	fi
	disk_mib=$(($(df -Pk /var/snap/lxd/common/lxd 2>/dev/null | awk 'NR==2 {print $4}') / 1024))
	if [[ "$LAB_STORAGE_DRIVER" == dir ]]; then
		need_disk_mib=$(($(size_mib "$LAB_LXD_DISK") * 2))
	else
		need_disk_mib=$(size_mib "$LAB_STORAGE_SIZE")
		((need_disk_mib > $(size_mib "$LAB_LXD_DISK"))) ||
			fail "LAB_STORAGE_SIZE ($LAB_STORAGE_SIZE) must exceed the lab VM's disk (LAB_LXD_DISK, $LAB_LXD_DISK), with room for its snapshot"
	fi
	if ((need_disk_mib <= disk_mib)); then
		ok "disk: ${need_disk_mib} MiB needed, ${disk_mib} MiB free under /var/snap/lxd/common/lxd"
	else
		fail "disk: ${need_disk_mib} MiB needed, ${disk_mib} MiB free under /var/snap/lxd/common/lxd"
	fi
}

preflight_software() {
	local tool
	for tool in openssl jq go; do
		if command -v "$tool" >/dev/null; then
			ok "$tool"
		else
			fail "$tool not found: install it"
		fi
	done
	command -v go >/dev/null || return
	local want have
	want="$(awk '/^go / {print $2}' "$REPO_DIR/go.mod")"
	have="$(go env GOVERSION)"
	have="${have#go}"
	if [[ "$(printf '%s\n%s\n' "$want" "$have" | sort -V | head -1)" == "$want" ]]; then
		ok "Go $have (go.mod: $want)"
	else
		fail "Go $have is older than go.mod's $want"
	fi
}

preflight_network() {
	[[ "$LAB_SUBNET" =~ ^([0-9]+\.){3}0/24$ ]] || fail "LAB_SUBNET must be a /24 such as 10.252.0.0/24, not $LAB_SUBNET"
	[[ "$LAB_INNER_SUBNET" =~ ^([0-9]+\.){3}0/24$ && "$LAB_INNER_SUBNET" != "$LAB_SUBNET" ]] ||
		fail "LAB_INNER_SUBNET must be a /24 other than LAB_SUBNET, not $LAB_INNER_SUBNET"
	local net
	if net="$(lxc query "/1.0/networks/$LAB_NETWORK" 2>/dev/null)" && [[ "$(jq -r .managed <<<"$net")" == true ]]; then
		if [[ "$(jq -r '.config["user.ligo-lab"] // ""' <<<"$net")" == yes ]]; then
			ok "network $LAB_NETWORK is the lab's"
		else
			fail "network $LAB_NETWORK exists and is not the lab's: set LAB_NETWORK"
		fi
		return
	elif [[ -n "$net" ]]; then
		fail "network $LAB_NETWORK exists on the host: set LAB_NETWORK"
		return
	fi
	if ip -4 route | awk '{print $1}' | grep -qx "$LAB_SUBNET"; then
		fail "$LAB_SUBNET is already routed on this host: set LAB_SUBNET"
	else
		ok "subnet $LAB_SUBNET is free"
	fi
}
