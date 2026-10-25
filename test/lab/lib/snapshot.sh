# shellcheck shell=bash
# The baseline snapshot of the lab VM, and stopping and starting the lab.
# Snapshots are disk only, taken with the inner instances stopped and the VM
# shut down: memory snapshots of VMs that run VMs are not reliable.

SNAPSHOT=baseline

# has_snapshot: true when the lab VM has its baseline snapshot.
has_snapshot() { lxc query "/1.0/instances/lxd/snapshots/$SNAPSHOT?project=$LAB_PROJECT" >/dev/null 2>&1; }

lab_snapshot() {
	section "Snapshot"
	lab_stop
	lxd delete lxd/"$SNAPSHOT" >/dev/null 2>&1 || true
	lxd snapshot lxd "$SNAPSHOT"
	jq --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.snapshot_at = $at' "$LAB_STATE_DIR/env.json" >"$LAB_STATE_DIR/env.json.new" &&
		mv "$LAB_STATE_DIR/env.json.new" "$LAB_STATE_DIR/env.json"
	info "lxd: snapshot $SNAPSHOT taken"
	lab_start
}

lab_reset() {
	section "Reset"
	has_snapshot || die "the lab VM has no snapshot: run lab.sh snapshot"
	if vm_running lxd; then
		lxd stop lxd --force
	fi
	lxd restore lxd "$SNAPSHOT"
	info "lxd: restored to $SNAPSHOT"
	lab_start
}

# lab_stop stops the inner instances, then the lab VM, cleanly.
lab_stop() {
	if vm_running lxd; then
		local name
		for name in $(inner list -c n -f csv 2>/dev/null); do
			inner stop "$name" --timeout 60 >/dev/null 2>&1 || true
		done
		lxd stop lxd --timeout 120
		info "lab stopped"
	fi
}

# lab_start boots the lab VM, starts the inner instances and waits until
# every server answers.
lab_start() {
	vm_running lxd || lxd start lxd
	vm_wait lxd
	local name
	for name in $(inner list -c n -f csv); do
		inner_running "$name" || inner start "$name"
	done
	inner_wait pg
	pg_wait_ready
}
