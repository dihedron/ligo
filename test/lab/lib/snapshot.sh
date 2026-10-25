# shellcheck shell=bash
# Baseline snapshots of the lab's VMs, and stopping and starting them.

SNAPSHOT=baseline

# has_snapshot: true when pg has its baseline snapshot.
has_snapshot() { lxc query "/1.0/instances/pg/snapshots/$SNAPSHOT?project=$LAB_PROJECT" >/dev/null 2>&1; }

lab_snapshot() {
	section "Snapshot"
	lab_stop
	lxd delete pg/"$SNAPSHOT" >/dev/null 2>&1 || true
	lxd snapshot pg "$SNAPSHOT"
	jq --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '.snapshot_at = $at' "$LAB_STATE_DIR/env.json" >"$LAB_STATE_DIR/env.json.new" &&
		mv "$LAB_STATE_DIR/env.json.new" "$LAB_STATE_DIR/env.json"
	info "pg: snapshot $SNAPSHOT taken"
	lab_start
}

lab_reset() {
	section "Reset"
	has_snapshot || die "pg has no snapshot: run lab.sh snapshot"
	lab_stop
	lxd restore pg "$SNAPSHOT"
	info "pg: restored to $SNAPSHOT"
	lab_start
}

lab_stop() {
	if vm_running pg; then
		lxd stop pg --timeout 120
		info "pg stopped"
	fi
}

lab_start() {
	vm_running pg || lxd start pg
	vm_wait pg
	pg_wait_ready
}
