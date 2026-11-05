# shellcheck shell=bash
# The release run: the full lab suite for one commit, from a new lab, on each
# secrets backend, with its evidence (spec §11.1 rules 4, 5, 6 and 8).

# release_step DIR NAME ARGS: lab.sh ARGS, its output kept in DIR/NAME.log.
release_step() {
	local dir="$1" name="$2"
	shift 2
	section "release-run: $name"
	"$LAB_DIR/lab.sh" "$@" 2>&1 | tee "$dir/$name.log" || die "release-run: $name failed; see $dir/$name.log"
}

# release_suite DIR BACKEND: every suite, on the selected backend.
release_suite() {
	local dir="$1" b="$2"
	release_step "$dir" "$b-deploy" deploy
	release_step "$dir" "$b-test" test
	release_step "$dir" "$b-test-ligo1" test --on ligo1 # replaces the plugins and leaves the service stopped
	release_step "$dir" "$b-serve-install" serve install
	release_step "$dir" "$b-serve-test" serve test
	release_step "$dir" "$b-serve-test-ha" serve test-ha
	release_step "$dir" "$b-serve-test-otel" serve test-otel
	release_step "$dir" "$b-serve-test-webhook" serve test-webhook
	release_step "$dir" "$b-serve-test-faults" serve test-faults
}

# release_versions: what env.json does not record of the lab's components.
release_versions() {
	printf 'commit %s\n' "$(git -C "$REPO_DIR" rev-parse HEAD)"
	printf 'recorded_at %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	go version
	printf 'slapd %s\n' "$(inner_exec ldap dpkg-query -W -f='${Version}' slapd)"
	printf 'haproxy %s\n' "$(inner_exec lb dpkg-query -W -f='${Version}' haproxy)"
}

# cmd_release_run destroys the lab, builds a new one and runs every suite on
# OpenBao and on Vault, for a clean tree only. The first failure stops it. The
# evidence is outside the state directory, which lab.sh down removes.
cmd_release_run() {
	[[ -z "$(git -C "$REPO_DIR" status --porcelain)" ]] || die "release-run: the tree is dirty: commit first, so that the evidence names what ran"
	confirm "Destroy the ligo lab and build a new one for the release run?" || die "cancelled"
	local commit dir
	commit="$(git -C "$REPO_DIR" rev-parse HEAD)"
	dir="$REPO_DIR/test/lab/.evidence/$commit"
	rm -rf "$dir"
	mkdir -p "$dir"
	export LAB_ASSUME_YES=yes
	release_step "$dir" down down
	release_step "$dir" up up --scenario "storage identity ha lb otel vault webhook"
	release_suite "$dir" openbao
	release_step "$dir" vault-select secrets vault
	release_step "$dir" vault-reset reset
	release_suite "$dir" vault
	section "release-run: htmx-check"
	make -C "$REPO_DIR" htmx-check 2>&1 | tee "$dir/htmx-check.log" || die "release-run: htmx-check failed"
	cp "$LAB_STATE_DIR/env.json" "$dir/env.json"
	release_versions >"$dir/versions.txt"
	tar -C "$dir/.." -czf "$dir/../evidence-$commit.tar.gz" "$commit"
	info "release run passed: test/lab/.evidence/evidence-$commit.tar.gz"
}
