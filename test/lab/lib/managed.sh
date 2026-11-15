#!/usr/bin/env bash
# The lock's scenario (.specs/ligo-managed-resources.md, AC-M11): resources
# that an automation owns, on the real service and both replicas.

# serve_test_managed: the Go e2e (TestServeManaged: the owner, the refusals,
# containment, the hold, the emergency path, the release by an administrator,
# a race), then the CLI's half, then what the database and the metrics say.
serve_test_managed() {
	deploy_tests
	section "e2e of the lock (managed resources)"
	local other x out rev metrics pw
	other="$(ligo_hosts | tail -1)"
	E2E_SUFFIX="$(openssl rand -hex 4)"
	serve_admins
	serve_e2e '^TestServeManaged$' ligo1 "$other" || die "TestServeManaged failed"
	info "the lock: owner, refusals, containment, hold, emergency path, release by an administrator, race passed"

	# the CLI: the pipeline's apply, the refusal, the release, the holds
	x="$(openssl rand -hex 3)"
	local source="cli-mg-$x"
	out="$(cli ligo-ci apply --managed --approval-ref CHG-1 -f - <<YAML
kind: Source
metadata: {name: $source}
identity:
  trustDomain: prod.lab
  svidRegex: '^spiffe://prod\.lab/ns/climg/sa/w$x\$'
visibility: {mode: PRIVATE}
YAML
)" || die "ligo apply --managed: $out"
	[[ "$(cli ligo-ops -o json source show "$source" | jq -r '.metadata.managedBy')" == "spiffe://prod.lab/ci/terraform" ]] || die "$source is not owned by the pipeline"
	rev="$(cli ligo-ops -o json source show "$source" | jq -r '.metadata.revision')"
	if out="$(cli ligo-ops source delete "$source" -r "$rev" 2>&1)"; then die "an operator retired the managed $source"; fi
	grep -q "resource-managed\|managed" <<<"$out" || die "retiring a managed source: $out"
	info "CLI: the pipeline owns $source; an operator's retirement is refused"
	if out="$(cli ligo-ops source release "$source" -r "$rev" --justification "the pipeline was retired in March" 2>&1)"; then die "an operator released $source"; fi
	if out="$(cli ligo-platform source release "$source" -r "$rev" --justification "the pipeline was retired in March" 2>&1)"; then die "an SVID released $source: a person releases"; fi
	pw="$LIGO1_E2E/bob.pw"
	ldap_password bob | inner_exec ligo1 sh -c "umask 077 && cat >$pw && chown ligo:ligo $pw"
	cli ligo source release "$source" -r "$rev" --justification "the pipeline was retired in March" --username bob --password-file "$pw" >/dev/null || die "ligo source release"
	approve_all ligo-approver source
	[[ "$(cli ligo-ops -o json source show "$source" | jq -r '.metadata.managedBy')" == null ]] || die "$source is still managed after the release"
	info "CLI: the administrator's release (a person with full access) was approved by a second person"
	cli ligo-ops hold list >/dev/null || die "ligo hold list"
	pw="$LIGO1_E2E/dave.pw"
	ldap_password dave | inner_exec ligo1 sh -c "umask 077 && cat >$pw && chown ligo:ligo $pw"
	if out="$(cli ligo hold lift 00000000-0000-7000-8000-000000000000 -m "no such hold" --username dave --password-file "$pw" 2>&1)"; then die "lifted a hold that does not exist"; fi
	grep -qi "not-found\|not found\|404" <<<"$out" || die "ligo hold lift of a missing hold: $out"
	info "CLI: hold list, and a missing hold is not found"

	# chaos: an adoption waits for people while ligo2 is down, and is decided through ligo1
	local adopt="cli-adopt-$x" doc
	doc="$(jq -nc --arg n "$adopt" --arg re "^spiffe://prod\\.lab/ns/adopt/sa/w$x\$" '{kind: "Source", metadata: {name: $n}, identity: {trustDomain: "prod.lab", svidRegex: $re}, visibility: {mode: "PRIVATE"}}')"
	cli ligo-ops apply -f - <<<"$doc" >/dev/null || die "apply $adopt"
	cli_approve source "$adopt"
	rev="$(cli ligo-ops -o json source show "$adopt" | jq -r '.metadata.revision')"
	cli ligo-ci apply --managed --approval-ref CHG-2 -f - <<<"$(jq -c --argjson r "$rev" '. + {expectedRevision: $r}' <<<"$doc")" >/dev/null || die "the adoption of $adopt"
	[[ "$(cli ligo-ops -o json source show "$adopt" | jq -r '.metadata.managedBy')" == null ]] || die "$adopt was adopted without its owner's consent"
	inner_exec ligo2 systemctl stop ligo
	cli_approve source "$adopt"
	inner_exec ligo2 systemctl start ligo
	serve_wait ligo2
	for out in ligo1 ligo2; do
		[[ "$(CLI_SERVER="$out.ligo.lab" cli ligo-ops -o json source show "$adopt" | jq -r '.metadata.managedBy')" == "spiffe://prod.lab/ci/terraform" ]] || die "$adopt is not owned by the pipeline on $out"
	done
	info "chaos: the adoption waited for people, was decided with ligo2 down, and both replicas agree on its owner"

	# the audit log and the metrics
	for out in RESOURCE_MANAGED RESOURCE_RELEASED_BY_ADMIN LOCK_VIOLATION_REFUSED HOLD_CREATED HOLD_LIFTED; do
		[[ "$(serve_sql "select count(*) from audit_log where action = '$out'")" -ge 1 ]] || die "no $out in the audit log"
	done
	info "the audit log holds RESOURCE_MANAGED, RESOURCE_RELEASED_BY_ADMIN, LOCK_VIOLATION_REFUSED, HOLD_CREATED and HOLD_LIFTED"
	metrics="$(inner_exec ligo1 curl -s http://127.0.0.1:9090/metrics)" || die "the metrics of ligo1"
	grep -q '^ligo_lock_violations_total{type="source"} [1-9]' <<<"$metrics" || die "ligo_lock_violations_total{type=source} is not above 0"
	grep -q '^ligo_managed_resources{type="source"} ' <<<"$metrics" || die "no ligo_managed_resources{type=source}"
	grep -q '^ligo_holds_open ' <<<"$metrics" || die "no ligo_holds_open"
	info "ligo_lock_violations_total, ligo_managed_resources and ligo_holds_open are exposed"
	[[ "$(cli ligo-approver -o json audit verify | jq -r .valid)" == true ]] || die "audit verify"
	info "e2e of the lock passed"
}
