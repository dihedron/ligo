#!/usr/bin/env bash
# The pre-release campaign's gaps in the lab (terraform-provider-ligo
# .specs/ligo-prerelease-campaign.md, phase 1): the releases of a binding and
# a target, the containment of a source's bindings, binding expiry, the limits
# and the revert of break-glass, rate limiting, and the CLI's hold lift.

# serve_test_campaign: the Go e2e, then the CLI's half.
serve_test_campaign() {
	deploy_tests
	section "e2e of the campaign's gaps"
	local other x out json id rev pw source target binding
	other="$(ligo_hosts | tail -1)"
	E2E_SUFFIX="$(openssl rand -hex 4)"
	serve_admins
	# CAMPAIGN_ONLY=cli skips the Go half (the break-glass TTL alone takes five minutes)
	if [[ "${CAMPAIGN_ONLY:-}" != cli ]]; then
		serve_e2e '^TestServeCampaignLifecycle$' ligo1 "$other" || die "TestServeCampaignLifecycle failed"
		info "releases of a binding and a target, revoke-bindings passed"
		serve_e2e '^TestServeCampaignExpiryCreate$' ligo1 "$other" || die "TestServeCampaignExpiryCreate failed"
		serve_sql "update bindings set expires_at = now() - interval '1 minute' where name = 'cmp-exp-$E2E_SUFFIX'" >/dev/null
		serve_e2e '^TestServeCampaignExpiryCheck$' ligo1 "$other" || die "the binding that expired was not revoked"
		info "a binding whose expiry came was revoked on a live server"
		serve_e2e '^TestServeCampaignBreakGlassLimits$' ligo1 "$other" || die "TestServeCampaignBreakGlassLimits failed"
		info "break-glass: max_ttl, max_open and the revert at the TTL passed"
		serve_e2e '^TestServeCampaignRateLimit$' ligo1 "$other" || die "TestServeCampaignRateLimit failed"
		info "rate limiting passed"
	fi

	# the CLI: a hold, listed, lifted by a person, and the pipeline applies again
	x="$(openssl rand -hex 3)" source="cli-hl-src-$x" target="cli-hl-tgt-$x" binding="cli-hl-$x"
	manifest() {
		cat <<YAML
kind: Target
metadata: {name: $target, platform: pg-ledger, jurisdiction: dc/corp-prod/ledger}
definition: {database: ledger, schema: ledger}
accessLevels: [{name: read, grants: {roles: [LEDGER_RO_ROLE]}}]
networkFlows: [{name: ledger, purpose: DATA, protocol: TCP, destination: pg.ligo.lab, ports: [5432], tls: true, serverName: pg.ligo.lab}]
visibility: {mode: PRIVATE}
---
kind: Source
metadata: {name: $source}
identity:
  trustDomain: prod.lab
  svidRegex: '^spiffe://prod\.lab/ns/clihl/sa/w$x\$'
  sampleSpiffeIds: ['spiffe://prod.lab/ns/clihl/sa/w$x']
visibility: {mode: PRIVATE}
---
{kind: Binding, name: $binding, source: $source, target: $target, accessLevel: read}
YAML
	}
	bmanifest() { echo "{kind: Binding, name: $binding, source: $source, target: $target, accessLevel: read}"; }
	out="$(manifest | cli ligo-ci apply --managed --approval-ref CHG-HL -f - 2>&1)" || die "the pipeline's apply: $out"
	cli_phase "$binding" ACTIVE
	rev="$(cli ligo-ops -o json binding show "$binding" | jq -r '.metadata.revision')"
	cli ligo-ops binding delete "$binding" -r "$rev" >/dev/null || die "containment of $binding"
	cli_approve binding "$binding"
	cli_phase "$binding" ""
	json="$(cli ligo-ops -o json hold list --binding "$binding")" || die "hold list"
	[[ "$(jq '.items | length' <<<"$json")" == 1 ]] || die "holds of $binding: $json"
	id="$(jq -r '.items[0].id' <<<"$json")"
	if out="$(bmanifest | cli ligo-ci apply --managed --approval-ref CHG-HL -f - 2>&1)"; then die "the pipeline re-created the held $binding"; fi
	grep -q "resource-held\|held" <<<"$out" || die "re-creating a held binding: $out"
	pw="$LIGO1_E2E/dave.pw"
	ldap_password dave | inner_exec ligo1 sh -c "umask 077 && cat >$pw && chown ligo:ligo $pw"
	if out="$(cli ligo-ops hold lift "$id" -m "an operator lifts" 2>&1)"; then die "an operator lifted the hold"; fi
	cli ligo hold lift "$id" -m "contained and reviewed, campaign" --username dave --password-file "$pw" >/dev/null || die "ligo hold lift $id"
	[[ "$(cli ligo-ops -o json hold list --binding "$binding" | jq '.items | length')" == 0 ]] || die "the hold is still open after the lift"
	bmanifest | cli ligo-ci apply --managed --approval-ref CHG-HL -f - >/dev/null || die "the pipeline applies after the lift"
	cli_phase "$binding" ACTIVE
	info "CLI: the pipeline was refused by the hold, an operator could not lift it, a person did, and the binding came back"
	[[ "$(cli ligo-approver -o json audit verify | jq -r .valid)" == true ]] || die "audit verify"
	info "e2e of the campaign's gaps passed"
}
