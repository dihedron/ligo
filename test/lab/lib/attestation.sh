#!/usr/bin/env bash
# The node attestation of the lab (lxd-spiffe's lxd_iid plugins; the pre-release
# campaign, terraform-provider-ligo .specs/ligo-prerelease-campaign.md, phase 3):
# the lab only used it, and never asserted on it. A failure here is a finding
# of lxd-spiffe, as .specs/ligo-test-environment.md says.

# serve_test_attestation: what the SPIRE servers say about the agents of ligo1
# and ligo2, and what happens to the callers when an agent restarts or is gone.
serve_test_attestation() {
	section "e2e of the node attestation (lxd_iid)"
	local realm out ids uuids host want got
	# 1. the agents' IDs have the shape lxd-spiffe documents, and name the instances' own UUIDs
	for realm in prod test; do
		out="$(spire "$realm" agent list)" || die "spire-server agent list ($realm)"
		ids="$(grep -o "spiffe://$realm\\.lab/spire/agent/lxd_iid/[^ ]*" <<<"$out" | sort)"
		[[ -n "$ids" ]] || die "$realm: no attested agent: $out"
		while IFS= read -r id; do
			[[ "$id" =~ ^spiffe://$realm\.lab/spire/agent/lxd_iid/inner/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || die "$realm: the agent ID $id is not spiffe://$realm.lab/spire/agent/lxd_iid/<server_id>/<volatile.uuid>"
		done <<<"$ids"
		[[ "$(grep -c "Attestation type  : lxd_iid" <<<"$out")" == "$(wc -l <<<"$ids")" ]] || die "$realm: an agent that is not attested by lxd_iid: $out"
		info "$realm: $(wc -l <<<"$ids") agent(s), IDs of the form spiffe://$realm.lab/spire/agent/lxd_iid/inner/<uuid>"
	done
	uuids="$(spire prod agent list | grep -o 'lxd_iid/inner/[0-9a-f-]*' | sed 's#.*/##' | sort)"
	for host in $(ligo_hosts); do
		want="$(lxd exec lxd -- lxc config get "$host" volatile.uuid)"
		grep -qx "$want" <<<"$uuids" || die "$host: its volatile.uuid $want is not among the attested agents of prod:\n$uuids"
	done
	info "the attested agents are the instances, by their volatile.uuid"

	# 2. an agent restarts: it attests again as the same node, and the callers recover
	got="$(spire prod agent list | grep -c 'SPIFFE ID')"
	inner_exec ligo1 systemctl restart spire-agent-prod || die "cannot restart the prod agent on ligo1"
	for _ in $(seq 1 60); do
		cli ligo-ops -o json source list >/dev/null 2>&1 && break
		sleep 2
	done
	cli ligo-ops -o json source list >/dev/null 2>&1 || die "ligo-ops cannot call ligo after the agent of ligo1 restarted"
	[[ "$(spire prod agent list | grep -c 'SPIFFE ID')" -ge "$got" ]] || die "the agent count fell after a restart"
	diff <(spire prod agent list | grep -o 'lxd_iid/inner/[0-9a-f-]*' | sed 's#.*/##' | sort -u) <(echo "$uuids") >/dev/null || die "the set of attested agents changed after a restart"
	info "the agent of ligo1 restarted: same node ID, the callers recover"

	# 3. an agent is down: the caller's error is clean, and it recovers
	inner_exec ligo1 systemctl stop spire-agent-prod
	if out="$(cli ligo-ops -o json source list 2>&1)"; then die "ligo-ops called ligo with no agent: $out"; fi
	grep -qi "workload\|socket\|spiffe\|agent" <<<"$out" || die "the error with no agent says nothing useful: $out"
	inner_exec ligo1 systemctl start spire-agent-prod
	for _ in $(seq 1 60); do
		cli ligo-ops -o json source list >/dev/null 2>&1 && break
		sleep 2
	done
	cli ligo-ops -o json source list >/dev/null 2>&1 || die "ligo-ops cannot call ligo after the agent came back"
	info "with the agent down the CLI fails with a clear error; it recovers when the agent returns"
	# the server's own agents keep serving: ligo2 was untouched
	CLI_SERVER=ligo2.ligo.lab cli ligo-ops -o json source list >/dev/null || die "ligo2 does not answer"
	info "e2e of the node attestation passed"
}
