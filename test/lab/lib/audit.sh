#!/usr/bin/env bash
# Audit export and pruning on the lab (.specs/ligo-pruning.md, AC-88, AC-89).
#
# A lab is hours old, and audit_prune refuses a checkpoint signed in the
# last 24 hours. audit_anchor therefore signs, with the real Transit key and
# the lab's root token, a checkpoint of a current entry dated 25 hours ago:
# what only someone holding the signing key could do. Everything after it
# is the product's own path: ligo audit export and verify, audit_prune, and
# entries chained onto the anchor.

# audit_anchor: inserts a checkpoint of the newest entry without one, signed
# with transit/sign/ligo-audit and dated 25 hours ago; prints the entry.
audit_anchor() {
	local head hash at msg sig inserted _
	for _ in 1 2 3; do
		head="$(serve_sql "select max(id) from audit_log a where not exists (select 1 from audit_checkpoints c where c.audit_id = a.id)")"
		[[ -n "$head" ]] || die "audit: no entry to anchor"
		hash="$(serve_sql "select entry_hash from audit_log where id = $head")"
		at="$(date -u -d '25 hours ago' +%Y-%m-%dT%H:%M:%S.000000Z)"
		# the JCS of what a checkpoint signs: keys sorted, no spaces (§4.3)
		msg="$(printf '{"auditId":%s,"createdAt":"%s","entryHash":"%s"}' "$head" "$at" "$hash")"
		sig="$(server_cli "$(secrets_host)" write -field=signature transit/sign/ligo-audit input="$(printf %s "$msg" | base64 -w0)")"
		[[ "$sig" == vault:v* ]] || die "audit: transit/sign/ligo-audit gave no signature"
		# ligo's own checkpoint may take the entry first: then another one
		inserted="$(serve_sql "insert into audit_checkpoints (audit_id, entry_hash, created_at, key_id, signature)
			values ($head, '$hash', '$at', 'vault-transit:ligo-audit', '$sig') on conflict (audit_id) do nothing returning audit_id")"
		if grep -qx "$head" <<<"$inserted"; then # psql -tA prints the command tag too
			echo "$head"
			return
		fi
	done
	die "audit: could not anchor a checkpoint"
}

# audit_public_keys: --public-key arguments for every version of the
# signing key, read from the store, not from a file under test.
audit_public_keys() {
	server_cli "$(secrets_host)" read -format=json transit/keys/ligo-audit |
		jq -r '.data.keys | to_entries[] | "--public-key=vault-transit:ligo-audit/\(.key)=\(.value.public_key)"'
}

# serve_test_audit: export through an anchor with ligo audit export, verify
# the file offline with the store's keys, catch a changed copy, prune
# through the anchor, chain new entries onto it, and verify in full.
serve_test_audit() {
	inner_exec ligo1 systemctl is-active --quiet ligo || die "serve test-audit needs ligo serve: lab.sh serve install"
	section "Audit export and pruning (AC-88, AC-89)"
	local head out file keys deleted oldest want carried
	ligo1_user audit-admin spiffe://prod.lab/ops/ada # full access: an export spans every jurisdiction
	head="$(audit_anchor)"
	info "a checkpoint of entry $head, signed with the store's key, dated 25 hours ago"
	# the requests the export must carry: those its entries name, still stored
	want="$(serve_sql "select count(distinct a.change_request_id) from audit_log a join change_requests c on c.id = a.change_request_id where a.id <= $head")"
	file="/tmp/audit-$(openssl rand -hex 4).jsonl"
	out="$(cli audit-admin -o json audit export --through "$head" --out "$file")" || die "ligo audit export failed"
	[[ "$(jq -r .through <<<"$out")" == "$head" ]] || die "the export ends at $(jq -r .through <<<"$out"), not $head"
	info "exported $(jq -r .entries <<<"$out") entries through $head, recorded with sha256 $(jq -r .sha256 <<<"$out" | cut -c1-12)…"
	mapfile -t keys < <(audit_public_keys)
	out="$(cli audit-admin -o json audit verify --file "$file" "${keys[@]}")" || die "the export does not verify with the store's keys: $out"
	jq -e --argjson want "$want" '.valid and (.keysFromFile | not) and .changeRequests == $want' <<<"$out" >/dev/null ||
		die "verify --file, $want change requests expected: $out"
	carried="$(jq -r .changeRequests <<<"$out")"
	inner_exec ligo1 sh -c "sed '0,/\"actor\":\"/s//\"actor\":\"x/' '$file' >'$file.changed' && chmod 0644 '$file.changed'"
	if out="$(cli audit-admin -o json audit verify --file "$file.changed" "${keys[@]}" 2>&1)"; then
		die "a changed export verified: $out"
	fi
	info "the export, with $carried change requests, verifies offline with the store's public keys; a changed copy does not"

	out="$(serve_sql "select audit_prune(0)" 2>&1)" && die "audit_prune of a non-checkpoint passed: $out"
	grep -q "is not a checkpoint" <<<"$out" || die "audit_prune of a non-checkpoint: $out"
	deleted="$(serve_sql "select audit_prune($head)")"
	oldest="$(serve_sql "select coalesce(min(id), 0) from audit_log")"
	((oldest == 0 || oldest > head)) || die "entry $oldest left after pruning through $head"
	cli audit-admin maintenance on -m "serve test-audit: an entry after the prune" >/dev/null
	cli audit-admin maintenance off >/dev/null
	out="$(cli audit-admin -o json audit verify --full)" || die "ligo audit verify --full failed"
	jq -e '.valid' <<<"$out" >/dev/null || die "the chain does not verify after the prune: $out"
	# captured first: grep -q would cut the pipe, which pipefail reports as a failure
	out="$(inner_exec ligo1 curl -fsS http://127.0.0.1:9090/metrics)"
	grep -q '^ligo_audit_oldest_entry_timestamp_seconds ' <<<"$out" || die "ligo_audit_oldest_entry_timestamp_seconds is not served"
	info "pruned $deleted entries through $head; new entries chain onto the anchor; the full verification passes"
	audit_test_requests
}

# audit_test_requests: after the audit prune, change_requests_prune deletes
# a request withdrawn 40 days ago that no entry names (written as the
# superuser: a lab is hours old), and keeps every request of the lab's own
# runs, decided within the last day (.specs/ligo-cr-pruning.md, AC-91). The
# rule that a request an entry names stays is the integration tests': the
# audit prune just before leaves no old entry to show it with.
audit_test_requests() {
	section "Change request pruning (AC-91)"
	local old recent n out
	old="$(serve_sql "select gen_random_uuid()")"
	serve_sql "begin;
		insert into change_requests (id, resource_type, resource_name, operation, kind, consent, owner_jurisdiction,
			policy_sha256, distinct_approvers_required, payload, payload_sha256, requested_by, requested_at, expires_at, status, decided_by, decided_at)
			values ('$old', 'SOURCE', 'audit-test-old', 'CREATE', 'STANDARD', 'ALL', 'dc/corp-prod/ledger', repeat('a', 64), true, '{}', repeat('b', 64),
			'lab', now() - interval '41 days', now() - interval '40 days', 'WITHDRAWN', 'lab', now() - interval '40 days');
		insert into change_request_sides (change_request_id, side, jurisdiction, approval_required, basis, requested_by, cr_kind)
			values ('$old', 'OWNER', 'dc/corp-prod/ledger', true, 'HUMAN', 'lab', 'STANDARD');
		commit;" >/dev/null
	recent="$(serve_sql "select count(*) from change_requests where status = 'PENDING' or decided_at > now() - interval '1 day'")"
	((recent > 0)) || die "the lab's runs left no change request"
	n="$(serve_sql "select change_requests_prune(now() - interval '30 days')")"
	[[ "$(serve_sql "select count(*) from change_requests where id = '$old'")" == 0 ]] || die "the old request was not pruned"
	[[ "$(serve_sql "select count(*) from change_requests where status = 'PENDING' or decided_at > now() - interval '1 day'")" == "$recent" ]] ||
		die "a request decided within the last day was pruned"
	out="$(cli audit-admin -o json audit verify --full)" || die "ligo audit verify --full failed"
	jq -e '.valid' <<<"$out" >/dev/null || die "the chain does not verify after the request prune: $out"
	info "pruned $n change request(s) decided 30+ days ago and named by no entry; the $recent of the last day stay"
}
