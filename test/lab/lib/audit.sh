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
	local head out file keys deleted oldest
	ligo1_user audit-admin spiffe://prod.lab/ops/ada # full access: an export spans every jurisdiction
	head="$(audit_anchor)"
	info "a checkpoint of entry $head, signed with the store's key, dated 25 hours ago"
	file="/tmp/audit-$(openssl rand -hex 4).jsonl"
	out="$(cli audit-admin -o json audit export --through "$head" --out "$file")" || die "ligo audit export failed"
	[[ "$(jq -r .through <<<"$out")" == "$head" ]] || die "the export ends at $(jq -r .through <<<"$out"), not $head"
	info "exported $(jq -r .entries <<<"$out") entries through $head, recorded with sha256 $(jq -r .sha256 <<<"$out" | cut -c1-12)…"
	mapfile -t keys < <(audit_public_keys)
	out="$(cli audit-admin -o json audit verify --file "$file" "${keys[@]}")" || die "the export does not verify with the store's keys: $out"
	jq -e '.valid and (.keysFromFile | not)' <<<"$out" >/dev/null || die "verify --file: $out"
	inner_exec ligo1 sh -c "sed '0,/\"actor\":\"/s//\"actor\":\"x/' '$file' >'$file.changed' && chmod 0644 '$file.changed'"
	if out="$(cli audit-admin -o json audit verify --file "$file.changed" "${keys[@]}" 2>&1)"; then
		die "a changed export verified: $out"
	fi
	info "the export verifies offline with the store's public keys; a changed copy does not"

	out="$(serve_sql "select audit_prune(0)" 2>&1)" && die "audit_prune of a non-checkpoint passed: $out"
	grep -q "is not a checkpoint" <<<"$out" || die "audit_prune of a non-checkpoint: $out"
	deleted="$(serve_sql "select audit_prune($head)")"
	oldest="$(serve_sql "select coalesce(min(id), 0) from audit_log")"
	((oldest == 0 || oldest > head)) || die "entry $oldest left after pruning through $head"
	cli audit-admin maintenance on -m "serve test-audit: an entry after the prune" >/dev/null
	cli audit-admin maintenance off >/dev/null
	out="$(cli audit-admin -o json audit verify --full)" || die "ligo audit verify --full failed"
	jq -e '.valid' <<<"$out" >/dev/null || die "the chain does not verify after the prune: $out"
	inner_exec ligo1 curl -fsS http://127.0.0.1:9090/metrics | grep -q '^ligo_audit_oldest_entry_timestamp_seconds ' ||
		die "ligo_audit_oldest_entry_timestamp_seconds is not served"
	info "pruned $deleted entries through $head; new entries chain onto the anchor; the full verification passes"
}
