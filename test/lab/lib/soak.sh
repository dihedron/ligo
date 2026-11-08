# shellcheck shell=bash
# The soak (.specs/ligo-soak.md): the generator TestSoak on ligo1, against both
# replicas, with the accounts' server.yaml, for SOAK_DURATION; its history and
# the replicas' journals kept as evidence.

SOAK_DIR=/home/ligo/soak # on ligo1: the history and the generator's output
LAB_SOAK=""              # non-empty: serve_config adds the soak's break-glass policy and pool size
SOAK_USERS=(soakop soaka soakb soakbg)

# cmd_soak run: see "lab.sh help".
cmd_soak() {
	require_lab
	case "${1:-}" in
	run) soak_run ;;
	prove) soak_prove ;;
	*) die "soak: run or prove" ;;
	esac
}

# soak_settings: the run's settings, with the spec's defaults.
soak_settings() {
	SOAK_SEED="${SOAK_SEED:-$(date +%s%N)}"
	SOAK_DURATION="${SOAK_DURATION:-15m}"
	SOAK_FAULTS="${SOAK_FAULTS:-none}"
	SOAK_RACE="${SOAK_RACE:-0}"
	SOAK_MAX_CONNS="${SOAK_MAX_CONNS:-}"
	SOAK_ACCOUNTS="${SOAK_ACCOUNTS:-20}"
	[[ "$SOAK_SEED" =~ ^[0-9]+$ ]] || die "SOAK_SEED: digits only"
	[[ "$SOAK_FAULTS" == none ]] || die "SOAK_FAULTS: only none for now"
	((SOAK_ACCOUNTS >= 1 && SOAK_ACCOUNTS <= 100)) || die "SOAK_ACCOUNTS: 1 to 100"
}

# soak_accounts: the names of the soak's long-lived accounts.
soak_accounts() { local i; for ((i = 0; i < SOAK_ACCOUNTS; i++)); do printf 's%02d\n' "$i"; done; }

# soak_directory: the soak's people, a unit per account with its operators
# (soakop) and approvers (soaka, soakb), and the break-glass group (soakbg).
soak_directory() {
	local base="ou=accounts,$LDAP_BASE" user acct
	{
		for user in "${SOAK_USERS[@]}"; do
			printf 'dn: uid=%s,ou=users,%s\nobjectClass: inetOrgPerson\nuid: %s\ncn: %s\nsn: Soak\nuserPassword: %s\n\n' \
				"$user" "$LDAP_BASE" "$user" "$user" "$(inner_exec ldap slappasswd -h '{SSHA}' -s "$(ldap_password "$user")")"
		done
		printf 'dn: cn=soak-breakglass,ou=groups,%s\nobjectClass: groupOfNames\ncn: soak-breakglass\nmember: uid=soakbg,ou=users,%s\n\n' "$LDAP_BASE" "$LDAP_BASE"
		for acct in $(soak_accounts); do
			printf 'dn: ou=%s,%s\nobjectClass: organizationalUnit\nou: %s\n\n' "$acct" "$base" "$acct"
			printf 'dn: cn=operators,ou=%s,%s\nobjectClass: groupOfNames\ncn: operators\nmember: uid=soakop,ou=users,%s\n\n' "$acct" "$base" "$LDAP_BASE"
			printf 'dn: cn=approvers,ou=%s,%s\nobjectClass: groupOfNames\ncn: approvers\nmember: uid=soaka,ou=users,%s\nmember: uid=soakb,ou=users,%s\n\n' \
				"$acct" "$base" "$LDAP_BASE" "$LDAP_BASE"
		done
	} | inner_exec ldap sh -c 'ldapadd -c -Q -Y EXTERNAL -H ldapi:/// >/dev/null 2>&1' || true
	info "soak: ${#SOAK_USERS[@]} people and $SOAK_ACCOUNTS accounts in the directory"
}

# soak_tenancies: two tenancies per soak account on the ledger database, as the
# platform team creates them outside ligo (sql/target.sql does acme's).
soak_tenancies() {
	local acct db ns sql=""
	for acct in $(soak_accounts); do
		for db in 1 2; do
			ns="${acct}_db$db"
			sql+="SELECT 'CREATE ROLE ${ns}_read NOLOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${ns}_read') \\gexec
SELECT 'CREATE ROLE ${ns}_write NOLOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${ns}_write') \\gexec
GRANT ${ns}_read, ${ns}_write TO lab_target_admin WITH ADMIN OPTION;
GRANT CONNECT ON DATABASE ledger TO ${ns}_read, ${ns}_write;
CREATE SCHEMA IF NOT EXISTS $ns;
CREATE TABLE IF NOT EXISTS $ns.entries (id bigint PRIMARY KEY, amount numeric NOT NULL);
GRANT USAGE ON SCHEMA $ns TO ${ns}_read, ${ns}_write;
GRANT SELECT ON $ns.entries TO ${ns}_read, ${ns}_write;
GRANT INSERT, UPDATE ON $ns.entries TO ${ns}_write;
"
		done
	done
	pg_superuser -q -v ON_ERROR_STOP=1 -d ledger <<<"$sql" >/dev/null || die "soak: cannot create the tenancies"
	info "soak: $((SOAK_ACCOUNTS * 2)) tenancies on ledger"
}

# soak_svids: each account's workload's X.509-SVID (1h) and its JWT-SVID for the store
# (asked for 10m; SPIRE caps it at 5), under its account's SPIFFE path, written to ligo1 for the generator.
# With "jwt", only the JWT-SVIDs.
soak_svids() {
	local i acct id dir=/root/soak-svids f only="${1:-}"
	inner_exec spire-prod sh -c "rm -rf $dir && mkdir -m 0700 $dir"
	for ((i = 0; i < SOAK_ACCOUNTS; i++)); do
		printf -v acct 's%02d' "$i"
		id="spiffe://prod.lab/acct/$acct/project/p1/sa/w0"
		if [[ "$only" != jwt ]]; then
			inner_exec spire-prod mkdir -m 0700 "$dir/w$i"
			spire prod x509 mint -spiffeID "$id" -ttl 1h -write "$dir/w$i" >/dev/null 2>&1 || { warn "soak: cannot mint w$i's X.509-SVID"; continue; }
			for f in svid.pem key.pem; do
				inner_exec spire-prod cat "$dir/w$i/$f" |
					inner_exec ligo1 sh -c "cat >$LIGO1_E2E/soakw$i-$f.new && chown ligo:ligo $LIGO1_E2E/soakw$i-$f.new && chmod 0600 $LIGO1_E2E/soakw$i-$f.new"
			done
			# both at once, so that the generator never reads a certificate with the other's key
			inner_exec ligo1 sh -c "mv $LIGO1_E2E/soakw$i-svid.pem.new $LIGO1_E2E/soakw$i-svid.pem && mv $LIGO1_E2E/soakw$i-key.pem.new $LIGO1_E2E/soakw$i-key.pem"
		fi
		spire prod jwt mint -spiffeID "$id" -audience "$(secrets_audience)" -ttl 10m 2>/dev/null |
			inner_exec ligo1 sh -c "tr -d '\n' >$LIGO1_E2E/soakw$i-store-jwt.new && chown ligo:ligo $LIGO1_E2E/soakw$i-store-jwt.new &&
				chmod 0600 $LIGO1_E2E/soakw$i-store-jwt.new && mv $LIGO1_E2E/soakw$i-store-jwt.new $LIGO1_E2E/soakw$i-store-jwt" ||
			warn "soak: cannot mint w$i's JWT-SVID"
	done
	inner_exec spire-prod rm -rf "$dir"
}

# soak_admin_svids: the X.509-SVIDs (1h) of the people the generator acts as
# by SVID, minted again as serve_admins mints them, file by file.
soak_admin_svids() {
	local who dir=/root/soak-admins f
	local -A ids=([ada]=ops/ada [peter]=ops/peter [rita]=ops/rita)
	inner_exec spire-prod sh -c "rm -rf $dir && mkdir -m 0700 $dir"
	for who in "${!ids[@]}"; do
		inner_exec spire-prod mkdir -m 0700 "$dir/$who"
		spire prod x509 mint -spiffeID "spiffe://prod.lab/${ids[$who]}" -ttl 1h -write "$dir/$who" >/dev/null 2>&1 || { warn "soak: cannot mint $who's SVID"; continue; }
		for f in svid.pem key.pem; do
			inner_exec spire-prod cat "$dir/$who/$f" |
				inner_exec ligo1 sh -c "cat >$LIGO1_E2E/$who-$f.new && chown ligo:ligo $LIGO1_E2E/$who-$f.new && chmod 0600 $LIGO1_E2E/$who-$f.new"
		done
		inner_exec ligo1 sh -c "mv $LIGO1_E2E/$who-svid.pem.new $LIGO1_E2E/$who-svid.pem && mv $LIGO1_E2E/$who-key.pem.new $LIGO1_E2E/$who-key.pem"
	done
	inner_exec spire-prod rm -rf "$dir"
}

# soak_renew: renews the SVIDs until stopped: the workloads' JWT-SVIDs every 2
# minutes (SPIRE caps them at 5), every X.509-SVID every 30.
soak_renew() {
	local n=0
	while :; do
		sleep 120
		n=$((n + 1))
		if ((n % 15 == 0)); then
			soak_svids
			soak_admin_svids
		else
			soak_svids jwt
		fi
	done
}

# soak_generator: TestSoak as the user ligo on ligo1, as a transient unit, so
# that it outlives a dropped lxc exec; waits for it and returns its result.
soak_generator() {
	local uid envs=() line timeout
	uid="$(env_get .ligo1.ligo_uid)"
	while IFS= read -r line; do
		envs+=(-E "$line")
	done < <(
		env_ligo
		printf '%s\n' "LIGO_E2E_ADMIN=https://ligo1.ligo.lab:9443" "LIGO_E2E_ADMIN2=https://ligo2.ligo.lab:9443" \
			"LIGO_E2E_WORKLOAD=https://ligo2.ligo.lab:8443" "LIGO_E2E_DIR=$LIGO1_E2E" "LIGO_E2E_SECRETS=$LIGO_E2E_SECRETS" \
			"LIGO_E2E_SUFFIX=$E2E_SUFFIX" "LIGO_SOAK_HISTORY=$SOAK_DIR/history.jsonl" "LIGO_SOAK_SEED=$SOAK_SEED" \
			"LIGO_SOAK_DURATION=$SOAK_DURATION" "LIGO_SOAK_ACCOUNTS=$SOAK_ACCOUNTS" \
			"LIGO_SOAK_DB_DSN=$(pg_dsn migrator pg.ligo.lab /etc/ligo-lab/ca.crt "$SERVE_DB")"
		for line in "${SOAK_USERS[@]}"; do
			printf 'LIGO_SOAK_LDAP_%s_PASS=%s\n' "$(tr '[:lower:]' '[:upper:]' <<<"$line")" "$(ldap_password "$line")"
		done
	)
	timeout="$(($(soak_seconds "$SOAK_DURATION") + 3600))s" # setup and the last convergence
	inner_exec ligo1 sh -c "rm -rf $SOAK_DIR && install -d -o ligo -g ligo -m 0700 $SOAK_DIR"
	inner_exec ligo1 systemctl reset-failed soak-generator 2>/dev/null || true
	inner_exec ligo1 systemd-run --unit soak-generator --uid "$uid" --working-directory "$LIGO_TESTS" \
		-p "StandardOutput=file:$SOAK_DIR/generator.log" -p StandardError=inherit "${envs[@]}" \
		"$LIGO_TESTS/internal_command_serve.test" -test.count=1 -test.v -test.timeout "$timeout" -test.run '^TestSoak$' >/dev/null ||
		die "soak: cannot start the generator"
	info "soak: the generator runs for $SOAK_DURATION (seed $SOAK_SEED)"
	while inner_exec ligo1 systemctl is-active --quiet soak-generator; do
		sleep 30
	done
	[[ "$(inner_exec ligo1 systemctl show -p ExecMainStatus --value soak-generator)" == 0 ]]
}

# soak_seconds DURATION: a Go duration of hours, minutes and seconds, in seconds.
soak_seconds() {
	local d="$1" s=0
	[[ "$d" =~ ([0-9]+)h ]] && s=$((s + BASH_REMATCH[1] * 3600))
	[[ "$d" =~ ([0-9]+)m ]] && s=$((s + BASH_REMATCH[1] * 60))
	[[ "$d" =~ ([0-9]+)s ]] && s=$((s + BASH_REMATCH[1]))
	((s > 0)) || die "SOAK_DURATION: hours, minutes or seconds, such as 8h or 15m"
	echo "$s"
}

# soak_run: install the accounts' ligo with the soak's additions, seed the
# soak's people and tenancies, run the generator, keep the evidence. A dirty
# tree runs only with SOAK_DEV=1, and its evidence goes to the state directory.
soak_run() {
	soak_settings
	local commit dir renewer rc=0 host
	commit="$(git -C "$REPO_DIR" rev-parse HEAD)"
	if [[ -n "$(git -C "$REPO_DIR" status --porcelain)" ]]; then
		[[ "${SOAK_DEV:-}" == 1 ]] || die "soak: the tree is dirty: commit first, or SOAK_DEV=1 for a trial run that is not evidence"
		dir="$LAB_STATE_DIR/soak-dev-$(date +%Y%m%dT%H%M%S)"
	else
		dir="$REPO_DIR/test/lab/.evidence/soak-$commit-$(date +%Y%m%dT%H%M%S)"
	fi
	mkdir -p "$dir"
	jq -n --arg commit "$commit" --arg seed "$SOAK_SEED" --arg duration "$SOAK_DURATION" --arg faults "$SOAK_FAULTS" \
		--arg race "$SOAK_RACE" --arg max_conns "$SOAK_MAX_CONNS" --arg accounts "$SOAK_ACCOUNTS" \
		--arg backend "$(secrets_backend)" --arg dirty "${SOAK_DEV:-0}" '$ARGS.named' >"$dir/settings.json"

	section "soak: install"
	LAB_SOAK=yes
	serve_accounts_install # resets the lab, installs ligo with charter.accounts, mints the admins' SVIDs
	soak_directory
	soak_tenancies
	soak_svids

	section "soak: run"
	soak_renew &
	renewer=$!
	soak_generator || rc=1
	kill "$renewer" 2>/dev/null || true
	wait "$renewer" 2>/dev/null || true

	section "soak: the checks after the run"
	soak_check_outbox "$dir" || rc=1
	(serve_scan_secrets 1) 2>&1 | tee "$dir/secrets-scan.log" || { soak_violation "$dir" SK-8 "a password is in the database or a journal"; rc=1; }

	section "soak: evidence"
	inner_exec ligo1 cat "$SOAK_DIR/history.jsonl" >"$dir/history.jsonl" || warn "soak: no history"
	inner_exec ligo1 cat "$SOAK_DIR/generator.log" >"$dir/generator.log" || true
	for host in $(ligo_hosts); do
		inner_exec "$host" journalctl --no-pager -u ligo -o cat >"$dir/journal-$host.log" || true
	done
	release_versions >"$dir/versions.txt"
	soak_summary "$dir" | tee "$dir/summary.md"
	((rc == 0)) || die "soak: the generator failed; see $dir/generator.log"
	info "soak: evidence in $dir"
}

# soak_violation DIR ID DETAIL: a violation found by lab.sh, not by the
# generator, appended to the history as the generator writes them.
soak_violation() {
	jq -cn --arg id "$2" --arg detail "$3" '{t: (now | todate), kind: "violation", res: $id, note: $detail, by: "lab.sh"}' >>"$1/violations-lab.jsonl"
	warn "soak: $2: $3"
}

# soak_check_outbox DIR: SK-9's other half: every event the outbox marks
# delivered reached the receiver.
soak_check_outbox() {
	local dir="$1" missing
	hooks_drained
	serve_sql "select event_id from notification_outbox where delivered_at is not null order by 1" >"$dir/outbox-delivered.txt"
	inner_exec hooks cat "$HOOKS_LOG" | jq -r '.body | fromjson | .eventId' | sort -u >"$dir/receiver-events.txt"
	missing="$(comm -23 <(sort -u "$dir/outbox-delivered.txt") "$dir/receiver-events.txt" | wc -l)"
	info "SK-9: $(wc -l <"$dir/outbox-delivered.txt") events delivered, $missing not at the receiver"
	((missing == 0)) || { soak_violation "$dir" SK-9 "$missing delivered events never reached the receiver"; return 1; }
}

# SOAK_MUTANTS: each mutant of test/lab/soak/mutants and the invariants it must
# trip (any one of them), with the settings it needs; "control" is the build
# as committed, which must trip none.
SOAK_MUTANTS=(
	"control||"
	"four-eyes|SK-4|"
	"revoke-keeps-role|SK-1 SK-6|"
	"cross-tenant-grant|SK-3|"
	"pool-deadlock|SK-7 SK-10|SOAK_MAX_CONNS=1"
)

# soak_prove: each mutant applied to a worktree of HEAD, run for
# SOAK_DURATION (default 15m) with the same seed, its violations compared with
# those it must trip (.specs/ligo-soak.md §8). The verdicts are evidence.
soak_prove() {
	[[ -z "$(git -C "$REPO_DIR" status --porcelain)" ]] || die "soak prove: the tree is dirty: commit first"
	local commit out entry name expect extra wt dir got rc=0 verdict
	commit="$(git -C "$REPO_DIR" rev-parse HEAD)"
	out="$REPO_DIR/test/lab/.evidence/soak-prove-$commit-$(date +%Y%m%dT%H%M%S)"
	mkdir -p "$out"
	printf '# Soak prove %s, seed %s\n\n| Mutant | Must trip | Tripped | Verdict |\n| :-- | :-- | :-- | :-- |\n' \
		"${commit:0:7}" "${SOAK_SEED:=$(date +%s%N)}" >"$out/prove.md"
	for entry in "${SOAK_MUTANTS[@]}"; do
		IFS='|' read -r name expect extra <<<"$entry"
		section "soak prove: $name"
		wt="$LAB_STATE_DIR/prove-wt"
		git -C "$REPO_DIR" worktree remove --force "$wt" 2>/dev/null || rm -rf "$wt"
		git -C "$REPO_DIR" worktree add -q --detach "$wt" "$commit" || die "soak prove: cannot create the worktree"
		[[ "$name" == control ]] || git -C "$wt" apply "$REPO_DIR/test/lab/soak/mutants/$name.patch" || die "soak prove: $name does not apply"
		rm -rf "$wt/test/lab/.state"
		ln -s "$LAB_STATE_DIR" "$wt/test/lab/.state"
		[[ -f "$LAB_DIR/lab.local.env" ]] && cp "$LAB_DIR/lab.local.env" "$wt/test/lab/"
		# shellcheck disable=SC2086 # extra is VAR=value or empty
		(cd "$wt" && env SOAK_DEV=1 SOAK_SEED="$SOAK_SEED" SOAK_DURATION="${SOAK_DURATION:-15m}" $extra LAB_ASSUME_YES=yes test/lab/lab.sh soak run) \
			2>&1 | tee "$out/$name.log" || true
		dir="$(find "$LAB_STATE_DIR" -maxdepth 1 -name 'soak-dev-*' | sort | tail -n 1)" # names sort by time; ls | head would SIGPIPE under pipefail
		cp "$dir/summary.md" "$out/$name-summary.md" 2>/dev/null || true
		got="$({ cat "$dir/history.jsonl" 2>/dev/null || true; cat "$dir/violations-lab.jsonl" 2>/dev/null || true; } | jq -rs '[.[] | select(.kind == "violation") | .res] | unique | join(" ")')"
		if [[ -z "$expect" ]]; then
			[[ -z "$got" ]] && verdict=pass || verdict=FAIL
		else
			verdict=FAIL
			for id in $expect; do [[ " $got " == *" $id "* ]] && verdict=pass; done
		fi
		[[ "$verdict" == pass ]] || rc=1
		printf '| %s | %s | %s | %s |\n' "$name" "${expect:-none}" "${got:-none}" "$verdict" >>"$out/prove.md"
		info "soak prove: $name tripped ${got:-nothing}: $verdict"
		git -C "$REPO_DIR" worktree remove --force "$wt"
	done
	cat "$out/prove.md"
	((rc == 0)) || die "soak prove: the checker misses a mutant, or the control trips: see $out"
	info "soak prove: every mutant tripped its invariant and the control none: $out"
}

# soak_summary DIR: the counts of the history, by kind and answer.
soak_summary() {
	local h="$1/history.jsonl"
	printf '# Soak %s\n\n' "$(jq -r '"\(.commit[0:7]), seed \(.seed), \(.duration), faults \(.faults), \(.backend)"' "$1/settings.json")"
	printf '| Kind | Calls | Answers | Errors | p95 ms |\n| :-- | --: | :-- | --: | --: |\n'
	jq -rs 'group_by(.kind)[] | {k: .[0].kind, n: length,
		codes: (map(select(.code) | .code) | group_by(.) | map("\(.[0]):\(length)") | join(" ")),
		errs: map(select(.err)) | length,
		p95: (map(select(.ms) | .ms) | sort | if length > 0 then .[(length * 95 / 100 | floor)] else 0 end)}
		| "| \(.k) | \(.n) | \(.codes) | \(.errs) | \(.p95) |"' "$h"
	printf '\n## Violations\n\n'
	{ cat "$h"; cat "$1/violations-lab.jsonl" 2>/dev/null || true; } | jq -rs '[.[] | select(.kind == "violation")] |
		if length == 0 then "None." else (group_by(.res)[] | "- \(.[0].res): \(length), first: \(.[0].note)") end'
	printf '\n## Checks skipped\n\n'
	jq -rs '[.[] | select(.kind == "check:skipped")] | if length == 0 then "None." else (group_by(.res)[] | "- \(.[0].res): \(length), first: \(.[0].err)") end' "$h"
}
