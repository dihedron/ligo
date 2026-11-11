# shellcheck shell=bash
# The soak's faults and drift (.specs/ligo-soak.md §6, §7): a seeded scheduler
# that applies one fault at a time (SOAK_FAULTS=single), then pairs of them too
# (all), measures each one's recovery, and samples the replicas every 10
# minutes. While a fault holds, and until ligo has recovered, a marker on ligo1
# tells the generator's checker to skip the checks of what is faulted.

SOAK_FAULT_GAP=300 # seconds between faults
SOAK_UNDO=()       # what undoes the faults in effect, for the trap
SOAK_LAST=()       # the last fault applied and when it started, for soak_damage

# SOAK_FAULT_LIST: name, duration in seconds, recovery limit in seconds.
SOAK_FAULT_LIST=(
	"ligo-hang 60 60" "plugin-hang 60 120" "pg-hang 30 120" "ldap-hang 60 120"
	"slow-pg 300 60" "slow-ldap 300 60" "slow-store 300 60" "partition 120 120"
	"conns-full 120 120" "long-lock 60 120" "memory 300 60" "spire-down 600 120"
	"store-sealed 120 120" "webhook-down 300 300" "reload 0 60" "maintenance 120 60"
	"rolling-restart 0 120" "group-change 300 60" "audit-prune 0 60"
)

# soak_marker NAME|"": the marker the checker reads; "" removes it.
soak_marker() {
	if [[ -n "$1" ]]; then
		inner_exec ligo1 sh -c "echo '$1' >$SOAK_DIR/fault && chown ligo:ligo $SOAK_DIR/fault"
	else
		inner_exec ligo1 rm -f "$SOAK_DIR/fault"
	fi
}

# soak_listens HOST SECONDS: whether ligo on HOST listens on :9443 within
# SECONDS; unlike serve_wait, never ends the caller.
soak_listens() {
	local host="$1" out
	for _ in $(seq 1 "$2"); do
		out="$(inner_exec "$host" ss -Hltn 'sport = :9443' 2>/dev/null)" || true
		grep -q LISTEN <<<"$out" && return 0
		sleep 1
	done
	return 1
}

# soak_netem HOSTS IP DELAY LOSS: delay and loss on traffic from HOSTS to IP;
# soak_netem_off HOSTS undoes it. Other traffic is untouched.
soak_netem() {
	local hosts="$1" ip="$2" delay="$3" loss="$4" h
	for h in $hosts; do
		inner_exec "$h" sh -c "tc qdisc del dev enp5s0 root 2>/dev/null; tc qdisc add dev enp5s0 root handle 1: prio &&
			tc qdisc add dev enp5s0 parent 1:3 handle 30: netem $delay loss $loss &&
			tc filter add dev enp5s0 protocol ip parent 1:0 prio 3 u32 match ip dst $ip/32 flowid 1:3"
	done
}
soak_netem_off() { local h; for h in $1; do inner_exec "$h" tc qdisc del dev enp5s0 root 2>/dev/null || true; done; }

# soak_pg_bg SQL [DB]: SQL as postgres in the background on pg, detached.
soak_pg_bg() {
	inner_exec pg sh -c "setsid nohup sudo -u postgres psql -Xq -d ${2:-postgres} -c \"$1\" >/dev/null 2>&1 &"
}

# soak_fault NAME start|stop: one fault. start registers its undo.
soak_fault() {
	local name="$1" op="$2" store unit
	store="$(secrets_host)"
	unit=openbao
	[[ "$store" == vault-* ]] && unit=vault
	case "$name:$op" in
	ligo-hang:start) inner_exec ligo2 systemctl kill -s STOP ligo ;;
	ligo-hang:stop) inner_exec ligo2 systemctl kill -s CONT ligo ;;
	plugin-hang:start) inner_exec ligo1 pkill -STOP -f ligo-plugin-postgres || true ;;
	plugin-hang:stop) inner_exec ligo1 pkill -CONT -f ligo-plugin-postgres || true ;;
	pg-hang:start) inner_exec pg pkill -STOP -u postgres ;;
	pg-hang:stop) inner_exec pg pkill -CONT -u postgres ;;
	ldap-hang:start) inner_exec ldap systemctl kill -s STOP slapd ;;
	ldap-hang:stop) inner_exec ldap systemctl kill -s CONT slapd ;;
	slow-pg:start) soak_netem "$(ligo_hosts)" "$(inner_ip pg)" "delay 200ms 50ms" 1% ;;
	slow-ldap:start) soak_netem "$(ligo_hosts)" "$(inner_ip ldap)" "delay 2s" 0% ;;
	slow-store:start) soak_netem "$(ligo_hosts)" "$(inner_ip "$store")" "delay 500ms" 0% ;;
	partition:start) soak_netem ligo2 "$(inner_ip pg)" "delay 0ms" 100% ;;
	slow-pg:stop | slow-ldap:stop | slow-store:stop | partition:stop) soak_netem_off "$(ligo_hosts)" ;;
	conns-full:start)
		local n
		n="$(pg_superuser -tAc "select current_setting('max_connections')::int - current_setting('superuser_reserved_connections')::int - count(*) from pg_stat_activity where backend_type = 'client backend'")"
		local i
		for ((i = 0; i < n; i++)); do soak_pg_bg "select pg_sleep(120) /* soak-filler */"; done
		;;
	conns-full:stop | long-lock:stop)
		pg_superuser -tAc "select pg_terminate_backend(pid) from pg_stat_activity where query like '%soak-%' and pid <> pg_backend_pid()" >/dev/null
		;;
	long-lock:start) soak_pg_bg "begin; lock table bindings in access exclusive mode; select pg_sleep(60) /* soak-lock */; commit;" "$SERVE_DB" ;;
	memory:start)
		local cur
		cur="$(inner_exec ligo2 systemctl show -p MemoryCurrent --value ligo)"
		inner_exec ligo2 systemctl set-property --runtime ligo "MemoryHigh=$((cur * 12 / 10))"
		;;
	memory:stop) inner_exec ligo2 systemctl set-property --runtime ligo MemoryHigh=infinity ;;
	spire-down:start) inner_exec spire-prod systemctl stop spire-server ;;
	spire-down:stop) inner_exec spire-prod systemctl start spire-server ;;
	store-sealed:start) server_cli "$store" operator seal >/dev/null ;;
	store-sealed:stop) bao_unseal "$store" ;;
	webhook-down:start) inner_exec hooks systemctl stop "$HOOKS_UNIT" ;;
	webhook-down:stop) inner_exec hooks systemctl start "$HOOKS_UNIT" ;;
	reload:start) inner_exec ligo1 systemctl reload ligo ;;
	reload:stop | rolling-restart:stop) ;;
	maintenance:start) cli soak-admin maintenance on -m "the soak's maintenance fault" >/dev/null ;;
	maintenance:stop) cli soak-admin maintenance off >/dev/null ;;
	audit-prune:start)
		# an export through a current entry, recorded as ligo audit export
		# would, and a prune through it under the generator's load
		local head
		head="$(audit_anchor)"
		serve_sql "insert into audit_exports (through, sha256, actor) values ($head, repeat('0', 64), 'soak')" >/dev/null
		serve_sql "select audit_prune($head)" >/dev/null
		;;
	audit-prune:stop) ;;
	rolling-restart:start)
		# paired with a fault ligo refuses to start under (a sealed store, SPIRE
		# down), a replica stays down until that fault is undone: the roll stops
		# there, so the other replica keeps serving, and the recovery after the
		# undo judges it (serve_wait would end the scheduler)
		local h
		for h in $(ligo_hosts); do
			inner_exec "$h" systemctl restart ligo
			soak_listens "$h" 60 || {
				warn "soak: rolling-restart: ligo on $h does not listen after 60s; the roll stops there"
				break
			}
		done
		;;
	group-change:start) printf 'dn: cn=approvers,ou=s00,ou=accounts,%s\nchangetype: modify\ndelete: member\nmember: uid=soakb,ou=users,%s\n' "$LDAP_BASE" "$LDAP_BASE" | ldap_admin ldapmodify >/dev/null ;;
	group-change:stop) printf 'dn: cn=approvers,ou=s00,ou=accounts,%s\nchangetype: modify\nadd: member\nmember: uid=soakb,ou=users,%s\n' "$LDAP_BASE" "$LDAP_BASE" | ldap_admin ldapmodify >/dev/null ;;
	*) die "soak: no fault $name:$op" ;;
	esac
}

# soak_answers: both replicas answer an authenticated list.
soak_answers() {
	local h
	for h in $(ligo_hosts); do
		CLI_SERVER="$h.ligo.lab" cli ligo-approver -o json list bindings >/dev/null 2>&1 || return 1
	done
}

# soak_fault_log DIR JSON-ARGS...: a line of faults.jsonl.
soak_fault_log() {
	local dir="$1"
	shift
	jq -cn --arg t "$(date -u +%FT%T.%3NZ)" "$@" '$ARGS.named + {t: $t}' >>"$dir/faults.jsonl"
}

# soak_apply DIR NAMES...: the faults NAMES at once: start, hold for the longest
# duration, stop, then the recovery measured against the largest limit.
soak_apply() {
	local dir="$1" name d l hold=0 limit=0 start waited=0
	shift
	for name in "$@"; do
		read -r _ d l < <(printf '%s\n' "${SOAK_FAULT_LIST[@]}" | grep "^$name ")
		((d > hold)) && hold=$d
		((l > limit)) && limit=$l
	done
	local t0
	t0="$(date -u +%FT%T.%3NZ)"
	soak_marker "$*"
	for name in "$@"; do
		soak_fault_log "$dir" --arg fault "$name" --arg event start
		soak_fault "$name" start || warn "soak: $name did not start"
		SOAK_UNDO+=("$name")
	done
	sleep "$hold"
	local failed=()
	for name in "$@"; do
		soak_fault "$name" stop || failed+=("$name")
		soak_fault_log "$dir" --arg fault "$name" --arg event stop
	done
	# an undo can need what the pair's other fault broke (maintenance off
	# under pg-hang): try it again once every other fault is undone
	for name in "${failed[@]}"; do
		soak_fault "$name" stop || warn "soak: $name did not stop"
	done
	SOAK_UNDO=()
	start="$(date +%s)"
	until soak_answers; do
		sleep 5
		waited=$(($(date +%s) - start))
		((waited > limit + 600)) && break
	done
	waited=$(($(date +%s) - start))
	soak_fault_log "$dir" --arg fault "$*" --arg event recovered --argjson seconds "$waited" --argjson limit "$limit"
	if ((waited > limit)); then
		soak_violation "$dir" RECOVERY "$* recovered in ${waited}s, over its limit of ${limit}s"
	fi
	soak_marker ""
	SOAK_LAST=("$*" "$t0")
}

# soak_damage DIR: SOAK_FAULT_GAP after a fault, every binding that went to
# FAILED or DELETE_FAILED since the fault started, and stayed there, is damage
# the fault left: ligo did not finish the operation by itself (DAMAGE).
soak_damage() {
	local dir="$1" n
	((${#SOAK_LAST[@]})) || return 0
	n="$(serve_sql "select count(*) from bindings where phase in ('FAILED', 'DELETE_FAILED') and last_transition_at >= '${SOAK_LAST[1]}'")"
	soak_fault_log "$dir" --arg fault "${SOAK_LAST[0]}" --arg event damage --argjson bindings "${n:-0}"
	((n == 0)) || soak_violation "$dir" DAMAGE "${SOAK_LAST[0]} left $n bindings FAILED or DELETE_FAILED"
	SOAK_LAST=()
}

# soak_undo: stops the faults in effect, for the trap.
soak_undo() {
	local name
	for name in "${SOAK_UNDO[@]}"; do soak_fault "$name" stop 2>/dev/null || true; done
	SOAK_UNDO=()
	soak_marker "" 2>/dev/null || true
}

# soak_faults DIR: the scheduler, until the generator ends. It waits for the
# setup, then applies the catalogue in seeded order, SOAK_FAULT_GAP apart; with
# all, each pass after the first pairs faults at random.
soak_faults() {
	local dir="$1" order=() pass=0 i a b stop_at
	trap soak_undo EXIT
	# no fault may overlap the generator's last convergence and check
	stop_at=$(($(date +%s) + $(soak_seconds "$SOAK_DURATION") - 900))
	RANDOM=$((SOAK_SEED % 32768))
	local seen=0 # the generator starts after the scheduler: it has ended only once seen running
	until inner_exec ligo1 grep -q '"kind":"setup:done"' "$SOAK_DIR/history.jsonl" 2>/dev/null; do
		if inner_exec ligo1 systemctl is-active --quiet soak-generator; then
			seen=1
		elif ((seen)); then
			return 0
		fi
		sleep 10
	done
	while :; do
		mapfile -t order < <(printf '%s\n' "${SOAK_FAULT_LIST[@]}" | cut -d' ' -f1 | grep -vxF -f <(tr ' ' '\n' <<<"${SOAK_EXCLUDE:-}" | grep . || echo '-') | awk -v s="$RANDOM" 'BEGIN{srand(s)} {print rand() "\t" $0}' | sort | cut -f2)
		for ((i = 0; i < ${#order[@]}; i++)); do
			sleep "$SOAK_FAULT_GAP"
			soak_damage "$dir"
			inner_exec ligo1 systemctl is-active --quiet soak-generator || return 0
			(($(date +%s) < stop_at)) || return 0
			a="${order[$i]}"
			if [[ "$SOAK_FAULTS" == all && "$pass" -gt 0 ]]; then
				b="${order[$(((i + 1 + RANDOM % (${#order[@]} - 1)) % ${#order[@]}))]}"
				soak_apply "$dir" "$a" "$b"
			else
				soak_apply "$dir" "$a"
			fi
		done
		pass=$((pass + 1))
	done
}

# soak_drift DIR: every 10 minutes, one row per host and metric in drift.csv.
soak_drift() {
	local dir="$1" t h pid
	echo "t,host,metric,value" >"$dir/drift.csv"
	while :; do
		t="$(date -u +%FT%TZ)"
		for h in $(ligo_hosts); do
			pid="$(inner_exec "$h" systemctl show -p MainPID --value ligo 2>/dev/null)" || continue
			[[ "$pid" =~ ^[1-9][0-9]*$ ]] || continue
			inner_exec "$h" sh -c "awk '/^VmRSS/{print \"rss_kib,\" \$2} /^Threads/{print \"threads,\" \$2}' /proc/$pid/status;
				echo fds,\$(ls /proc/$pid/fd | wc -l); echo plugins,\$(pgrep -c -f ligo-plugin- || true)" 2>/dev/null |
				sed "s/^/$t,$h,/" >>"$dir/drift.csv"
		done
		pg_superuser -tA -F, -c "select '$t', 'pg', 'conns_' || coalesce(usename, 'none'), count(*) from pg_stat_activity group by usename" 2>/dev/null >>"$dir/drift.csv" || true
		pg_superuser -d "$SERVE_DB" -tA -F, -c "select '$t', 'pg', 'rows_' || relname, n_live_tup from pg_stat_user_tables where relname in ('audit_log', 'notification_outbox', 'bindings')" 2>/dev/null >>"$dir/drift.csv" || true
		sleep 600
	done
}

# soak_drift_report DIR: per host and metric, the first hour's median against
# the last sample; a rise over 20 % in RSS, FDs, threads, plugins or
# connections fails a run of 2 hours or more.
soak_drift_report() {
	local dir="$1" hours="$2"
	printf '\n## Drift\n\n| Host | Metric | First hour (median) | Last | Change |\n| :-- | :-- | --: | --: | --: |\n'
	awk -F, -v hours="$hours" 'NR > 1 {
			k = $2 "," $3; if (!(k in t0)) t0[k] = $1; n[k]++; v[k, n[k]] = $4; last[k] = $4
		}
		END {
			for (k in n) {
				m = 0; for (i = 1; i <= n[k] && i <= 6; i++) a[++m] = v[k, i]
				asort(a); med = a[int((m + 1) / 2)]; delete a
				ch = (med > 0) ? (last[k] - med) * 100 / med : 0
				split(k, p, ","); printf "| %s | %s | %s | %s | %+.0f %% |\n", p[1], p[2], med, last[k], ch
				if (hours >= 2 && ch > 20 && p[2] !~ /^rows_/) print k "," ch > "/dev/stderr"
			}
		}' "$dir/drift.csv" 2>"$dir/drift-over.txt" | sort
	local line
	while IFS= read -r line; do
		soak_violation "$dir" DRIFT "$line % over the first hour's median"
	done <"$dir/drift-over.txt"
}

# soak_fault_report DIR: each fault and its recovery.
soak_fault_report() {
	[[ -s "$1/faults.jsonl" ]] || return 0
	printf '\n## Faults\n\n| Fault | Recovered in | Limit |\n| :-- | --: | --: |\n'
	jq -r 'select(.event == "recovered") | "| \(.fault) | \(.seconds) s | \(.limit) s |"' "$1/faults.jsonl"
}

# soak_try NAME...|all: each fault on its own against the lab as soak run left
# it, its recovery measured; the record goes to the state directory.
soak_try() {
	local dir name names=("$@")
	[[ "${names[0]:-}" == all ]] && mapfile -t names < <(printf '%s\n' "${SOAK_FAULT_LIST[@]}" | cut -d' ' -f1)
	((${#names[@]})) || die "soak fault: NAME... or all"
	dir="$LAB_STATE_DIR/soak-faults-$(date +%Y%m%dT%H%M%S)"
	mkdir -p "$dir"
	inner_exec ligo1 install -d -o ligo -g ligo -m 0700 "$SOAK_DIR"
	trap soak_undo EXIT
	for name in "${names[@]}"; do
		section "soak fault: $name"
		# a+b applies faults a and b together, as a pair in a run does
		# shellcheck disable=SC2086
		soak_apply "$dir" ${name//+/ }
		sleep 30
		soak_damage "$dir"
	done
	soak_fault_report "$dir"
	[[ ! -s "$dir/violations-lab.jsonl" ]] || die "soak fault: a recovery was over its limit: $dir"
}
