# shellcheck shell=bash
# The echo target on ligo1: a toy service that a workload reaches only
# through a binding, to test bindings by hand (.specs/ligo-echo-target.md).

# ECHO_SERVERS: name, mode, data port, control port.
ECHO_SERVERS=("echo-svid svid 7101 7102" "echo-local password 7201 7202")
ECHO_SERVER_ID=spiffe://prod.lab/ns/lab/sa/echo-server
ECHO_USERS=("echo-bound ns/echo/sa/bound" "echo-unbound ns/echo/sa/unbound")

cmd_echo() {
	require_lab
	inner_exists ligo1 || die "ligo1 does not exist: lab.sh up --scenario identity"
	case "${1:-status}" in
	install) echo_install ;;
	status)
		local s
		for s in "${ECHO_SERVERS[@]}"; do
			inner_exec ligo1 systemctl --no-pager status "${s%% *}" || true
		done
		;;
	logs) inner_exec ligo1 journalctl --no-pager -u echo-svid -u echo-local ;;
	client)
		shift
		[[ $# -ge 2 ]] || die "echo client USER TARGET [args]"
		echo_client "$@"
		;;
	smoke) echo_smoke ;;
	ui-smoke) echo_ui_smoke ;;
	*) die "echo: install, status, logs, client, smoke or ui-smoke" ;;
	esac
}

# echo_install: the echo servers, their identity, the users echo-bound and
# echo-unbound, and the two targets (after lab.sh serve install, which
# deploys ligo-plugin-echo and configures the echo platforms).
echo_install() {
	section "The echo target on ligo1"
	inner_exec ligo1 systemctl -q is-active ligo || die "ligo does not run on ligo1: lab.sh serve install"
	local out="$LAB_STATE_DIR/echo" s name mode data control
	mkdir -p "$out"
	for s in "${ECHO_SERVERS[@]}"; do
		inner_exec ligo1 systemctl stop "${s%% *}" 2>/dev/null || true # their binary is replaced
	done
	for name in server client; do
		(cd "$REPO_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$out/echo-$name" "./test/lab/echo/$name") ||
			die "cannot build echo-$name"
		inner_push "$out/echo-$name" ligo1 "/usr/local/bin/echo-$name" 0755
	done
	ligo1_user echo "$ECHO_SERVER_ID"
	info "the echo servers run as the user echo, which holds $ECHO_SERVER_ID"
	for s in "${ECHO_SERVERS[@]}"; do
		read -r name mode data control <<<"$s"
		inner_exec ligo1 sh -c "cat >/etc/systemd/system/$name.service" <<UNIT
[Unit]
Description=lab echo server ($mode mode), .specs/ligo-echo-target.md
After=network-online.target

[Service]
User=echo
StateDirectory=$name
ExecStart=/usr/local/bin/echo-server --mode $mode --data :$data --control :$control --state /var/lib/$name/state.json \\
  --socket unix:///run/spire/prod/agent.sock --control-id spiffe://prod.lab/ligo/plugin/echo
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT
	done
	inner_exec ligo1 systemctl daemon-reload
	for s in "${ECHO_SERVERS[@]}"; do
		read -r name mode data control <<<"$s"
		inner_exec ligo1 systemctl enable "$name" >/dev/null 2>&1
		inner_exec ligo1 systemctl restart "$name"
		echo_wait "$data" && echo_wait "$control" || die "$name does not listen on :$data and :$control"
		info "$name ($mode mode) listens on ligo1.ligo.lab:$data, its control API on :$control"
	done
	local pair
	for pair in "${ECHO_USERS[@]}"; do
		ligo1_user "${pair%% *}" "spiffe://prod.lab/${pair#* }"
		info "the user ${pair%% *} on ligo1 holds spiffe://prod.lab/${pair#* }"
	done
	echo_target echo-svid-target echo-svid 7101 "admits SVIDs"
	echo_target echo-local-target echo-local 7201 "admits users with a password"
	info "the echo target is ready: see the guide in .specs/ligo-echo-target.md"
}

# echo_wait PORT: until something listens on ligo1:PORT, for 30s.
echo_wait() {
	local out
	for _ in $(seq 1 30); do
		out="$(inner_exec ligo1 ss -Hltn "sport = :$1" 2>/dev/null)" || true
		grep -q LISTEN <<<"$out" && return
		sleep 1
	done
	return 1
}

# echo_target NAME PLATFORM PORT WHAT: publishes the target as ligo-ops and
# approves it as ligo-approver, unless it exists.
echo_target() {
	local name="$1" platform="$2" port="$3" what="$4"
	if cli ligo-ops get target "$name" >/dev/null 2>&1; then
		info "the target $name exists"
		return
	fi
	cli ligo-ops apply -f - <<YAML >/dev/null || die "apply the target $name"
kind: Target
metadata: {name: $name, platform: $platform, jurisdiction: dc/corp-prod/echo}
displayName: "Echo server that $what"
description: "The lab's echo target (.specs/ligo-echo-target.md): it echoes a line with the client's identity."
definition: {}
accessLevels: [{name: echo, description: "send a line, get it back", grants: {}}]
networkFlows: [{name: echo, purpose: DATA, protocol: TCP, destination: ligo1.ligo.lab, ports: [$port], tls: true}]
visibility: {mode: PUBLIC}
YAML
	cli_approve target "$name"
	info "the target $name is published"
}

# echo_client USER TARGET ARGS: echo-client on ligo1 as USER; its exit
# status is the client's.
echo_client() {
	local user="$1" target="$2" uid
	shift 2
	uid="$(inner_exec ligo1 id -u "$user" </dev/null)" || die "no user $user on ligo1"
	lxd exec lxd -- lxc exec ligo1 --user "$uid" --cwd /tmp --env SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/prod/agent.sock -- \
		/usr/local/bin/echo-client --target "$target" --audience "$(secrets_audience)" "$@"
}

# expect CODE PATTERN USER TARGET ARGS: runs the client and checks its exit
# status and that its output matches PATTERN.
expect() {
	local want="$1" pattern="$2" out code=0
	shift 2
	out="$(echo_client "$@" </dev/null 2>&1)" || code=$?
	[[ "$code" == "$want" ]] && grep -qE "$pattern" <<<"$out" ||
		die "echo client $*: exit $code, want $want matching /$pattern/:"$'\n'"$out"
	info "echo client $1 $2 ${*:3}: exit $code, $(tail -1 <<<"$out")"
}

# echo_smoke: the guide's CLI part for both targets, scripted, then the
# source retired again so the guide starts clean (.specs/ligo-echo-target.md).
echo_smoke() {
	section "Echo smoke test"
	local mode target binding port direct revision bound=spiffe://prod.lab/ns/echo/sa/bound
	for mode in svid local; do
		target="echo-$mode-target" binding="echo-bound-$mode"
		port=7101 direct=(--mode svid)
		if [[ "$mode" == local ]]; then
			port=7201 direct=(--mode password --user anyone --password anything)
		fi
		expect 2 '^no binding$' echo-bound "$target"
		expect 2 '^no binding$' echo-unbound "$target"
		expect 3 '^denied$' echo-bound "$target" --direct "ligo1.ligo.lab:$port" "${direct[@]}"
		if ! cli ligo-ops get source echo-bound-src >/dev/null 2>&1; then
			cli ligo-ops apply -f - <"$REPO_DIR/test/lab/echo/manifests/source.yaml" >/dev/null || die "apply the source"
			cli_approve source echo-bound-src
		fi
		cli ligo-ops apply -f - <"$REPO_DIR/test/lab/echo/manifests/binding-$mode.yaml" >/dev/null || die "apply $binding"
		cli_approve binding "$binding"
		cli_phase "$binding" ACTIVE
		if [[ "$mode" == svid ]]; then
			expect 0 "^smoke $mode"$'\t'"$bound\$" echo-bound "$target" --message "smoke $mode"
		else
			expect 0 "^smoke $mode"$'\t'"bnd_[a-z0-9]+ $bound\$" echo-bound "$target" --message "smoke $mode"
		fi
		expect 2 '^no binding$' echo-unbound "$target"
		expect 3 '^denied$' echo-unbound "$target" --direct "ligo1.ligo.lab:$port" "${direct[@]}"
		revision="$(cli ligo-ops -o json get binding "$binding" | jq -r '.metadata.revision')"
		cli ligo-ops delete binding "$binding" -r "$revision" >/dev/null || die "delete $binding"
		cli_approve binding "$binding"
		cli_phase "$binding" ""
		expect 2 '^no binding$' echo-bound "$target"
		expect 3 '^denied$' echo-bound "$target" --direct "ligo1.ligo.lab:$port" "${direct[@]}"
	done
	revision="$(cli ligo-ops -o json get source echo-bound-src | jq -r '.metadata.revision')"
	cli ligo-ops delete source echo-bound-src -r "$revision" >/dev/null || die "retire the source"
	cli_approve source echo-bound-src
	info "echo smoke test passed; the source is retired, so the guide starts clean"
}

# echo_ui PHASE TARGET BINDING REGISTER: the human steps of the guide in
# headless Chrome on the lab host, as carol and dave (test/lab/echo/ui).
echo_ui() {
	(cd "$REPO_DIR" && ECHO_UI_PHASE="$1" ECHO_UI_TARGET="$2" ECHO_UI_SOURCE=echo-bound-src ECHO_UI_BINDING="$3" ECHO_UI_REGISTER_SOURCE="$4" \
		ECHO_UI_URL="https://$(lxd_ip):9443" ECHO_UI_PASSWORD_carol="$(ldap_password carol)" ECHO_UI_PASSWORD_dave="$(ldap_password dave)" \
		go test -tags uilab -count=1 -run TestUISmoke -v ./test/lab/echo/ui/ 2>&1 | sed 's/^/        /') || die "the browser steps ($1 $2) failed"
}

# echo_ui_smoke: the whole guide for both targets, the human steps in a
# browser (as carol and dave) and the client checks in between; the source
# is retired at the end if this run registered it.
echo_ui_smoke() {
	section "Echo UI smoke test"
	local mode target binding port direct register=1 ours=1 revision bound=spiffe://prod.lab/ns/echo/sa/bound
	if cli ligo-ops get source echo-bound-src >/dev/null 2>&1; then
		register=0 ours=0 # someone's source, e.g. from the guide: kept at the end
	fi
	for mode in svid local; do
		target="echo-$mode-target" binding="echo-bound-src-$target"
		cli ligo-ops get binding "$binding" >/dev/null 2>&1 && die "the binding $binding exists: revoke it first"
		port=7101 direct=(--mode svid)
		if [[ "$mode" == local ]]; then
			port=7201 direct=(--mode password --user anyone --password anything)
		fi
		expect 2 '^no binding$' echo-bound "$target"
		expect 3 '^denied$' echo-bound "$target" --direct "ligo1.ligo.lab:$port" "${direct[@]}"
		echo_ui request "$target" "$binding" "$register"
		register=0
		cli_phase "$binding" ACTIVE
		if [[ "$mode" == svid ]]; then
			expect 0 "^ui $mode"$'\t'"$bound\$" echo-bound "$target" --message "ui $mode"
		else
			expect 0 "^ui $mode"$'\t'"bnd_[a-z0-9]+ $bound\$" echo-bound "$target" --message "ui $mode"
		fi
		expect 2 '^no binding$' echo-unbound "$target"
		expect 3 '^denied$' echo-unbound "$target" --direct "ligo1.ligo.lab:$port" "${direct[@]}"
		echo_ui revoke "$target" "$binding" 0
		cli_phase "$binding" ""
		expect 2 '^no binding$' echo-bound "$target"
		expect 3 '^denied$' echo-bound "$target" --direct "ligo1.ligo.lab:$port" "${direct[@]}"
	done
	if [[ "$ours" == 1 ]]; then
		revision="$(cli ligo-ops -o json get source echo-bound-src | jq -r '.metadata.revision')"
		cli ligo-ops delete source echo-bound-src -r "$revision" >/dev/null || die "retire the source"
		cli_approve source echo-bound-src
	fi
	info "echo UI smoke test passed"
}
