# shellcheck shell=bash
# Terraform and OpenTofu on ligo1, and the acceptance tests of the provider
# (terraform-provider-ligo, a separate repository): the CLIs are not installed
# on the lab host, and the tests that need a real ligo run next to it.

IAC_BIN=/usr/local/bin

# iac_zip NAME URL SUMS FILE: the cached zip of FILE, verified against the
# release's SHA-256 file, which comes from the same host over HTTPS.
# shortcut: no signature check of the checksums (HashiCorp and OpenTofu sign
# them); pin their keys as lxd-spiffe's is if the lab ever ships the binaries.
iac_zip() {
	local base="$1" sums="$2" file="$3" sha
	sha="$(curl -fsSL --proto '=https' "$base/$sums" | awk -v f="$file" '$2 == f {print $1}')"
	[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "no published SHA-256 for $file"
	fetch "$base/$file" "$sha"
}

cmd_iac() {
	require_lab
	inner_exists ligo1 || die "ligo1 does not exist: lab.sh up --scenario identity"
	case "${1:-status}" in
	install) iac_install ;;
	status) inner_exec ligo1 sh -c "$IAC_BIN/terraform version | head -1; $IAC_BIN/tofu version | head -1" ;;
	test)
		shift
		iac_test "$@"
		;;
	campaign)
		shift
		iac_campaign "$@"
		;;
	*) die "iac: install, status, test [-run REGEX] or campaign [SCENARIO...]" ;;
	esac
}

# iac_install: Terraform and OpenTofu, pinned in lab.env, into ligo1.
iac_install() {
	section "Terraform $LAB_TERRAFORM_VERSION and OpenTofu $LAB_TOFU_VERSION on ligo1"
	local tf tofu tmp
	tf="$(iac_zip "https://releases.hashicorp.com/terraform/$LAB_TERRAFORM_VERSION" "terraform_${LAB_TERRAFORM_VERSION}_SHA256SUMS" \
		"terraform_${LAB_TERRAFORM_VERSION}_linux_amd64.zip")"
	tofu="$(iac_zip "https://github.com/opentofu/opentofu/releases/download/v$LAB_TOFU_VERSION" "tofu_${LAB_TOFU_VERSION}_SHA256SUMS" \
		"tofu_${LAB_TOFU_VERSION}_linux_amd64.zip")"
	tmp="$(mktemp -d)"
	unzip -qo "$tf" terraform -d "$tmp"
	unzip -qo "$tofu" tofu -d "$tmp"
	inner_push "$tmp/terraform" ligo1 "$IAC_BIN/terraform" 0755
	inner_push "$tmp/tofu" ligo1 "$IAC_BIN/tofu" 0755
	rm -rf "$tmp"
	info "terraform $LAB_TERRAFORM_VERSION and tofu $LAB_TOFU_VERSION installed in ligo1:$IAC_BIN"
}

# iac_fixtures MANAGED FREE: a source that the pipeline owns and one that
# nobody owns, for the provider's reads.
iac_fixtures() {
	local managed="$1" free="$2" name doc ns
	cli ligo-ops apply -f - <<YAML >/dev/null || die "apply the target iac-t-${managed##*-}"
kind: Target
metadata: {name: iac-t-${managed##*-}, platform: pg-ledger, jurisdiction: dc/corp-prod/ledger}
definition: {database: ledger, schema: ledger}
accessLevels: [{name: read, grants: {roles: [LEDGER_RO_ROLE]}}]
networkFlows: [{name: ledger, purpose: DATA, protocol: TCP, destination: pg.ligo.lab, ports: [5432], tls: true, serverName: pg.ligo.lab}]
visibility: {mode: PRIVATE}
YAML
	cli_approve target "iac-t-${managed##*-}"
	for name in "$managed" "$free"; do
		ns=adopt
		[[ "$name" == "$managed" ]] && ns=climg
		doc="$(jq -nc --arg n "$name" --arg re "^spiffe://prod\\.lab/ns/$ns/sa/w${name##*-}\$" '{kind: "Source", metadata: {name: $n}, identity: {trustDomain: "prod.lab", svidRegex: $re}, visibility: {mode: "PRIVATE"}}')"
		if [[ "$name" == "$managed" ]]; then
			cli ligo-ci apply --managed --approval-ref CHG-IAC -f - <<<"$doc" >/dev/null || die "apply $name"
		else
			cli ligo-ops apply -f - <<<"$doc" >/dev/null || die "apply $name"
			cli_approve source "$name"
		fi
	done
}

# iac_test [-run REGEX]: builds the provider's tests (tag lab) on the host,
# copies them to ligo1 and runs them as the operator ligo-ops, once per tool, with the
# environment of the e2e of ligo serve and the SVIDs that serve_admins mints.
IAC_ENV=()

iac_test() {
	local provider="${LIGO_PROVIDER_DIR:-$REPO_DIR/../terraform-provider-ligo}" run="" host tool
	[[ "${1:-}" == -run ]] && run="$2"
	[[ -d "$provider/internal/provider" ]] || die "the provider is not at $provider: set LIGO_PROVIDER_DIR"
	inner_exec ligo1 test -x "$IAC_BIN/terraform" || die "terraform is not installed on ligo1: lab.sh iac install"
	inner_exec ligo1 systemctl -q is-active ligo || die "ligo does not run on ligo1: lab.sh serve install"
	section "Provider tests on ligo1"
	local out="$LAB_STATE_DIR/iac"
	mkdir -p "$out"
	(cd "$provider" && go test -c -tags lab -o "$out/provider.test" ./internal/provider) || die "cannot build the provider's tests"
	inner_push "$out/provider.test" ligo1 /tmp/provider.test 0755
	E2E_SUFFIX="$(openssl rand -hex 4)"
	serve_admins
	local managed="iac-m-$E2E_SUFFIX" free="iac-f-$E2E_SUFFIX"
	iac_fixtures "$managed" "$free"
	local user tool pend="iac-w-$E2E_SUFFIX"
	for user in ligo-ops ligo-ci; do
		inner_exec ligo1 sh -c "rm -rf /tmp/iac-$user && install -d -o $user -m 0700 /tmp/iac-$user"
	done
	for tool in terraform tofu; do
		info "with $tool"
		# the reads and the hermetic tests, as the operators: by the SVID of ligo-ops
		iac_exec ligo-ops "$tool" -test.skip 'TestLabPipeline|TestLabTarget|TestLabBinding|TestLabInstances|TestLabPending' ${run:+-test.run "$run"}
		# the pipeline: trusted automation, its writes apply at once
		if [[ -z "$run" || "TestLabPipeline TestLabTarget TestLabBinding" =~ $run ]]; then
			iac_exec ligo-ci "$tool" -test.run '^(TestLabPipeline|TestLabTarget|TestLabBinding)$'
		fi
		# instances are always decided by a person: the apply waits for the platform approver
		if [[ -z "$run" || "TestLabInstances" =~ $run ]]; then
			iac_instances "$tool" "$E2E_SUFFIX-$tool"
		fi
		# an operator's write waits for a person, and a second apply waits for the same request
		if [[ -z "$run" || "TestLabPending" =~ $run ]]; then
			iac_pending "$tool" "$pend-$tool"
		fi
	done
}

# iac_exec USER TOOL TESTARGS...: the provider's tests, as USER, with TOOL.
iac_exec() {
	local user="$1" tool="$2" uid
	shift 2
	uid="$(inner_exec ligo1 id -u "$user" </dev/null)"
	local envs=(--env "LIGO_LAB_SOCKET=unix:///run/spire/prod/agent.sock" --env "LIGO_LAB_SERVER_ID=spiffe://prod.lab/ns/sys/sa/ligo"
		--env "LIGO_LAB_MANAGED_SOURCE=$managed" --env "LIGO_LAB_FREE_SOURCE=$free" --env "LIGO_LAB_TARGET=iac-t-${managed##*-}"
		--env "LIGO_LAB_OWNER=spiffe://prod.lab/ci/terraform" --env "TF_ACC=1" --env "TF_ACC_TERRAFORM_PATH=$IAC_BIN/$tool"
		--env "LIGO_E2E_ADMIN=https://ligo1.ligo.lab:9443" --env "LIGO_E2E_DIR=$LIGO1_E2E" --env "LIGO_E2E_SUFFIX=$E2E_SUFFIX" "${IAC_ENV[@]}")
	[[ "$tool" == tofu ]] && envs+=(--env "TF_ACC_PROVIDER_NAMESPACE=hashicorp" --env "TF_ACC_PROVIDER_HOST=registry.opentofu.org")
	envs+=(--env "LIGO_LAB_LB_URL=https://lb.ligo.lab:9443" --env "LIGO_LAB_CAMPAIGN=${IAC_CAMPAIGN:-}")
	set +e # a failing scenario is reported, not fatal, when IAC_TOLERATE is set
	lxd exec lxd -- lxc exec ligo1 --user "$uid" --cwd "/tmp/iac-$user" --env "TMPDIR=/tmp/iac-$user" --env "HOME=/tmp/iac-$user" "${envs[@]}" -- \
		/tmp/provider.test -test.count=1 -test.v "$@" | sed 's/^/        /' | tee -a "${IAC_OUT:-/dev/null}"
	IAC_RC="${PIPESTATUS[0]}"
	set -e
	[[ "$IAC_RC" == 0 || -n "$IAC_TOLERATE" ]] || die "the provider's tests failed with $tool, as $user"
}
IAC_TOLERATE="" IAC_RC=0

# iac_instances TOOL SUFFIX: an operator files an identity provider, a secret
# store and a platform that wires them, which wait for a person; the platform approver approves them (and their
# removal) in the background. Each is two requests, filed once.
iac_instances() {
	local tool="$1" sfx="$2" approver kind name n
	(for _ in $(seq 1 60); do
		sleep 3
		(approve_all ligo-platform-approver identity-provider && approve_all ligo-platform-approver secret-store && approve_all ligo-platform-approver platform) >/dev/null 2>&1 || true
	done) &
	approver=$!
	IAC_ENV=(--env "LIGO_LAB_INSTANCE_SUFFIX=$sfx" --env "LIGO_LAB_CA_B64=$(base64 -w0 <"$LAB_STATE_DIR/pki/ca.crt")")
	iac_exec ligo-ops "$tool" -test.run '^TestLabInstances$'
	kill "$approver" 2>/dev/null || true
	wait "$approver" 2>/dev/null || true
	IAC_ENV=()
	for kind in identity-provider:iac-idp secret-store:iac-ss platform:iac-pf; do
		name="${kind#*:}-$sfx"
		n="$(cli ligo-platform-approver -o json cr list --kind "${kind%%:*}" --name "$name" | jq '.items | length')"
		[[ "$n" == 2 ]] || die "$name: $n change requests, want 2 (the creation, waited for once, and the removal)"
	done
	info "$tool: the instances waited for a person; two requests each"
}

# iac_pending TOOL NAME: an operator's source waits for approval. The first
# apply ends at its timeout with the request open; the second waits for that
# same request while ligo-approver approves it (no second filing), and its
# removal is approved the same way. The requests are counted at the end.
iac_pending() {
	local tool="$1" name="$2" n approver
	IAC_ENV=(--env "LIGO_LAB_PENDING_SOURCE=$name" --env "LIGO_LAB_PHASE=file")
	iac_exec ligo-ops "$tool" -test.run '^TestLabPending$'
	n="$(cli ligo-approver -o json cr list --kind source --name "$name" | jq '.items | length')"
	[[ "$n" == 1 ]] || die "$name: $n change requests after the first apply, want 1"
	(for _ in $(seq 1 45); do
		sleep 3
		(cli_approve source "$name") >/dev/null 2>&1 || true
	done) &
	approver=$!
	IAC_ENV=(--env "LIGO_LAB_PENDING_SOURCE=$name" --env "LIGO_LAB_PHASE=adopt")
	iac_exec ligo-ops "$tool" -test.run '^TestLabPending$'
	kill "$approver" 2>/dev/null || true
	wait "$approver" 2>/dev/null || true
	IAC_ENV=()
	n="$(cli ligo-approver -o json cr list --kind source --name "$name" | jq '.items | length')"
	[[ "$n" == 2 ]] || die "$name: $n change requests, want 2 (the creation, waited for once, and the removal)"
	info "$tool: a pending request is waited for, not filed again; the requests of $name are 2"
}

# ---------------------------------------------------------------------------
# The pre-release campaign (terraform-provider-ligo
# .specs/ligo-prerelease-campaign.md, phase 2): scenarios with people and
# incidents. The provider's tests run on ligo1 and ask for them through files
# (req-N in their directory); camp_responder performs each with the CLI, as the
# right person, and answers in ack-N ("ok", or why not).

# camp_pending KIND NAME: the id of the pending request of the resource, waiting
# up to 5 minutes for it to exist.
camp_pending() {
	local id
	for _ in $(seq 1 150); do
		id="$(cli ligo-ops -o json cr list --status PENDING --kind "$1" --name "$2" 2>/dev/null | jq -r '.items[0].id // empty')" || id=""
		[[ -n "$id" ]] && {
			echo "$id"
			return 0
		}
		sleep 2
	done
	return 1
}

# camp_count KIND NAME: how many change requests the resource has had.
camp_count() { cli ligo-ops -o json cr list --kind "$1" --name "$2" --page-size 200 | jq '.items | length'; }

# camp_person_pw USER: the LDAP password of a person, on ligo1, for --password-file.
camp_person_pw() {
	local pw="$LIGO1_E2E/$1.pw"
	ldap_password "$1" | inner_exec ligo1 sh -c "umask 077 && cat >$pw && chown ligo:ligo $pw"
	echo "$pw"
}

# camp_source_doc NAME DESC [REV]: a source of the campaign, as JSON.
camp_source_doc() {
	jq -nc --arg n "$1" --arg d "$2" --arg re "^spiffe://prod\\.lab/ns/cmp/sa/$1\$" --arg r "${3:-}" \
		'{kind: "Source", metadata: {name: $n}, description: $d, identity: {trustDomain: "prod.lab", svidRegex: $re}, visibility: {mode: "PRIVATE"}} + (if $r == "" then {} else {expectedRevision: ($r | tonumber)} end)'
}

# camp_act ACTION ARGS...: one request; prints why it failed, and returns 1.
camp_act() {
	local action="$1" id rev pw out holds n
	shift
	case "$action" in
	approve)
		camp_pending "$1" "$2" >/dev/null || { echo "nothing is pending for $1 $2"; return 1; }
		cli_approve "$1" "$2" >/dev/null 2>&1 || { echo "cannot approve $1 $2"; return 1; }
		;;
	approve-after-restart)
		for _ in $(seq 1 150); do [[ -e "$CAMP_DIR/restarted" ]] && break; sleep 2; done
		[[ -e "$CAMP_DIR/restarted" ]] || { echo "ligo was not restarted"; return 1; }
		camp_act approve "$@"
		;;
	decline)
		id="$(camp_pending "$1" "$2")" || { echo "nothing is pending for $1 $2"; return 1; }
		cli ligo-approver cr decline "$id" -m "campaign: declined" >/dev/null 2>&1 || { echo "cannot decline $id"; return 1; }
		;;
	withdraw)
		id="$(camp_pending "$1" "$2")" || { echo "nothing is pending for $1 $2"; return 1; }
		cli ligo-ops cr withdraw "$id" >/dev/null 2>&1 || { echo "cannot withdraw $id"; return 1; }
		;;
	pending)
		camp_pending "$1" "$2" >/dev/null || { echo "nothing is pending for $1 $2"; return 1; }
		;;
	nopending)
		id="$(cli ligo-ops -o json cr list --status PENDING --kind "$1" --name "$2" | jq -r '.items[0].id // empty')"
		[[ -z "$id" ]] || { echo "request $id of $1 $2 is pending: the provider filed over a hold"; return 1; }
		;;
	count)
		n="$(camp_count "$1" "$2")"
		[[ "$n" == "$3" ]] || { echo "$1 $2 has $n change requests, want $3"; return 1; }
		;;
	contain)
		rev="$(cli ligo-ops -o json binding show "$1" | jq -r '.metadata.revision')"
		cli ligo-ops binding delete "$1" -r "$rev" >/dev/null 2>&1 || { echo "cannot contain $1"; return 1; }
		cli_approve binding "$1" >/dev/null 2>&1 || { echo "cannot approve the containment of $1"; return 1; }
		cli_phase "$1" "" >/dev/null 2>&1 || { echo "$1 is not gone"; return 1; }
		holds="$(cli ligo-ops -o json hold list --binding "$1" | jq '.items | length')"
		[[ "$holds" == 1 ]] || { echo "$1 has $holds holds, want 1"; return 1; }
		;;
	lift)
		id="$(cli ligo-ops -o json hold list --binding "$1" | jq -r '.items[0].id // empty')"
		[[ -n "$id" ]] || { echo "no hold for $1"; return 1; }
		pw="$(camp_person_pw dave)"
		cli ligo hold lift "$id" -m "campaign: reviewed" --username dave --password-file "$pw" >/dev/null 2>&1 || { echo "cannot lift $id"; return 1; }
		;;
	edit-refused)
		rev="$(cli ligo-ops -o json source show "$2" | jq -r '.metadata.revision')"
		if out="$(camp_source_doc "$2" "edited by a person" "$rev" | cli ligo-ops apply -f - 2>&1)"; then
			echo "a person's edit of the managed source $2 was accepted: $out"
			return 1
		fi
		grep -qi "managed" <<<"$out" || { echo "the edit of $2 was refused, but not as managed: $out"; return 1; }
		;;
	edit)
		rev="$(cli ligo-ops -o json source show "$2" | jq -r '.metadata.revision')"
		camp_source_doc "$2" "$3" "$rev" | cli ligo-ops apply -f - >/dev/null 2>&1 || { echo "cannot edit $2"; return 1; }
		cli_approve source "$2" >/dev/null 2>&1 || { echo "cannot approve the edit of $2"; return 1; }
		;;
	drain)
		# the removal that ends a scenario waits too: approve this scenario's requests until it is over
		(while [[ ! -e "$CAMP_DIR/stop" ]]; do
			for id in $(cli ligo-approver -o json cr list --awaiting-me --kind source --page-size 200 2>/dev/null | jq -r --arg s "-$E2E_SUFFIX" '.items[]? | select(.resourceName | endswith($s)) | .resourceName'); do
				cli_approve source "$id" >/dev/null 2>&1 || true
			done
			sleep 3
		done) >/dev/null 2>&1 &
		;;
	restart-ligo)
		camp_pending source "cmp-rs-$E2E_SUFFIX" >/dev/null || { echo "nothing is pending to restart ligo under"; return 1; }
		inner_exec "$1" systemctl restart ligo || { echo "cannot restart ligo on $1"; return 1; }
		serve_wait "$1" >/dev/null 2>&1 || { echo "ligo on $1 does not come back"; return 1; }
		touch "$CAMP_DIR/restarted"
		;;
	restart-agent)
		# the SPIRE agent of ligo1 restarts while the provider waits on a request: its SVID source reconnects
		camp_pending source "cmp-ag-$E2E_SUFFIX" >/dev/null || { echo "nothing is pending to restart the agent under"; return 1; }
		inner_exec ligo1 systemctl restart spire-agent-prod || { echo "cannot restart the prod agent"; return 1; }
		for _ in $(seq 1 60); do
			cli ligo-ops -o json source list >/dev/null 2>&1 && break
			sleep 2
		done
		touch "$CAMP_DIR/restarted"
		;;
	kill-ligo)
		for _ in $(seq 1 120); do
			n="$(cli ligo-ops -o json cr list --kind source --page-size 200 2>/dev/null | jq "[.items[]? | select(.resourceName | test(\"^cmp-rp[0-9]+-$E2E_SUFFIX\$\"))] | length")" || n=0
			[[ "${n:-0}" -ge 10 ]] && break
			sleep 0.2
		done
		inner_exec "$1" pkill -9 -x ligo || { echo "cannot kill ligo on $1"; return 1; }
		;;
	start-ligo)
		inner_exec "$1" systemctl start ligo >/dev/null 2>&1 || true
		serve_wait "$1" >/dev/null 2>&1 || { echo "ligo on $1 does not run"; return 1; }
		;;
	*) echo "unknown action $action"; return 1 ;;
	esac
}

# camp_responder USER: performs the provider tests' requests (as files in
# /tmp/iac-USER on ligo1) until $CAMP_DIR/stop exists.
camp_responder() {
	local user="$1" dir="/tmp/iac-$1" line f id
	while [[ ! -e "$CAMP_DIR/stop" ]]; do
		while IFS= read -r line; do
			[[ -n "$line" ]] || continue
			f="${line%%|*}" id="${f#req-}"
			(
				# shellcheck disable=SC2086 # the request is words
				out="$(camp_act ${line#*|} </dev/null 2>&1)" && out=ok
				printf '%s\n' "$out" | inner_exec ligo1 sh -c "cat >$dir/ack-$id.tmp && mv $dir/ack-$id.tmp $dir/ack-$id"
			) &
		done < <(inner_exec ligo1 sh -c "cd $dir 2>/dev/null && for f in req-*; do [ -e \"\$f\" ] || continue; [ -e \"ack-\${f#req-}\" ] && continue; [ -e \"seen-\${f#req-}\" ] && continue; touch \"seen-\${f#req-}\"; printf '%s|%s\n' \"\$f\" \"\$(cat \"\$f\")\"; done")
		sleep 1
	done
}

# camp_run USER TOOL REGEX: the provider's scenario REGEX as USER with TOOL,
# with the responder running; returns the tests' status in IAC_RC.
camp_run() {
	local user="$1" tool="$2" regex="$3" responder
	CAMP_DIR="$(mktemp -d)"
	inner_exec ligo1 sh -c "rm -rf /tmp/iac-$user && install -d -o $user -m 0700 /tmp/iac-$user"
	camp_responder "$user" &
	responder=$!
	IAC_CAMPAIGN=1 IAC_OUT="$CAMP_DIR/out" IAC_TOLERATE=1 iac_exec "$user" "$tool" -test.run "$regex"
	if grep -q "no tests to run" "$CAMP_DIR/out"; then IAC_RC=1; fi # a scenario that does not exist is not a pass
	touch "$CAMP_DIR/stop"
	wait "$responder" 2>/dev/null || true
	sleep 4 # the drain loops see the stop file
	rm -rf "$CAMP_DIR"
}

# iac_campaign [SCENARIO...]: the scenarios, once per tool, against the lab as
# it is (lab.sh serve install first). A failed scenario is reported, and the
# next one runs; the status is the number of failures.
iac_campaign() {
	local provider="${LIGO_PROVIDER_DIR:-$REPO_DIR/../terraform-provider-ligo}" tool s user failed=0 only=" $* "
	[[ -d "$provider/internal/provider" ]] || die "the provider is not at $provider: set LIGO_PROVIDER_DIR"
	inner_exec ligo1 test -x "$IAC_BIN/terraform" || die "terraform is not installed on ligo1: lab.sh iac install"
	inner_exec ligo1 systemctl -q is-active ligo || die "ligo does not run on ligo1: lab.sh serve install"
	section "Provider campaign on ligo1"
	local out="$LAB_STATE_DIR/iac"
	mkdir -p "$out"
	(cd "$provider" && go test -c -tags lab -o "$out/provider.test" ./internal/provider) || die "cannot build the provider's tests"
	inner_push "$out/provider.test" ligo1 /tmp/provider.test 0755
	E2E_SUFFIX="$(openssl rand -hex 4)"
	serve_admins
	local managed="iac-m-$E2E_SUFFIX" free="iac-f-$E2E_SUFFIX"
	iac_fixtures "$managed" "$free"
	local scenarios=(Approval:ligo-ops Hold:ligo-ci Lock:ligo-ci Restart:ligo-ops AgentRestart:ligo-ops Crash:ligo-ops Replica:ligo-ci Burst:ligo-ci)
	for tool in terraform tofu; do
		for s in "${scenarios[@]}"; do
			user="${s#*:}" s="${s%%:*}"
			[[ "$only" == "  " || "$only" == *" $s "* ]] || continue
			info "$tool: $s as $user"
			E2E_SUFFIX="$(openssl rand -hex 4)"
			IAC_ENV=()
			if [[ "$s" == Crash ]]; then
				IAC_ENV=(--env "LIGO_LAB_PHASE=file")
				camp_run "$user" "$tool" '^TestLabCampaignCrash$'
				# the killed process is the expected result of the first phase
				[[ "$IAC_RC" != 0 ]] || { info "FAIL $tool $s: the provider was not killed"; failed=$((failed + 1)); continue; }
				IAC_ENV=(--env "LIGO_LAB_PHASE=adopt")
				camp_run "$user" "$tool" '^TestLabCampaignCrash$'
			else
				camp_run "$user" "$tool" "^TestLabCampaign$s\$"
			fi
			IAC_ENV=()
			if [[ "$IAC_RC" == 0 ]]; then info "PASS $tool $s"; else info "FAIL $tool $s (rc $IAC_RC)"; failed=$((failed + 1)); fi
			# a killed replica must run again whatever happened
			inner_exec ligo1 systemctl start ligo >/dev/null 2>&1 || true
			inner_exec ligo2 systemctl start ligo >/dev/null 2>&1 || true
		done
	done
	info "campaign: $failed scenario(s) failed"
	return "$failed"
}
