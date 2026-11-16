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
	*) die "iac: install, status or test [-run REGEX]" ;;
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
	lxd exec lxd -- lxc exec ligo1 --user "$uid" --cwd "/tmp/iac-$user" --env "TMPDIR=/tmp/iac-$user" --env "HOME=/tmp/iac-$user" "${envs[@]}" -- \
		/tmp/provider.test -test.count=1 -test.v "$@" | sed 's/^/        /'
	[[ "${PIPESTATUS[0]}" == 0 ]] || die "the provider's tests failed with $tool, as $user"
}

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
