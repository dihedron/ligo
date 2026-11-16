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
iac_test() {
	local provider="${LIGO_PROVIDER_DIR:-$REPO_DIR/../terraform-provider-ligo}" run="" uid host tool
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
	uid="$(env_get .ligo1.ligo_uid)"
	host=ligo1
	local managed="iac-m-$E2E_SUFFIX" free="iac-f-$E2E_SUFFIX"
	iac_fixtures "$managed" "$free"
	inner_exec ligo1 sh -c "rm -rf /tmp/iac && install -d -o ligo-ops -m 0700 /tmp/iac"
	uid="$(inner_exec ligo1 id -u ligo-ops </dev/null)" # the provider reads as the operators do: by its SVID
	for tool in terraform tofu; do
		info "with $tool"
		local envs=(--env "LIGO_LAB_SOCKET=unix:///run/spire/prod/agent.sock" --env "LIGO_LAB_SERVER_ID=spiffe://prod.lab/ns/sys/sa/ligo" --env "LIGO_LAB_MANAGED_SOURCE=$managed" --env "LIGO_LAB_FREE_SOURCE=$free" --env "LIGO_LAB_TARGET=iac-t-${managed##*-}"
			--env "LIGO_LAB_OWNER=spiffe://prod.lab/ci/terraform" --env "TF_ACC=1" --env "TF_ACC_TERRAFORM_PATH=$IAC_BIN/$tool" --env "LIGO_E2E_ADMIN=https://$host.ligo.lab:9443"
			--env "LIGO_E2E_DIR=$LIGO1_E2E" --env "LIGO_E2E_SUFFIX=$E2E_SUFFIX")
		[[ "$tool" == tofu ]] && envs+=(--env "TF_ACC_PROVIDER_NAMESPACE=hashicorp" --env "TF_ACC_PROVIDER_HOST=registry.opentofu.org")
		lxd exec lxd -- lxc exec ligo1 --user "$uid" --cwd /tmp/iac --env TMPDIR=/tmp/iac --env HOME=/tmp/iac "${envs[@]}" -- \
			/tmp/provider.test -test.count=1 -test.v ${run:+-test.run "$run"} | sed 's/^/        /'
		[[ "${PIPESTATUS[0]}" == 0 ]] || die "the provider's tests failed with $tool"
	done
}
