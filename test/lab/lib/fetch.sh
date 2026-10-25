# shellcheck shell=bash
# Downloads, cached on the lab host and verified as an operator would: SPIRE
# against the release's SHA-256 files, lxd-spiffe against its checksums
# file and that file's signature.

# fetch URL SHA256: downloads URL into the cache unless already there with
# that checksum, and prints the cached path. Fails on a mismatch.
fetch() {
	local url="$1" sha="$2" path
	path="$LAB_CACHE_DIR/downloads/${url##*/}"
	mkdir -p "${path%/*}"
	if [[ -f "$path" ]] && echo "$sha  $path" | sha256sum -c --quiet >/dev/null 2>&1; then
		echo "$path"
		return
	fi
	info "downloading ${url##*/}" >&2
	curl -fsSL --proto '=https' -o "$path.part" "$url" || die "cannot download $url"
	echo "$sha  $path.part" | sha256sum -c --quiet >/dev/null 2>&1 || {
		rm -f "$path.part"
		die "checksum mismatch for $url (expected $sha)"
	}
	mv "$path.part" "$path"
	echo "$path"
}

# spire_release NAME: the cached, verified tarball NAME (spire or
# spire-extras) of LAB_SPIRE_VERSION.
spire_release() {
	local base="https://github.com/spiffe/spire/releases/download/v$LAB_SPIRE_VERSION"
	local file="$1-$LAB_SPIRE_VERSION-linux-amd64-musl.tar.gz" sha
	sha="$(curl -fsSL --proto '=https' "$base/$1-$LAB_SPIRE_VERSION-linux-amd64-musl_sha256sum.txt" | awk -v f="$file" '$2 == f {print $1}')"
	[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "no published SHA-256 for $file"
	fetch "$base/$file" "$sha"
}

# lxd_spiffe_package NAME: the cached .deb of an lxd-spiffe plugin, verified
# against the release's checksums file, itself verified against its
# signature with the pinned packaging key.
lxd_spiffe_package() {
	local version="$LAB_LXD_SPIFFE_VERSION"
	local base="https://github.com/dihedron/lxd-spiffe/releases/download/v$version"
	local dir="$LAB_CACHE_DIR/lxd-spiffe-$version" sums file="$1_${version}_linux_amd64.deb" sha
	sums="$dir/lxd-spiffe_${version}_checksums.txt"
	if [[ ! -f "$dir/verified" ]]; then
		mkdir -p "$dir"
		curl -fsSL --proto '=https' -o "$sums" "$base/${sums##*/}" &&
			curl -fsSL --proto '=https' -o "$sums.asc" "$base/${sums##*/}.asc" &&
			curl -fsSL --proto '=https' -o "$dir/signing-key.asc" \
				"https://raw.githubusercontent.com/dihedron/lxd-spiffe/v$version/packaging/signing-key.asc" ||
			die "cannot download lxd-spiffe $version's checksums and signature"
		local fpr
		fpr="$(gpg --show-keys --with-colons "$dir/signing-key.asc" 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}')"
		[[ "$fpr" == "$LAB_LXD_SPIFFE_KEY_FINGERPRINT" ]] ||
			die "lxd-spiffe's packaging key is $fpr, not the pinned $LAB_LXD_SPIFFE_KEY_FINGERPRINT"
		gpg --dearmor <"$dir/signing-key.asc" >"$dir/key.gpg"
		gpgv --keyring "$dir/key.gpg" "$sums.asc" "$sums" >/dev/null 2>&1 ||
			die "the signature of lxd-spiffe $version's checksums does not verify"
		touch "$dir/verified"
	fi
	sha="$(awk -v f="$file" '$2 == f {print $1}' "$sums")"
	[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "$file is not in lxd-spiffe $version's checksums"
	fetch "$base/$file" "$sha"
}
