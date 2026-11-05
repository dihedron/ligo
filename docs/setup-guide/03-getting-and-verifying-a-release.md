# Getting and verifying a release

Download from <https://github.com/dihedron/ligo/releases>. Each release holds, per architecture, a deb, an rpm and an archive of `ligo` and of each plugin; an SBOM for each package; these documents; the lab run's evidence, `evidence-<commit>.tar.gz`; and `checksums.txt` with its signature.

Releases are signed with the project's packaging key, `packaging/signing-key.asc` in the repository, fingerprint:

```text
FB7DE97BAAFAA2A676CEE59A1B34E6A2A14CD06A
```

Get the key from the repository, not from the release you are verifying.

## The checksums file

It covers every file of the release, and its signature covers it:

```bash
gpg --import signing-key.asc
gpg --verify checksums.txt.asc checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

## rpm packages

They carry their own signature, which `rpm` and `dnf` check once the key is imported:

```bash
sudo rpm --import signing-key.asc
rpm --checksig ligo_<version>_linux_amd64.rpm   # must report "digests signatures OK"
```

## deb packages

They carry a `debsig` origin signature. `apt` and `dpkg` do not check it on a standalone package, so use `debsig-verify`, after installing its policy for the key:

```bash
sudo apt-get install debsig-verify
sudo mkdir -p /usr/share/debsig/keyrings/1B34E6A2A14CD06A /etc/debsig/policies/1B34E6A2A14CD06A
gpg --dearmor < signing-key.asc | sudo tee /usr/share/debsig/keyrings/1B34E6A2A14CD06A/debsig.gpg > /dev/null
sudo tee /etc/debsig/policies/1B34E6A2A14CD06A/ligo.pol > /dev/null <<'POLICY'
<?xml version="1.0"?>
<!DOCTYPE Policy SYSTEM "https://www.debian.org/debsig/1.0/policy.dtd">
<Policy xmlns="https://www.debian.org/debsig/1.0/">
  <Origin Name="ligo" id="1B34E6A2A14CD06A" Description="ligo packages"/>
  <Selection><Required Type="origin" File="debsig.gpg" id="1B34E6A2A14CD06A"/></Selection>
  <Verification MinOptional="0"><Required Type="origin" File="debsig.gpg" id="1B34E6A2A14CD06A"/></Verification>
</Policy>
POLICY
debsig-verify ligo_<version>_linux_amd64.deb
```

## Install

```bash
sudo apt install ./ligo_<version>_linux_amd64.deb ./ligo-plugin-postgres_<version>_linux_amd64.deb \
  ./ligo-plugin-vault_<version>_linux_amd64.deb
```

The `ligo` package creates the system user `ligo`, the directory `/etc/ligo` (`root:ligo`, `0750`), the plugin directory `/usr/lib/ligo/plugins` (`root:root`, `0755`) and the unit `ligo.service`, which it neither enables nor starts. Examples are in `/usr/share/ligo/examples`.

If you use the archives instead, reproduce those owners and modes: `ligo` refuses a plugin unless the directory and the binary are owned by `root:root`, are not writable by anyone else, and are not symbolic links.

Compute the hash of each plugin you installed. You will need it twice, in SPIRE and in `server.yaml`:

```bash
sha256sum /usr/lib/ligo/plugins/ligo-plugin-*
```
