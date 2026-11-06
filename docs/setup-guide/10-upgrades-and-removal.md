# Upgrades and removal

## Upgrading `ligo`

This release makes no compatibility promise. Read the release notes first. Avoid depending on workflows surviving across versions by draining first:

1. `ligo maintenance on -m "upgrade to <version>"`
2. `ligo maintenance status --wait-drained`, which waits until nothing is in flight.
3. `ligo migrate`, with the new binary, as `ligo_migrator`.
4. Install the new package and restart, one replica at a time.
5. If the entries select on `unix:sha256` of `ligo`, update them first.
6. `ligo maintenance off`

The workload API and all reads keep serving during maintenance.

## Upgrading a plugin

A package update changes the binary's hash, and two things pin it: `plugins[].sha256` in `server.yaml`, and the `unix:sha256` selector in SPIRE. Until both match, `ligo` refuses to start the new binary and the agent issues it no SVID. A running plugin keeps working, but it cannot start again if it stops, so do these steps together. A reload is not enough: `SIGHUP` only reloads certificates.

1. Upgrade the package on one replica, and note the new hash with `sha256sum`.
2. Add a SPIRE entry with the new hash, keeping the old one, and check with `-svids`.
3. Set the new hash in `server.yaml`, and restart `ligo` on that replica.
4. Repeat steps 1 and 3 on the other replicas.
5. Delete the SPIRE entry with the old hash.

A plugin's binary carries only its version, so you can compare the hash with your own build of the same tag.

## Removing a plugin or instance

Revoke its bindings first. `ligo` refuses to start while a binding refers to a removed instance, unless you give `--allow-orphaned-bindings`, which is audited.

## Removing `ligo`

Revoke every binding, so that the accounts, roles and credentials are removed from the systems they live on. Then stop the service, remove the packages, and drop the database. The package keeps `/etc/ligo`, the user and the database.
