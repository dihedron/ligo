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

**From v0.4.x to v0.5.0.** There is no migration to run (the database schema is unchanged), and `server.yaml` needs no change: `plugins.dynamic_credentials` is optional, and without it a dynamic credential keeps its one hour and 24 hours. Upgrade `ligo-plugin-vault` too (see "Upgrading a plugin"): a binding's `auth` now carries the JWT audience, and the namespace when the store instance has one, and they come from the plugin. A binding the old plugin applied has neither until its next reconciliation, six hours at most with the default `reconciliation.interval`, once the new plugin runs. The Go client SDK needs them, so a workload that uses it sees an error for such a binding until then; workloads that read their credentials by other means are not affected.

**From v0.5.x to v0.6.0.** There is no migration to run (the database schema is unchanged), no change to `server.yaml`, and the plugins need no upgrade. The `ligo` CLI is now built on the Go admin client (`pkg/adminclient`), and three things change for people who run it: a read (GET) is repeated up to twice after a broken connection or a 429, 502, 503 or 504; the standard `HTTPS_PROXY` and `NO_PROXY` variables are honoured, so a CLI behind a corporate proxy reaches the server through it; and when a server or a proxy answers with something that is not an RFC 9457 problem, the CLI reports the status only, not the text of the page. The admin API's OpenAPI document (`api/openapi/admin.v1alpha1.yaml`) now types every answer, which changes no behaviour of the server.

## Upgrading a plugin

A package update changes the binary's hash, and two things pin it: the type's `sha256` in `server.yaml`, and the `unix:sha256` selector in SPIRE. Until both match, `ligo` refuses to start the new binary and the agent issues it no SVID. A running plugin keeps working, but it cannot start again if it stops, so do these steps together. A reload is not enough: `SIGHUP` only reloads certificates.

1. Upgrade the package on one replica, and note the new hash with `sha256sum`.
2. Add a SPIRE entry with the new hash, keeping the old one, and check with `-svids`.
3. Set the new hash in `server.yaml`, and restart `ligo` on that replica.
4. Repeat steps 1 and 3 on the other replicas.
5. Delete the SPIRE entry with the old hash.

A plugin's binary carries only its version, so you can compare the hash with your own build of the same tag.

## Retiring an instance

Revoke its bindings and retire its targets first, and rewire or retire the platforms that use it: `ligo delete platform|identity-provider|secret-store NAME -r REVISION` is refused while any of them remains (`instance-in-use`). A second person of its jurisdiction approves the retirement; its name is never reused.

## Removing a plugin type

Retire its instances, then remove the type from `server.yaml` and restart each replica.

## Removing `ligo`

Revoke every binding, so that the accounts, roles and credentials are removed from the systems they live on. Then stop the service, remove the packages, and drop the database. The package keeps `/etc/ligo`, the user and the database.
