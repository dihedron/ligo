# The echo target: testing a binding by hand

**Status**: lab only, not hardened, never shipped. It extends the lab of `.specs/ligo-test-environment.md`.

## Purpose

A toy echo service on `ligo1` that a workload can reach only through a binding, so that a person can watch, step by step, a binding grant access and its revocation take it away: first without a binding, then with a binding requested by one user and approved by another, then after its revocation. The service runs in two modes, chosen by the platform it belongs to, which exercise the two ways a target admits a workload: by its X.509-SVID (`SVID`) or by a password that ligo provisions and keeps in OpenBao (`TARGET_LOCAL`, `vault-static`). The scenario can be run with the CLI and with the web UI (*Guide* below).

## Protocol

One line each way over TLS. The client sends a line of text; the server answers the same text, a tab and the client's identity, which tells the client apart, or `denied` and closes. In the password mode the client first sends `auth <user> <password>`.

## Components

- **`echo-server`** (`test/lab/echo/server`), one binary with `--mode svid` or `--mode password`, a data port and a control port. Its server certificate is its own X.509-SVID `spiffe://prod.lab/ns/lab/sa/echo-server`, from the prod agent.
  - `svid`: the data port requires a client X.509-SVID of `prod.lab` (mTLS) and admits it if its SPIFFE ID fully matches one regex of the access list; the identity is that SPIFFE ID.
  - `password`: the data port requires no client certificate; `auth` must name a user of the user list with its password; the identity is the user, followed by the client's SPIFFE ID if it presented an SVID.
  - The control API (HTTPS, mTLS) admits only `spiffe://prod.lab/ligo/plugin/target-echo`: `PUT` and `DELETE /acl/{bindingId}` (body `{"regex"}`), `GET` (204 or 404), `PUT` and `DELETE /users/{name}` (body `{"password"}`, kept as a SHA-256 hash). The lists are kept in `/var/lib/echo-<mode>/state.json`, so they survive restarts.
- **`target-echo`** (`test/lab/plugins/target-echo`, type `echo.v1`, SPIFFE ID `spiffe://prod.lab/ligo/plugin/target-echo`): the platform provider of the two echo platforms. It accepts the identity modes `SVID` and `TARGET_LOCAL`; its instance configuration names the server's data and control addresses, the server's SPIFFE ID and the mode, which must agree with the platform's identity mode. Its targets have an empty definition; every access level grants the one privilege `echo`. `ValidateBinding` takes no parameters and returns the requested spec `{"host", "port", "serverId", "mode"}`; the client spec workloads receive is `{"endpoint", "serverId", "mode"}`, with `"user"` in the password mode, its `endpoint` within the platform's `allowed_endpoints`. `EnsureTarget` adds the binding's `source_svid_regex` to the access list (`SVID`), or creates the user named after the binding's derived principal with a generated password, returned as `StaticSecret` (`TARGET_LOCAL`); `CleanupTarget` removes it. Both are idempotent and keyed by the binding's ID; a user's password stays until the binding's secrets are rotated. The plugin calls the control API with its own X.509-SVID and accepts only the server's SPIFFE ID.
- **`store-vault`, for workloads**: with `vault-static` it also creates the JWT role `binding-<id>` on its auth mount, bound to the source's SPIFFE ID and to the audience of its `workload_jwt_audience` setting (default `https://bao-prod.ligo.lab`), with the policy `binding-<id>`, so that a workload logs in with its JWT-SVID and reads its own secret, and nothing else; cleanup deletes it. The plugin's own policy (`ligo-plugin-store-vault`) may write roles named `binding-*` only, and give them only policies named `binding-*` (`allowed_parameters`), so the stand-in cannot mint a login with any other policy. **Lab only**: OpenBao matches a JWT subject exactly or by glob, not by regex, so the stand-in supports only sources whose regex is one literal SPIFFE ID (`^spiffe://…$`, dots escaped, no other metacharacters) and refuses the others with `INCOMPATIBLE_IDENTITY_MODE`.
- **`echo-client`** (`test/lab/echo/client`): fetches its X.509-SVID, and its JWT-SVID for bao-prod, from the prod agent; asks ligo's workload API (`https://ligo1.ligo.lab:8443`, verifying ligo's core SVID) for its bindings to `--target`; with none, it prints `no binding` and exits 2. With one, it connects to the spec's address, verifying the server's SPIFFE ID; when the binding's `auth` names no secret store it presents its SVID (`svid`), otherwise it logs in to bao-prod with the role `binding-<id>`, reads the password and sends `auth`. It sends `--message` (default `hello`), prints the server's answer and exits 0 when the server echoes the message, 3 for `denied`. `--direct host:port --mode svid|password` connects without asking ligo (with `--user` and `--password` for the password mode), to show that the server refuses on its own.

## Lab wiring

`lab.sh echo install|status|logs|client` sets the echo target up after `lab.sh serve install`:
- two server instances on `ligo1` as the user `echo`: `echo-svid.service` (data `:7101`, control `:7102`) and `echo-local.service` (data `:7201`, control `:7202`), and the SPIRE entries of the server (`unix:uid` of `echo`) and of `target-echo` (as the other plugins);
- in ligo's configuration (`serve_config`) the platforms `echo-svid` (`svid.v1`, secret store `none.v1`) and `echo-local` (`target-local.v1`, secret store `vault-prod`, `vault-static`), both of `echo.v1`, owned by `dc/corp-prod`;
- two attested users on `ligo1`, `echo-bound` and `echo-unbound`, whose SPIRE entries (children of the node alias, `unix:uid`) give them `spiffe://prod.lab/ns/echo/sa/bound` and `spiffe://prod.lab/ns/echo/sa/unbound`;
- the targets `echo-svid-target` and `echo-local-target` (scope `dc/corp-prod/echo`, one access level `echo`), published and approved by `install` through the CLI as `ligo-ops` and `ligo-approver`;
- the manifests the guide applies, in `test/lab/echo/manifests/`: the source `echo-bound-src` (`^spiffe://prod\.lab/ns/echo/sa/bound$`) and one binding of it to each target;
- `lab.sh echo client <user> <target> [args]` runs `echo-client` on `ligo1` as that user; `lab.sh cli <user> <ligo args…>` runs the `ligo` CLI on `ligo1` as that user (`ligo-ops`, `ligo-approver`), with stdin passed through for manifests.

For the web UI, `lab.sh serve install` also:
- publishes ligo's admin listener on the lab VM's address, `https://10.252.0.20:9443`, through a proxy device on the lab VM (as `pg`'s), and sets `external_origin` to that address. The listener's certificate is ligo's X.509-SVID, which names no host, so the browser warns once;
- grants, in ligo's configuration, the LDAP group `ledger-dbas` (`carol`) the role `operator` and the group `ligo-approvers-prod` (`dave`) the role `approver`, both on `dc/corp-prod/*`. The other LDAP grants are unchanged (`olivia` stays a viewer). The LDAP passwords are in `test/lab/.state/passwords/ldap-<user>`.

The web UI is phase 9's (`feature/ui`): this branch is based on it, and its PR is merged after phase 9's.

## Guide

Run each part for both targets: `echo-svid-target` (the server admits the client by its SVID) and `echo-local-target` (by a password ligo provisions). The commands run from the repository's root on the lab host, with the lab running and `lab.sh serve install` and `lab.sh echo install` done. The binding is named `echo-bound-svid` (or `echo-bound-local`).

### 1. Without a binding

```bash
test/lab/lab.sh echo client echo-bound echo-svid-target            # expect: no binding, exit 2
test/lab/lab.sh echo client echo-unbound echo-svid-target          # expect: no binding, exit 2
test/lab/lab.sh echo client echo-bound echo-svid-target --direct ligo1.ligo.lab:7101 --mode svid
                                                                   # expect: denied, exit 3
```
For `echo-local-target`, the direct test is `--direct ligo1.ligo.lab:7201 --mode password --user anyone --password anything`.

### 2a. Request and approve the binding with the CLI

```bash
test/lab/lab.sh cli ligo-ops apply -f - < test/lab/echo/manifests/source.yaml        # the source, once
test/lab/lab.sh cli ligo-ops apply -f - < test/lab/echo/manifests/binding-svid.yaml  # prints the approver's command
test/lab/lab.sh cli ligo-approver cr list --awaiting-me                              # the source's and the binding's requests
test/lab/lab.sh cli ligo-approver cr approve <id> --sha256 <payloadSha256> --side <side> -m "echo test"
                                                                                     # the source's first, then the binding's
test/lab/lab.sh cli ligo-ops get binding echo-bound-svid                             # until status.phase is ACTIVE
```
`ligo-ops` (olga) and `ligo-approver` (dora) are two different principals: the approval is four-eyes.

### 2b. Request and approve the binding with the web UI

1. Open `https://10.252.0.20:9443/ui/login` and accept the certificate warning.
2. Sign in as `carol` (password in `test/lab/.state/passwords/ldap-carol`).
3. **Sources → Register a source**: name `echo-bound-src`, trust domain `prod.lab`, SVID regex `^spiffe://prod\.lab/ns/echo/sa/bound$`, sample `spiffe://prod.lab/ns/echo/sa/bound`. The tester shows the scope `dc/corp-prod` and the match. Submit: the page shows the pending change request.
4. **Catalog → `echo-svid-target` → Request access**: level `echo`, source `echo-bound-src`, Review (name `echo-bound-svid`; the governance outcome lists the sides), Submit. The page shows the binding's change request, `PENDING`.
5. Sign out, sign in as `dave` (password in `test/lab/.state/passwords/ldap-dave`).
6. **Bindings**: "Awaiting my decision" lists both requests. Open the source's, **Approve**; then the binding's, **Approve** (approving the binding first answers that it depends on the source).
7. Open **Bindings → `echo-bound-svid`**: the status row follows the provisioning until `ACTIVE`.

### 3. With the binding

```bash
test/lab/lab.sh echo client echo-bound echo-svid-target --message "hello from the bound workload"
    # expect: hello from the bound workload<TAB>spiffe://prod.lab/ns/echo/sa/bound, exit 0
    # (echo-local-target: <TAB>bnd_…  spiffe://prod.lab/ns/echo/sa/bound: the binding's user, then the SPIFFE ID)
test/lab/lab.sh echo client echo-unbound echo-svid-target          # expect: no binding, exit 2
test/lab/lab.sh echo client echo-unbound echo-svid-target --direct ligo1.ligo.lab:7101 --mode svid
                                                                   # expect: denied, exit 3
test/lab/lab.sh echo logs                                          # the server logged "echoed" and "denied"
```

### 4. Revoke the binding

- CLI: `test/lab/lab.sh cli ligo-ops delete binding echo-bound-svid -r <revision>` (the revision from `get binding`), then approve its request as `ligo-approver` as in 2a; `get binding` until it is gone.
- Web UI: as `carol`, **Bindings → `echo-bound-svid` → Revoke** and confirm; as `dave`, approve the request.

Then, as in 1: `echo-bound` gets `no binding` (exit 2), and `denied` with `--direct` (exit 3).

## Implementation plan (`feature/echo`)

1. This spec.
2. `test/lab/echo/server`, with unit tests: both modes, the access list and the users, the control API's peer check, the state file.
3. `test/lab/plugins/target-echo`, with unit tests against an in-process server.
4. `store-vault`: the per-binding JWT role and the literal-ID check.
5. `test/lab/echo/client`, with unit tests against a fake workload API and an in-process server.
6. `lib/echo.sh`, `lab.sh echo` and `lab.sh cli`, the `serve_config` platforms, the UI proxy and the LDAP grants, the manifests. Done when `lab.sh echo install` passes and one scripted run of the guide's CLI part passes on the lab.
7. The guide checked against the lab: every command run, every expected output seen.
