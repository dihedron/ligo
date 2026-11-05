# A first binding

This walks through the whole path: a source, a target, a binding, and a workload using it. Here `olga` holds `operator` and `dora` `approver` on `dc/corp-prod/*`. `dc/corp-prod` needs an approver, so each change waits for `dora`.

## Register a source

```yaml
# source.yaml
kind: Source
metadata: { name: payments-worker }
identity:
  trustDomain: prod.internal
  svidRegex: '^spiffe://prod\.internal/ns/payments/sa/worker$'
  sampleSpiffeIds: ["spiffe://prod.internal/ns/payments/sa/worker"]
visibility: { mode: PRIVATE }
```

```bash
ligo source test --trust-domain prod.internal --regex '^spiffe://prod\.internal/ns/payments/sa/worker$' \
  --id spiffe://prod.internal/ns/payments/sa/worker
ligo apply -f source.yaml
```

`ligo apply` answers with a change request. As `dora`, review and approve it:

```bash
ligo cr review
```

The regex is checked strictly: anchored, with no `.`, no alternation at the top, nothing that lets a segment match `/`. A source can only ever narrow.

## Publish a target

```yaml
# target.yaml
kind: Target
metadata: { name: ledger, platform: pg-ledger, scope: dc/corp-prod/ledger }
definition: { database: ledger, schema: ledger }
accessLevels:
  - { name: read, grants: { roles: [LEDGER_RO_ROLE] } }
networkFlows:
  - { name: ledger, purpose: DATA, protocol: TCP, destination: db.prod.internal, ports: [5432], tls: true, serverName: db.prod.internal }
visibility: { mode: PRIVATE }
```

`ligo apply -f target.yaml`. A target needs its owner's and its platform's consent, two sides when the scopes differ.

## Bind them

```yaml
# binding.yaml
kind: Binding
name: payments-ledger
source: payments-worker
target: ledger
accessLevel: read
```

```bash
ligo governance check -f binding.yaml   # the scopes, the rule and the sides it will need
ligo apply -f binding.yaml --wait
ligo get binding payments-ledger
```

Once every side approves, the binding becomes `PROVISIONING`, then `ACTIVE`.

## Use it, as the workload

The workload authenticates with its X.509-SVID, or a JWT-SVID:

```bash
curl --cert svid.pem --key key.pem --cacert bundle.pem https://ligo.prod.internal:8443/v1/bindings
```

Each item gives the connection coordinates in `spec`, and how to get the credential in `auth`: the store's `address`, `authMount`, `role`, and `secretPath` or `credsPath`. The workload logs in to Vault with a JWT-SVID for the store's audience and its own role, reads the path, and connects:

```bash
vault write auth/jwt-spiffe/login role=binding-<id> jwt=<JWT-SVID>
vault read kv/data/bindings/<id>
```

`GET /v1/flows` lists the network flows the workload needs, for a tool on its host to verify them.

## Check the result

- `ligo get binding payments-ledger` shows `ACTIVE`, and its stages `ENSURED`.
- In the target database, the role exists, with the comment `ligo:binding_id=<uuid>` and only the level's memberships.
- `ligo audit verify` reports a valid chain.
- `ligo delete binding payments-ledger -r 1` files a revocation, for that revision. Once it applies, the role is gone, its sessions have ended and the credential no longer connects.
