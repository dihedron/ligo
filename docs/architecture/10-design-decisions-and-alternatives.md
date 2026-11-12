# Design decisions and alternatives

| Decision | Why | Rejected |
| :------------------------- | :------------------------------------- | :------------------------ |
| Three orthogonal plugin stages | Identity, target and store vary independently | Monolithic plugins: N × M × K of them |
| Plugins as processes, per type and realm | A crash or a compromise is contained; each gets its realm's identity | In-process plugins |
| Durable workflows on DBOS, in `ligo`'s own database | One dependency; a step's result commits with the data | An external workflow engine |
| Sealing with Transit | No secret in clear in checkpoints, and a retry does not need it back | Encrypting with a local key; keeping secrets out of the workflow, which then cannot resume |
| Regex validation on the syntax tree | Text checks miss what the parser sees | Globs, which `*` makes cross `/` |
| Maker-checker per side, in the database | A bug or the application's role cannot approve | Checks in code only |
| Consent from both owners | One owner alone allows hijacking and injection | The proposer holding rights on both ends, which needs a global administrator |
| Unilateral revocation | No one may veto cutting off a compromised client | Symmetric consent |
| Default-deny interconnection policy | Two owners agreeing is not always enough | Consent alone |
| Maintenance as one database setting | Enabling it per process lets replicas accept changes during a drain | A startup flag |
| Targets are registered, not created | A database's owner keeps its schema and group roles | `ligo` provisioning the target itself |
| Fixed error messages from plugins | A backend's text can echo statements or data | Persisting the error |
| Instances in the database, plugin types in `server.yaml` | Instances change as often as the systems they describe; four-eyes requests per jurisdiction replace file ownership, and the types' `instance_bounds` keep a root-owned limit | Instances in `server.yaml`, a restart per change; a global role applying changes at once |
| Instance rows signed by the audit key | Catches edits outside `ligo` even after audit pruning | Comparing with the audit entry, which pruning removes |

## Why the Vault store takes exact SPIFFE IDs only

`ligo` decides which workloads see a binding, but Vault's JWT role releases the credential. Vault matches a subject exactly, or by glob, and its `*` also matches `/`. If the store's constraint were broader than the regex, workloads `ligo` rejects could still obtain the credential, which defeats segment confinement at the point that matters.

So a store declares in `Describe` what it can enforce, and `ligo` refuses, when a binding is filed, a source the store could only over-approximate. The cost is that a source covering many workloads cannot use this store. Translating a regex to a glob only when exact is possible future work, as is an explicit list of SPIFFE IDs.

## Why PostgreSQL has no `SVID` mode yet

PostgreSQL's `cert` authentication maps a certificate's CN or DN, never the URI SAN that holds a SPIFFE ID. Setting the CN through a SPIRE entry's DNS name would work on today's servers, but PostgreSQL would then trust a name outside `ligo`'s control: anyone able to register an entry with that name becomes that role, and the source's regex would not be enforced at the database. The operator would also have to keep each trust domain's CA current through rotations.

**The design to build:** a JWT-SVID through PostgreSQL 18's OAuth support. A validator module loaded by the server verifies the token against the trust domain's bundle, and enforces the binding's regex at the database. The open questions are the module's packaging per server version, and client support in drivers.

## Why a role's password is sent as a verifier

PostgreSQL accepts a pre-computed SCRAM verifier in `ALTER ROLE ... PASSWORD`. A statement log then holds a value that does not let anyone log in. The cost is implementing the computation in the plugin, which a test checks against RFC 7677's vector.

## Future work

- More platform providers, such as Oracle, whose open question is its mapping of identities too.
- A conformance suite every plugin must pass (INV-07).
- `activedirectory.v1`, and an `s3-e2ee.v1` store.
- Native dual-password rollover where a target has it, to close the rotation window.
