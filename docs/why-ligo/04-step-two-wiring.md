# Step two: wiring the data centre together

`ligo` (Latin for "I bind") takes the identities of step one and turns them into access: it records who may use what, gets the consent of the people responsible for each side, creates the access on the target system, and takes it away again.

## A binding, from request to connection

Suppose the billing team needs to write to the orders database, which the database team owns.

![Step two: both owners approve, ligo provisions the access, and the workload proves its identity to use it.](why-wiring.pdf){width=90%}

1. **Someone asks.** The billing team opens a change request for a binding: source *billing*, target *orders*, access level `write`.
2. **Everyone concerned approves.** The owners of both sides must approve, and each owner's rules apply: some changes need two people (four eyes), some are allowed only within a jurisdiction. A charter, one per installation, sets the rules every owner must follow. Nobody can bind their own workloads to someone else's database, or someone else's workloads to a system they control, without the other side's consent.
3. **`ligo` provisions.** Its plugins create a role on the database with only the privileges of the `write` level, and put its credential in Vault or OpenBao, where it can be released only to billing's exact SPIFFE ID. Each step is checkpointed, so a crash or an outage resumes where it stopped, and a failure never takes working access away.
4. **The workload asks and connects.** The billing workload, holding its SVID, asks `ligo` what it may use. It gets the binding, where its credential is, and the network flows it needs. It logs in to Vault with its own SVID, reads the credential and connects.

From then on `ligo` looks after the binding: it repairs drift if someone changes the role by hand, rotates the credential on a schedule, removes the access when the binding expires, and revokes it at once when any owner asks.

## Plugins: one model, many technologies

`ligo` itself knows no database. Three kinds of plugins do the work: an **identity provider** creates the principal, a **platform provider** grants the privileges on the target, and a **secret store** delivers the credential. PostgreSQL, OpenLDAP and Vault or OpenBao ship today; Oracle, Kafka or a cloud database are each a new plugin, under the same approvals, audit and lifecycle.

## Across realms and trust domains

Large organisations rarely have one trust domain. The data centre, the private cloud and each public cloud often have their own, run by different teams. `ligo` works across them:

- in a **realm**, `ligo` runs a SPIRE Agent of that trust domain and its plugins hold identities there, so it can provision targets in it;
- a trust domain that only has workloads calling `ligo` is reached through **federation**, so `ligo` can verify its SVIDs without any agent there.

![Across realms: federated trust domains in the data centre and the clouds, and one ligo that knows every binding.](why-realms.pdf){width=100%}

A workload in GCP can therefore be bound to a database in the data centre, with the consent of both owners, and the binding is recorded in the same place as one between two containers on the same LXD server.
