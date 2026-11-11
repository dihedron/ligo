# The ideas you need

You need only a handful of ideas to follow the rest of this leaflet. The first seven are standard terms of SPIFFE and SPIRE; the last two are `ligo`'s.

**Workload.** A running piece of software that does a job: a web service, a batch job, a database client. Not a person, and not a machine: one machine may run many workloads.

**SPIFFE ID.** A workload's name, written as a URI:

```text
spiffe://prod.example/ns/payments/sa/billing
```

The part after `spiffe://` is the **trust domain**, and the path says which workload it is. Nobody types a SPIFFE ID as a password: it is a name, and it is useless without the proof that goes with it.

**SVID.** The proof: a short-lived document that carries a SPIFFE ID and is signed by the trust domain. It comes in two forms. An **X.509-SVID** is a certificate, used to open mutually authenticated TLS connections. A **JWT-SVID** is a signed token, used where a certificate cannot be presented, for example to log in to Vault. SVIDs live for minutes or hours and are renewed automatically: a stolen one soon becomes worthless.

**Trust domain.** A boundary of identity, such as `prod.example`. One authority signs every SVID in it, and whoever runs that authority can issue any of them. Production and test, two companies, or two regulators usually get separate trust domains.

**SPIRE.** The reference implementation of SPIFFE. A **SPIRE Server** is the trust domain's authority: it signs SVIDs. A **SPIRE Agent** runs on every machine and hands SVIDs to the workloads on it.

**Attestation.** How SPIRE decides who is asking, without trusting what the asker says about itself.

- *Node attestation* proves which machine an agent runs on. The agent presents evidence, and the server checks it with the platform: AWS signs an instance identity document, Kubernetes signs a service account token, and the companion plugins do the same for LXD, OpenStack and ESXi. The machine gets an identity from facts the platform vouches for: its project, its image, its network.
- *Workload attestation* then proves which process is calling the agent: its user, its container, its Kubernetes pod. Registration entries map those facts to a SPIFFE ID.

**Federation.** Two trust domains exchanging their public keys (their **bundles**), so that each can verify the other's SVIDs. It joins identities across companies, clouds and data centres without merging them: each side keeps its own authority.

**Binding** (`ligo`). The statement "this group of workloads may use that resource, at this access level". A **source** is the group of workloads, named by a pattern over SPIFFE IDs. A **target** is the resource: a database, a schema, a topic, with named access levels such as `read` and `write`, and the network flows needed to reach it. A binding links one source to one target.

**Realm** (`ligo`). A trust domain that `ligo` works in, with a SPIRE Agent on its hosts: there `ligo` holds an identity of its own, runs its plugins and provisions access. Trust domains it only needs to verify reach it through federation.
