# SPIRE topology and sizing

## The question

How many SPIRE servers and agents does the plan need, where do they run, who runs them, and what does that team's power mean for `ligo`?

## Servers

At least one SPIRE server, or highly available cluster, per trust domain chosen in chapter 3. `ligo` puts no requirement on how a trust domain's servers are built; size and protect them by SPIRE's own guidance:

- **High availability.** Several servers of one domain sharing an external SQL datastore. Without it, an outage longer than the SVIDs' lifetime stops `ligo`, its plugins and its workloads from renewing.
- **Nested SPIRE.** Downstream servers under an upstream one, still one trust domain: for scale, or for network zones the central server must not reach. Workloads and `ligo` see one domain.
- **Federation** between domains, in the direction chapter 3 chose.

## Agents on the `ligo` hosts

Each `ligo` host runs **one agent per realm**, each with its own socket. With *R* realms and *N* replicas, that is *N* × *R* agents for `ligo`, on top of the agents that already serve the workloads.

Each agent must attest its host, by a node attestor its server supports (in the lab, `lxd_iid`). Give the `ligo` hosts a node alias per realm, so that registration entries can name them as a group rather than host by host.

## Registration entries

| Entry | Where | How many |
| :---------------------------- | :---------------------------- | :------------------------------------ |
| `ligo`'s core identity, `/ns/sys/sa/ligo` | The core realm | One |
| Bundle access, `/ns/sys/sa/ligo-bundles` | Every other realm | One per other realm |
| Each plugin, `/ligo/plugin/<binary>` | Each realm where that plugin type has instances | One per plugin type and realm; more with `hint`, when several instances of one type in one realm need distinct SVIDs |
| Workloads | Their own domain | One or more per workload; created by whoever registers workloads |

`ligo`'s and its plugins' entries select on `unix:uid` and on `unix:sha256` of the binary, so that a replaced binary gets no SVID. The cost is that **every upgrade of `ligo` or a plugin changes those entries**, in every realm. Plan who updates them, and make it part of the upgrade procedure, as the *Setup Guide* describes.

With a node alias per realm, the `ligo` entries are 1 + (*R* − 1) + *P*, where *P* counts plugin types per realm summed over the realms; without one, multiply by *N*.

## Who can do what to `ligo`

Whoever administers a SPIRE server can issue any SVID of its trust domain. For `ligo`, that power reaches further than it may seem:

| The administrator of | Can | So |
| :-------------------------------- | :---------------------------------------------- | :------------------------------------------ |
| The core realm's server | Issue `ligo`'s own identity, and its plugins' in that realm | Treat it as part of `ligo`'s trusted base |
| Any realm's server | Issue that realm's plugin identities, and reach the credentials those plugins hold | Trusted for every platform in that realm |
| A workload domain's server | Issue an SVID matching any source of that domain, and receive its bindings | Trusted for every binding of that domain |
| A domain accepted for admin SVIDs (`client_svid_auth`) | Issue an SVID that holds an admin role, such as an approver or trusted automation | Accept admin SVIDs only from the strictest domain |
| A federating server | Decide which bundle `ligo` accepts for the federated domain | Trusted for that domain |
| Any server, for another domain | Nothing: `ligo` takes each domain's bundle from one source only | |

A second point matters for multitenancy. `ligo` derives a source's jurisdiction from its SPIFFE path. If someone who can create entries registers a workload under another tenant's path, bindings approved for that tenant reach it, and `ligo` cannot tell. **Let a registrar that tenants cannot influence create tenants' entries**, and give tenants no direct access to the SPIRE server.

## Recommendation

- One highly available server cluster per trust domain, run by the identity team.
- One agent per realm on each `ligo` host, and a node alias per realm for the `ligo` hosts.
- The core realm and the admin SVID domain administered by the fewest people.
- Workload entries created by a registrar under the identity team's control, never by tenants.
- Entry updates written into the upgrade procedure of `ligo` and every plugin.

No figures for SPIRE's own capacity are given here: size it with SPIRE's documentation. `ligo`'s own load on SPIRE is small (a few SVIDs per host, renewed on their lifetime) and has not been measured separately.

## When this goes wrong

| Mistake | Consequence |
| :---------------------------------------- | :------------------------------------------------- |
| One SPIRE server, no HA | A server outage longer than SVID lifetimes stops identities everywhere, `ligo` included |
| Tenants creating their own entries | A tenant can take another tenant's bindings |
| Admin SVIDs accepted from a widely administered domain | Its administrators can approve changes |
| Entries not updated with an upgrade | The new binary gets no SVID; `ligo` or the plugin does not start |
| A missing bundle-access entry on a realm's agent | That agent releases no bundle to `ligo`: its domain's workloads are refused |
