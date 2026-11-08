# From network zones to trust domains

## The question

Your organisation already has network zones. Which SPIFFE trust domains should they map to, and which of those does `ligo` hold as realms, with an agent on its hosts, and which does it only verify, through federation?

## What a trust domain is for

A trust domain is a boundary of **identity**: one SPIRE server, or cluster of servers, signs every SVID in it, and whoever administers that server can issue any of them. A network zone is a boundary of **reachability**. The two answer different questions, and mapping them one to one is a choice, not a rule.

Create a separate trust domain when the **people** differ: when a different team must administer the identities, or when one environment must not be able to issue identities valid in another (production and test, two regulators, two companies). Do not create one only because workloads sit behind a different firewall; firewalls already separate reachability, and `ligo` tells each workload which flows it needs (`GET /v1/flows`), so they can be checked.

## How `ligo` uses each trust domain

`ligo` holds each trust domain it deals with in one of two ways:

| Held as | On each `ligo` host | `ligo` can | Choose it when |
| :------------- | :------------------------ | :---------------------------------- | :-------------------------------- |
| A realm | An agent of that domain | Run plugins with identities in it; verify its workloads | Platforms or stores of that domain are provisioned by `ligo` |
| Federated | Nothing more: the bundle arrives through a realm's agent | Verify its workloads only | `ligo` provisions nothing there, and only its workloads call `ligo` |

A trust domain is never both. Which way to hold it gives the three topologies of the *Setup Guide*:

| Topology | Realms | Federated | In short |
| :--------- | :------------- | :---------- | :--------------------------------------- |
| A | Several, one agent each | Possibly | One installation provisions in several domains, each verified on its own |
| B | One | No | One domain only, or one installation per domain |
| C | One or more | One or more | Some domains are only verified, through a realm's federation |

![Topologies A and C: a realm per provisioned domain, federation for a verified one.](realm-topologies.pdf){width=85%}

## One authoritative bundle per domain

`ligo` accepts a trust domain's bundle from exactly one source: that realm's own agent, or the realm named as `via_realm` for a federated domain. A bundle for that domain arriving from any other agent is discarded and counted (`ligo_bundle_conflicts_total`). So the administrator of one SPIRE server cannot make `ligo` trust a forged bundle for another domain.

The consequence for a plan is that **federation runs in a direction**. In Topology C, trust in the federated domain rests on the federating server's configuration, administered by its team. Federate from the higher-assurance side: let production decide whether it trusts test, never the reverse.

## What crosses between domains

Three things cross a trust domain boundary, and each needs its own answer.

1. **Workloads calling `ligo`.** `ligo` verifies them against their own domain's bundle, held as a realm or federated. The workload, in turn, verifies `ligo`'s certificate. If that certificate is an SVID of another domain, the workload needs that domain's bundle (federation in the other direction), or the workload listener uses a certificate from a shared corporate CA (`tls_source: file`).
2. **Workloads reading credentials.** A workload reads its credential from the secret store with its own JWT-SVID. The store must accept that domain: the workload's domain is the store's realm's domain, or the store's JWT authentication is configured for it. `ligo` does not check this when it provisions; a binding becomes `ACTIVE` and the failure appears when the workload reads. Check every pair of source domain and store in the plan.
3. **Plugins reaching platforms.** A plugin authenticates to its platform and store with an SVID of its realm. A platform in another domain either trusts that realm's SVIDs, or gets a realm of its own.

## What each network zone must reach

Draw this table for every network zone in the plan. Ports are the defaults.

| From | To | Port | Why |
| :------------------------ | :------------------------ | :---------- | :---------------------------- |
| Workloads | `ligo`, through the load balancer | 8443 | Discover bindings and flows |
| Workloads | Secret store | 8200 | Read credentials |
| Workloads | Targets | Theirs | Use them |
| People, automation | `ligo`, through the load balancer | 9443 | Admin API and web UI |
| `ligo` hosts | PostgreSQL, Vault or OpenBao, LDAP | 5432, 8200, 636 | `ligo` itself |
| `ligo` hosts | Platforms and stores of every realm | Theirs | Plugins provisioning |
| SPIRE agents on `ligo` hosts | Their SPIRE servers | 8081 | SVIDs and bundles |
| Federating SPIRE server | Federated server's bundle endpoint | As configured | Federation |

The `ligo` hosts reach into every network zone that holds a platform. Where a network zone must not be reached from a central host, that is an argument for a separate installation inside it (chapter 5).

## Recommendation

- **Start with one realm per trust domain in which `ligo` provisions**, and federate the domains it only verifies.
- **Keep trust domains to the boundaries of administration.** One per network zone only where the zones also have different SPIRE administrators or must not issue each other's identities.
- **Pick the core realm carefully.** `ligo`'s own identity (`core_identity`), used for its serving certificate and for Vault Transit, comes from one realm. Make it the domain with the strictest SPIRE administration.
- **Avoid sharing one realm between production and test plugins** (the *Setup Guide*'s option B2): their instances then share processes, and a compromise or a bug exposes both.

## When this goes wrong

| Mistake | Consequence |
| :---------------------------------------- | :------------------------------------------------- |
| A trust domain per network zone, with one SPIRE team | More servers, agents and entries, and no separation gained: the same people can issue every identity |
| One trust domain for production and test | Test administrators can issue production identities |
| Federation from the lower-assurance side | The lower-assurance team decides what production trusts |
| A store that does not trust a source's domain | Bindings become `ACTIVE`, and workloads cannot read their credentials |
| A platform in a network zone `ligo` hosts cannot reach | Its bindings fail after retries |
