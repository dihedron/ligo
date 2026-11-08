# Introduction

This guide is for the architect who plans a `ligo` environment, and for the security and platform leads who sign the plan off. It is read before anything is installed. It does not say how to install, which is the *Setup Guide*'s job, nor how `ligo` works inside, which *Architecture and Design* explains; it says what to install, how many of each, where, and who is responsible for what.

## How to read it

| Part | Contents | Read it |
| :---------------- | :-------------------------------------- | :------------------------ |
| I, Foundations | The terms, and what an installation is made of | First, once |
| II, Decisions | One chapter per decision: the question, the options, the criteria, a recommendation, and what goes wrong with the wrong choice | In order: each decision narrows the next |
| III, Blueprints | Five complete layouts, from one network zone to a data centre joined to a multitenant cloud | The one closest to your organisation, then its neighbours |

Appendix A is a worksheet with every question of Part II, to fill in as you read. Appendix B is the glossary.

Where this guide states a number, it says where the number was measured. Where nothing has been measured, it gives the method to size, not a figure.

Products appear only as examples of a role: HAProxy as a load balancer, Patroni for PostgreSQL high availability, Vault or OpenBao as a secret store. What matters is the role and what `ligo` needs from it; any product that provides it will do.

## Two layers: network zones and realms

The word "zone" means different things to different people. In this guide it always means a network zone: `ligo` calls its own configuration unit a realm.

- A **network zone** is the architect's starting point: a segment with its own security level and reachability, such as a data centre segment, a DMZ, or a cloud region or VPC. It decides who can reach whom.
- A **realm** is `ligo`'s configuration term (`realms` in `server.yaml`): one SPIFFE trust domain, the SPIRE agent socket on the `ligo` host that serves it, and the plugin processes attached to it. It decides which identities `ligo` and its plugins hold, and which workloads it can verify.

The two are independent. One realm can serve workloads spread over several network zones, and one network zone can hold workloads of several realms. Every blueprint in Part III starts from network zones and ends with realms.

## Other terms

| Term | Meaning |
| :--------------- | :------------------------------------------------ |
| Trust domain | A SPIFFE trust domain, such as `prod.internal`: the namespace of SPIFFE IDs one SPIRE server (or cluster of servers) signs for |
| Installation | One `ligo` database, and the replicas that share it. Installations share nothing with each other unless you make them |
| Replica | One `ligo serve` process on one host. All replicas of an installation are equal |
| Jurisdiction | Who decides: a slash-separated path such as `dc/corp-prod` or `cloud/acme/app/payments`. Every source, target and platform has one owner jurisdiction |
| Charter | The rules every jurisdiction must comply with, one per installation (`charter:` in `server.yaml`); see chapter 6 |
| Account | A registered tenant: a root jurisdiction, its people in the directory, its workloads under its own SPIFFE paths |
| Tenancy | A target on a shared, namespaced platform, belonging to one account: on PostgreSQL, one schema |
| Platform team | The people who own `server.yaml`: the platforms, their plugins and their privilege bounds |

## The decisions, in order

| Decision | Depends on | Chapter |
| :------------------------------------------ | :------------------------ | :---- |
| Which trust domains, and which are realms or federated | Network zones, existing SPIRE | 3 |
| How many SPIRE servers and agents, and who runs them | Trust domains | 4 |
| One installation or several, and what they share | Realms, regulation, teams | 5 |
| The jurisdiction tree, accounts and the interconnection policy | Organisation, installations | 6 |
| Who holds each role, and who is accountable | Jurisdictions, teams | 7 |
| Replicas, database, store and directory availability; recovery | Everything above | 8 |

## Limits that shape a plan

Read the *Setup Guide*'s "Known limits of this version" before you start. Three of them change a design:

- **PostgreSQL is the only shipped platform provider.** A plan with other targets needs plugins of its own.
- **The Vault store releases a credential to one exact SPIFFE ID.** A source covering many workloads is refused on such a platform: plan one source per workload.
- **A secret store must trust the source's trust domain.** A workload reads its credential with its own JWT-SVID, so the store must accept that domain. `ligo` does not check this when it provisions: the failure appears when the workload reads.
