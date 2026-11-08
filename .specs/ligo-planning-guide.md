# ligo: Planning for Deployment Guide

Status: approved, 2026-11-08 (decisions in §8).

## 1. Purpose

A fourth release document, beside the three of `.specs/ligo-docs.md`. It is for **architects planning a `ligo` environment**, before anything is installed. It gives them what they need to decide:

- how network zones map to trust domains, realms and federation;
- how many SPIRE servers and agents, and where;
- one `ligo` installation or several, and what they share;
- how to lay out governance scopes, accounts and the interconnection policy;
- who holds which role, and who is responsible for what;
- how many replicas, and what PostgreSQL, Vault or OpenBao and LDAP must provide, for availability and recovery.

| Document | For | Answers |
| :------- | :------ | :---------------------- |
| **Planning for Deployment Guide**, subtitle *Architectural Blueprints* | Architects; security and platform leads who sign off a design | Which layout fits my organisation, and why? What must I decide, and what does each choice cost? |

The Setup Guide says how to install; this document says what to install, how many, where and for whom. It points to the Setup Guide for procedures and to Architecture and Design for mechanisms, and does not repeat them.

## 2. Toolchain and publication

As `.specs/ligo-docs.md`, with no new tool:

- `docs/planning-guide/`, one file per chapter, and `metadata.yaml`; output `ligo-planning-for-deployment-guide-<version>.pdf`.
- `docs/build.sh` gains `planning-guide` in `DOCUMENTS` and `FILE_NAMES`. `make docs`, `docs.yml` and goreleaser need no change: they take every `build/docs/*.pdf`.
- Diagrams in `docs/common/diagrams/`, Mermaid, one per file; a network layout too wide for portrait goes in `::: landscape`.
- `.specs/ligo-docs.md` lists the fourth document.

## 3. Terms (fixed for the whole document)

Two layers, never confused:

- **Network zone**: the architect's starting point. A segment with its own security level and reachability: a data centre segment, a DMZ, a cloud region or VPC.
- **Realm**: the configuration term (`realms` in `server.yaml`, called zone before spec 4.0.3). One trust domain, one SPIRE agent socket on the `ligo` host, one set of plugin processes. One realm may serve several network zones; one network zone may hold workloads of several realms.
- **Trust domain**, **governance scope**, **account**, **tenancy**: as in Architecture and Design and the Setup Guide.

Each blueprint starts from network zones and ends with realms, trust domains and scopes.

## 4. Content

The outline fixes the scope, not the wording. Every decision chapter has the same shape: the question; the options; the criteria, in a table; a recommendation with its conditions; what goes wrong if the choice is wrong.

**Part I, Foundations**

1. **Introduction**: who it is for, how to read it, the terms of §3, and a one-page decision map that points to the chapters.
2. **What an installation is made of**: `ligo` replicas, PostgreSQL, SPIRE agents, Vault or OpenBao (Transit and stores), LDAP, the load balancer, plugin processes, webhooks and the SIEM. For each one: what `ligo` needs from it, who usually owns it, and what fails without it.

**Part II, Decisions**

3. **From network zones to trust domains**: one trust domain per network zone or not; topologies A, B and C of the Setup Guide; the rule of one authoritative bundle per domain; the secret store's trust constraint (tenancy spec §9.4); what a workload in each network zone must reach.
4. **SPIRE topology and sizing**: SPIRE servers per trust domain, server HA, nested SPIRE, federation direction; the agents on each `ligo` host; registration entries and `unix:sha256`; who runs SPIRE, and what a SPIRE administrator can and cannot do to `ligo`.
5. **One `ligo` or several**: the criteria: blast radius, regulatory separation, production and test, administration teams, failure domains, network reachability, shared or separate PostgreSQL and Vault, the cost of each extra installation. What the interconnection policy already separates inside one installation, and what only separate installations separate.
6. **Governance layout**: the scope tree, extractors per trust domain, `approval_required` per level, the interconnection policy, `governance.accounts` and the account grammar, trusted automation.
7. **Roles and responsibilities**: the role catalogue (platform team, target and source owners, approvers, platform approvers, account administrators, account operators and approvers, additional parties, break-glass holders, auditors, SPIRE and Vault administrators); a RACI per activity; separation of duties `ligo` enforces and what the organisation must enforce; directory groups.
8. **Capacity, availability and recovery**: replicas and the load balancer; multi-site (see §5); what each dependency's outage does (from the Operator's Guide, not repeated: summarised and linked); PostgreSQL sizing and connection pools; Vault, LDAP and SPIRE availability; failure domains across sites; backup, restore and disaster recovery. Numbers only where measured (lab or soak), each with where it was measured; otherwise the method to size, not a figure.

**Part III, Blueprints**

Each blueprint has the same sections: context and assumptions; network zones (diagram); trust domains, realms and SPIRE (diagram); installations and what they share; governance layout (with a `server.yaml` excerpt, validated by a test, see §5); roles and RACI; capacity and availability; failure analysis; variations; a checklist.

9. **Single network zone, one organisation**: the smallest production layout. One trust domain, one installation, HA replicas, flat scopes.
10. **Traditional data centre**: several network zones (for example production, test, DMZ), classic teams and approval chains, no account registry, an interconnection policy that keeps test from production, Information Security as an additional party.
11. **Cloud network zone, multitenant**: hundreds of accounts in one cloud trust domain, one OU per account, platform team and account administrators, tenancies on shared platforms, the platform approver.
12. **Several network zones, multitenant**: the cloud of blueprint 11 spread over several network zones (for example regions or security levels), each with its own trust domain or not; federation or several realms; one installation or one per network zone, and how the choice changes the roles.
13. **Traditional data centre interconnected with a multitenant cloud over several network zones**: blueprint 10 next to blueprint 12, workloads crossing between them in both directions; which side's trust decides, the interconnection policy across the two, who approves a binding from a cloud account to a data-centre target and back, and whether the two keep separate installations.

**Appendices**

- A. **Decision worksheet**: the questions of Part II, in order, with space for the answer and the chapter to read.
- B. **Glossary**.

## 5. Accuracy

- Every claim about `ligo`'s behaviour is checked against the code or the specs at writing time; a claim the lab has not shown is marked as such.
- Each blueprint's `server.yaml` excerpt is a file under `docs/planning-guide/examples/`, included with `include.lua`, and `docs/docs_test.go` loads it with the real configuration loader, so it cannot drift from the code.
- **Products.** Each dependency is described by the role it plays and what `ligo` needs from it; products are named only as examples (load balancer: HAProxy; PostgreSQL HA: Patroni; secret store: Vault, OpenBao). A later release adds worked examples per product, several per role (for example Vault, OpenBao, CyberArk; HAProxy, F5 BIG-IP).
- **Multi-site.** Chapter 8 gives the guidance `ligo` itself supports: what must hold after a PostgreSQL failover (the audit chain, the workflow journal, replica IDs), the Transit key both sites need for sealed inter-stage secrets, SPIRE and Vault per site. Where `ligo` gives no element of its own, the chapter says so and refers to the PostgreSQL documentation. Nothing here is lab-tested yet, and the text says so.
- No sizing figure without its source. The overnight soak (planned) is expected to give the first figures for chapter 8; until then the chapter gives the method.

## 6. Out of scope

Installation steps (Setup Guide), procedures (Operator's Guide), mechanisms and the threat model (Architecture and Design), non-SPIRE identity systems, a cost model in money.

## 7. Chunks

Each chunk builds the PDF and is reviewed by the user before its commit.

1. This spec; the build wiring (`build.sh`, `metadata.yaml`, `.specs/ligo-docs.md`); chapters 1 and 2.
2. Chapters 3 and 4.
3. Chapters 5 and 6.
4. Chapters 7 and 8.
5. Blueprints 9 and 10, with their examples and the loader test.
6. Blueprints 11 and 12.
7. Blueprint 13, appendices A and B; a full read-through.

## 8. Decisions and open questions

Decided by the user on 2026-11-08: the title and subtitle; products described by role and named as examples; multi-site as in §5; blueprint 13 added.

Title simplified by the user on 2026-11-08: "Planning for Deployment Guide" ("Ligo planning for deployment guide"; ligo goes in the author line and the file name, as in the other three).

Decided on 2026-11-08: the configuration term "zone" becomes "realm" in code, configuration, schema and proto for v0.2.0, on its own branch, before this document is written. This document then uses "network zone" for the architect's segments and "realm" for the configuration term; §3 and every chapter follow.
