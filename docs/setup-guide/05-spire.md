# SPIRE

## Topologies

`ligo` verifies each trust domain against the bundle of that domain's own source, so that a lower-assurance SPIRE server cannot inject a bundle for another.

| Topology | On the `ligo` host | `server.yaml` | Choose it when |
| :--------- | :---------------- | :---------------- | :----------------- |
| **A**, several realms | One agent per trust domain | One `realms` entry each | One `ligo` serves several domains, and you want each verified independently |
| **B**, one domain | One agent | One `realms` entry | Each environment has its own `ligo`, or all share one domain |
| **C**, federated | One agent, whose server federates with the other domain | `federated_trust_domains`, with `via_realm` | `ligo` only verifies workloads of the other domain, and runs no plugins in it |

A trust domain is either a realm or federated, never both. Topology C rests trust in the other domain's bundle on your own server's federation configuration, which is the safe direction when the higher-assurance environment decides what it trusts.

## Registration entries

Create these on the agent's server, with the `ligo` host's agent as the parent. `ligo` and its plugins run as the user `ligo`.

| SPIFFE ID path | Selectors | For |
| :------------------ | :------------------------ | :---------------- |
| `/ns/sys/sa/ligo` | `unix:uid`, `unix:sha256` of `/usr/bin/ligo` | `ligo` itself, in the core realm: serving TLS and logging in to Transit |
| `/ns/sys/sa/ligo-bundles` | The same | Each other realm: an agent releases bundles only to a caller it has an entry for |
| `/ligo/plugin/postgres` | `unix:uid`, `unix:sha256` of its binary | The plugin |
| `/ligo/plugin/vault` | `unix:uid`, `unix:sha256` of its binary | The plugin |
| `/ligo/plugin/openldap` | `unix:uid`, `unix:sha256` of its binary | The plugin |

For example:

```bash
spire-server entry create -parentID spiffe://prod.internal/node/ligo1 \
  -spiffeID spiffe://prod.internal/ligo/plugin/postgres \
  -selector unix:uid:$(id -u ligo) \
  -selector unix:sha256:$(sha256sum /usr/lib/ligo/plugins/ligo-plugin-postgres | cut -d' ' -f1)
```

The agents' `unix` workload attestor needs `discover_workload_path = true` for `unix:sha256` selectors. In Topology C, add `federatesWith` to `ligo`'s core entry.

Run as the user `ligo`, a plugin's binary prints the SPIFFE IDs its agent issues to it, and exits. Nothing secret is printed:

```bash
sudo -u ligo /usr/lib/ligo/plugins/ligo-plugin-postgres -svids /run/spire/prod/agent.sock
```

## Workloads, and jurisdictions

A jurisdiction derived from a SPIFFE path is only as trustworthy as who can assign that path. If someone able to create entries registers a workload under another tenancy's path, bindings approved for that tenancy reach it, and `ligo` cannot detect it. Let a registrar that tenants cannot influence create tenants' entries.
