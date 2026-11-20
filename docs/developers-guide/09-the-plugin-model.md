# Part 2: Developing a Ligo Plugin

# The plugin model

`ligo` knows nothing of any backend. Everything that touches one, such as a directory, a database or a secret store, is done by a **plugin**: a separate program that `ligo` starts and calls over gRPC. This part shows how to write one. It uses `pkg/pluginsdk`, and the three shipped plugins, `ligo-plugin-openldap`, `ligo-plugin-postgres` and `ligo-plugin-vault`, as examples.

## Three kinds

A binding is applied in three stages (see the Architecture and Design Guide). Each stage has one kind of plugin:

| Kind | Stage | Does | Shipped |
| :------------------ | :---- | :--------------------------------------------- | :---------------------- |
| Identity provider | 1 | Makes the identity the workload will use: a directory account, or nothing. | `openldap.v1`, and builtins |
| Platform provider | 2 | Gives that identity access on the target: a role, a grant, an access-list entry. | `postgres.v1` |
| Secret store | 3 | Keeps the credential where the workload can read it. | `vault.v1` |

A plugin binary implements exactly one kind, with the control service that every plugin has. The kind decides which service it serves.

## Types and instances

A plugin has a **type**, such as `postgres.v1`: the code. An **instance** is one configured use of it: one database server, one directory. The platform team declares types in `server.yaml`, with the binary and its SHA-256, and creates instances in the database with change requests. A plugin process serves all the instances of its type in one realm; `ligo` sends it the whole set and a change to one instance is a new set.

## Trust

`ligo` does not trust a plugin more than it must, because a plugin holds powerful credentials:

- the binary is root-owned, in `plugins.directory`; `ligo` checks its SHA-256 before every start and executes it from the open file;
- the plugin runs as an unprivileged user, and `ligo` and the plugin authenticate each other with mutual TLS (go-plugin's AutoMTLS);
- every answer is checked against the plugin's schema, and every endpoint it declares against the instance's `allowed_endpoints`; a violation is a terminal, audited error (`OUTPUT_VALIDATION_FAILED`);
- an instance's secrets are never in its configuration: it names a bootstrap credential that the plugin reads from Vault with its own SVID.

A plugin author's part in this is to keep to the rules in "The stage services", and to never be clever with a secret.

## The smallest plugin

```go
func main() {
    p := &plugin{}
    pluginsdk.Serve(pluginsdk.Plugins{Control: p, Platform: p})
}
```

`Serve` runs the plugin until `ligo` stops it. `p` implements `pluginv1.PluginControlServer` (`Describe`, `ConfigureInstances`, `ValidateInstance`, `Health`) and, here, `pluginv1.PlatformProviderPluginServer`. The next chapters show each. Give the binary two more subcommands, which tools expect: `version`, and `-svids SOCKET`, which prints the SVIDs the SPIRE agent at SOCKET issues to it (`pluginsdk.PrintSVIDs`).
