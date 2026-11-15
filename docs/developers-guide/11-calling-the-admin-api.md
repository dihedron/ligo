# Part 3: Automating ligo

# Calling the admin API from Go

Part 1 is for the workloads that `ligo` gives access to a target and Part 2 for the plugins that do the work. This part is for the tools that **drive `ligo` itself**: a program that lists targets, files a source or a platform, or waits for a change to be approved. The `ligo` CLI is one, and so are the Terraform and OpenTofu provider and the MCP server of the same project. They all call the **admin API**, on port 9443, and they all use one Go package, `pkg/adminclient`, so that authentication, the verification of the server, errors and the rules of change requests are written once.

```go
import "github.com/dihedron/ligo/pkg/adminclient"
```

The package is part of `ligo`'s module, like the SDK of Part 1. Until `ligo` is 1.0.0 its API may change between minor versions; the release notes say how.

## Words used here

- The admin API is `api/openapi/admin.v1alpha1.yaml`. The package's types and calls are generated from it, so the document is the contract.
- Every change of `ligo` is a **change request**. A tool does not change a source, a target, a binding or an instance: it **files** the change, and people approve it (four eyes). The client says so in what it returns.
- A **revision** is the number of a version of a resource. An update names the revision it is based on, so a concurrent change is refused and never overwritten.

## Creating a client

`New` checks the configuration and prepares the client. It does not call `ligo`.

```go
source, err := workloadapi.NewX509Source(ctx) // SPIFFE_ENDPOINT_SOCKET
if err != nil {
    return err
}
defer source.Close()

c, err := adminclient.New(adminclient.Config{
    ServerURL:  "https://ligo.example.com:9443",
    ServerID:   "spiffe://example.com/ns/sys/sa/ligo",
    X509Source: source, // the client SVID, and the bundle that verifies ligo
})
if err != nil {
    return err
}
defer c.Close()
```

The package has no flag and no environment variable of its own: they belong to the program that uses it.

| Field | Meaning |
| :--------------- | :--------------------------------------------------------------------- |
| `ServerURL` | The admin API, an `https` URL. Anything else is refused. A path is kept as a prefix. |
| `RootCAs` | The CAs that verify `ligo`'s certificate. |
| `ServerID`, `Bundles` | Or: `ligo`'s SPIFFE ID and the bundles to verify it against (`X509Source` when `Bundles` is not set). One of the two ways is required. |
| `X509Source` | The caller authenticates with its SVID, over mTLS. |
| `Basic` | Or with LDAP credentials: `BasicAuth{Username, Password}`, if the server allows them (`allow_basic_auth`). Exactly one of the two. |
| `Logger` | A `*slog.Logger`; default `slog.Default()`. It gets the method, path and status of each call, never a body or a header. |
| `UserAgent` | Default `ligo-adminclient`. |
| `HTTPClient` | Its timeout and, if its transport is an `*http.Transport`, its proxy and limits. Its TLS settings and its redirect policy are replaced, never merged. |
| `MaxRetries` | How often a GET is repeated: 0 is twice, -1 is never. |

The password is a `Secret`, a string that prints as `[redacted]` with every `fmt` verb and in logs. The package never prompts for it, never reads it from a file and never logs it: how the program gets it is the program's business.

## Verifying the server

There is no option to skip verification. The server is verified by `RootCAs`, or by its exact SPIFFE ID against a bundle. With an SVID and no `RootCAs`, `X509Source` is the bundle. With LDAP credentials and a SPIFFE ID, give `Bundles` too. The minimum TLS version is 1.3.

The client never follows a redirect, because a redirect would carry the credentials to another host: a `3xx` is an error (`ErrRedirect`).

## Behind a proxy

A tool on a corporate network reaches a `ligo` elsewhere through the proxy of the standard `HTTPS_PROXY` and `NO_PROXY` variables, which `net/http` reads. To set one in code, give `HTTPClient` an `*http.Transport` with its `Proxy` set; the package keeps it.

A proxy only tunnels the connection (`CONNECT`). The TLS session, the verification of the server and the client's SVID are end to end, so a proxy that intercepts TLS fails the verification, as it should. With LDAP credentials its CA can be added to `RootCAs`; with an SVID there is no way, and the proxy must not intercept.

## Reading

One method per operation, named from its `operationId`, with the context first. A list returns an iterator over all the pages; the `...Page` form returns one page and the token of the next.

```go
for t, err := range c.ListTargets(ctx, adminclient.TargetFilter{PlatformType: "postgres"}) {
    if err != nil {
        return err
    }
    fmt.Println(t.Metadata.Name, t.Metadata.Jurisdiction, t.Metadata.Revision)
}

detail, err := c.GetTarget(ctx, "orders-db") // with its last 20 audit entries
```

The iterator stops at the first error, which it yields, and when the loop stops: no page is fetched that nobody reads. A filter's fields are the query parameters of the API; an empty one is not sent. The page size is the size of each page, 0 for the server's default and at most 200.

| Reads | Methods |
| :----------------- | :------------------------------------------------------------------ |
| Sources, targets, bindings | `ListSources`, `GetSource`, `SourceAudit`, `ListSourceBindings`, and the same for targets and bindings; `GetBindingFlows` |
| The catalog | `SearchCatalog`, `GetCatalogTarget`, `GetCatalogTargetFlows`, `ListCatalogSources` |
| Change requests | `ListChangeRequests`, `GetChangeRequest` |
| Accounts | `ListAccounts`, `GetAccount` |
| Instances | `ListPlatforms`, `ListIdentityProviders`, `ListSecretStores`, their `Get...` and `...Audit` |

The types are aliases of the generated ones, under names of this package, so that a change of generator does not break your code. What is specific to a platform type (a target's definition and grants, a binding's parameters and spec, an instance's config) is free-form JSON: its schema is the plugin's.

## Filing a change

Every write files a change request and returns it, never the resource as if it had changed.

```go
var spec adminclient.SourceSpec
spec.Metadata.Name = "orders-workers"
spec.Identity.TrustDomain = "example.com"
spec.Identity.SvidRegex = "^spiffe://example.com/ns/orders/sa/worker$"

cr, err := c.CreateSource(ctx, spec, adminclient.Options{ApprovalReference: "CHG-1042"})
if err != nil {
    return err
}
fmt.Println("filed", cr.Id, "awaiting", cr.AwaitingApproval)
```

`Options` carries the `ApprovalReference`, the external ticket or decision, and the `AutomationContext`, which says who runs the automation (delegated approval, ADR-11, uses them); the package passes them on unchanged.

An update, a state change (deprecate, reactivate, retire) and a deletion take the revision they are based on, and fail **before any request** without one:

```go
cur, err := c.GetSource(ctx, "orders-workers")
// ... build the new spec ...
cr, err := c.UpdateSource(ctx, cur.Metadata.Name, spec, cur.Metadata.Revision, adminclient.Options{})
if errors.Is(err, adminclient.ErrConflict) {
    // someone changed it first: read it again
}
```

A mutation is **never repeated** by the client, whatever the answer: a repeated filing would be a second change request. After a timeout, read the change requests to see whether the first one arrived (`ListChangeRequests` with `ResourceName`).

## Managed resources and holds

`Options.Managed` locks a source, a target or a binding to the caller (`true`, a trusted automation delegated on every jurisdiction involved) or releases it (`false`, by the owner). Nil leaves it as it is. After that only the owner, identified by its SPIFFE ID, can change the resource: anybody else gets `ErrState` (`resource-managed`), and `ManagedBy` in the metadata says who the owner is.

```go
cr, err := c.CreateSource(ctx, spec, adminclient.Options{Managed: ptr(true)})
```

When a person removes a managed binding in an emergency, a **hold** stops everybody from creating it again until a person lifts it; a creation under a hold is refused with `ErrState` (`resource-held`). `ListHolds` (and `ListHoldsPage`) shows the holds, open ones by default. Lifting a hold and the release of a resource by an administrator are decisions of people: they are in the CLI (`ligo hold lift`, `ligo source|target|binding release`) and not in this package.

## Waiting for the approval

A change request is `PENDING` until the people who must decide have decided. `WaitChangeRequest` reads it until it ends and returns it.

```go
cr, err = c.WaitChangeRequest(ctx, cr.Id.String(), adminclient.WaitOptions{})
switch {
case err != nil:
    // the context ended (cr is the last state read), or it cannot be read
case !adminclient.IsApplied(cr):
    // REJECTED, WITHDRAWN, EXPIRED or FAILED_TO_APPLY
}
```

Every state but `PENDING` is terminal, and so is any state a later server adds. A terminal state that is not `APPLIED` is not an error of the wait: the tool decides what it means. The wait runs in your goroutine, reads every 2 s by default (at least 1 s, with jitter), and after a failure that may pass, such as a busy server, pauses longer each time, up to `MaxInterval`, and follows the server's `Retry-After`. When the context ends, the last state read comes back with the context's error, so a tool can say "still pending, waiting for its owner".

For a binding, `UntilBindingActive` goes on after `APPLIED` until the binding is `ACTIVE`, which happens asynchronously; a binding that ends `FAILED` is `ErrBindingFailed`.

Give the wait a deadline. A change request that nobody decides expires at its `ExpiresAt`, which the server sets, and that may be a long time away.

## Platforms, identity providers and secret stores

The instances are filed like the rest: `CreatePlatform`, `UpdateSecretStore`, `RetireIdentityProvider` and the others take a `Definition`, the same document as in `ligo apply`. The definition's `kind` must be that of the method, or the call fails before any request.

```go
var def adminclient.Definition
_ = json.Unmarshal([]byte(`{
    "kind": "SecretStore",
    "metadata": {"name": "vault-prod", "jurisdiction": "example/platform", "realm": "prod"},
    "type": "vault.v1",
    "config": {"address": "https://vault.example.com:8200"}
}`), &def)

cr, err := c.CreateSecretStore(ctx, def, adminclient.Options{})
```

An instance change needs the approval of a person of its jurisdiction, never an automatic one, so `cr` comes back `PENDING` and the store does not exist until it is `APPLIED`. A tool that must see the store in force waits; one that must not wait reports that the change awaits approval.

A reader sees an instance's summary and, for a platform, its health. Only a person who may file or decide on its jurisdiction also gets its `Revision` and `Definition`: for anyone else they are nil. A tool that reads instances must say what it cannot fill, and for whom. An instance names a bootstrap credential, it does not hold one: the package never logs a definition, in case its `config` holds anything a user put there.

## Operating, containing and auditing

Some operations are not filings of a change. They are made once and never repeated by the client.

- `RetryBinding` and `RotateBinding` start a binding's workflow again and return the binding. The server asks for an operator of one of the binding's jurisdictions.
- `RevokeTargetBindings` files, for containment, one deletion per binding of a source, or of the sources of a jurisdiction, on a target. A `Comment` is required, and exactly one of `Source` and `SourceJurisdiction`. The answer holds the change requests filed and, apart, the bindings that could not be revoked: a call that filed some and failed others is an answer, not an error, so read `Errors`.
- `WithdrawChangeRequest` withdraws a pending request of the caller's own, with an optional comment for the audit log.
- `GetCharter`, `EvaluateCharter` and `TestSourceRegex` are dry runs: they store nothing. `EvaluateCharter` takes a planned binding, source or target as it would be filed, and says which sides the charter would ask for.
- `GetMaintenance` and `PutMaintenance`, `VerifyAudit`, `ExportAudit`, `RecordAuditExport`, `ListExecutors` and `RecoverExecutor` are the operator's tools, and most of them need `admin.full_access`. A chain that does not verify is a result (`Valid` false), not an error. `ExportAudit` writes JSON Lines to an `io.Writer`; verify the file offline before you record it, and discard it if the call fails: a cut stream is not repeated.

## What the package does not do

It does not approve, decline, ratify or revert a change request, and it does not break glass: those are decisions of people, and the server enforces who may decide and that the approver is not the requester. A tool that automates filing must leave the decision to people.

It keeps no cache, starts no goroutine of its own, reads no file, and prints nothing.

The next chapter lists the errors and what the package protects.
