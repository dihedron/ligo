# The Go SDK

```go
import "github.com/dihedron/ligo/pkg/client"
```

## Creating a client

```go
c, err := client.New(ctx, client.Config{
    Address:  "ligo.example.com:8443",               // the workload API: host:port, no scheme
    ServerID: "spiffe://example.com/ns/sys/sa/ligo", // the only SPIFFE ID accepted for ligo
})
if err != nil {
    return err
}
defer c.Close()
```

`New` checks the configuration and opens the SVID source. It does not call `ligo`; the first request does. It reads `SPIFFE_ENDPOINT_SOCKET`, as every SPIFFE program does, so a workload in a pod or a VM needs no more.

| Field | Meaning |
| :-------------- | :----------------------------------------------------------------- |
| `Address` | `host:port` of the workload API. Always TLS. |
| `ServerID` | `ligo`'s SPIFFE ID. Any other peer is refused. |
| `Transport` | `client.REST` (default) or `client.GRPC`. Both return the same data. |
| `X509Source` | Your own source of the SVID and bundles; default: the Workload API. |
| `JWTSource` | Your own source of JWT-SVIDs; default: the Workload API. |
| `StoreRoots` | The CAs of the secret store's certificate; default: the system's roots. |
| `AllowedStores` | The store addresses (`https://host:port`) the client may log in to. See "Errors and security". |
| `PollInterval` | How often `Watch` asks `ligo`; default 30 s, at least 5 s. |
| `Logger` | A `*slog.Logger`; default `slog.Default()`. |

The client is safe for concurrent use. Create one for the life of the program.

## Bindings

```go
bindings, err := c.Bindings(ctx, client.Filter{Target: "orders-db"})
if err != nil {
    return err
}
if len(bindings) == 0 {
    return errors.New("no binding to orders-db")
}
b := bindings[0]
fmt.Println(b.Name, b.PlatformType, b.Endpoint())
```

No binding is an empty list, not an error. `Filter` narrows by `Target` and by `PlatformType`. A `Binding` has the fields of the previous chapter; `Spec` is a `map[string]any`, since it differs per platform type, and `Endpoint()` returns `Spec["endpoint"]` when there is one.

The client remembers the last answer for each filter and asks `ligo` again with its ETag. When nothing has changed, `ligo` answers without a body, and the client returns the remembered list. A call is cheap.

## Credentials

```go
cred, err := c.Credential(ctx, b)
if err != nil {
    return err
}
db, err := sql.Open("pgx", fmt.Sprintf("postgres://%s:%s@%s/%s",
    url.QueryEscape(cred.Username), url.QueryEscape(cred.Password), b.Endpoint(), b.Spec["database"]))
```

`Credential` logs in to the secret store with a JWT-SVID and reads the credential of the binding. `cred.Expires` is the end of the lease, or zero when there is none.

- Every call reads the store. With `vault-dynamic` each read creates a new database user, so read once and keep the result; do not call it for every connection.
- `fmt.Println(cred)` and logging `cred` never show the password: `Credential` hides it in `String`, `%#v` and `slog`. Read `cred.Password` when you need it.
- A binding that needs no credential, such as one with the `svid` strategy, gives `ErrNoCredential`. Connect with `c.TLSConfig`:

```go
id := spiffeid.RequireFromString(b.Spec["serverId"].(string))
conn, err := tls.Dial("tcp", b.Endpoint(), c.TLSConfig(id))
```

`TLSConfig` is mTLS with the workload's SVID, and it accepts only the server named. It never offers TLS 1.2.

## Flows

```go
flows, err := c.Flows(ctx, client.Filter{Target: "orders-db"})
```

returns the network flows each binding needs: destination, ports, protocol and whether TLS is used. It is data: the SDK does not test them.
