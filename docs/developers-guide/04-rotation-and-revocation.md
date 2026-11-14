# Rotation and revocation

A binding changes, and a credential ends. A workload that reads its credential once will fail at the end of the lease, or after the platform team has revoked the binding. `Watch` is how a workload follows.

## Watch

```go
err := c.Watch(ctx, client.Filter{Target: "orders-db", WatchCredentials: true}, func(ev client.Event) {
    switch ev.Kind {
    case client.Added, client.Changed:
        log.Printf("binding %s, revision %d", ev.Binding.Name, ev.Binding.Revision)
    case client.CredentialRotated:
        pool.Replace(ev.Binding, ev.Credential)
    case client.Removed:
        pool.Close(ev.Previous)
    }
})
```

`Watch` blocks until `ctx` ends and returns its error. It calls the function on its own goroutine, one event at a time, so the function should not block for long.

| Event | When | Set |
| :----------------- | :------------------------------------------------------- | :--------------- |
| `Added` | A binding appears; at the first poll, every binding. | `Binding` |
| `Changed` | A binding has another revision. | `Binding`, `Previous` |
| `Removed` | A binding is gone: revoked or expired. | `Previous` |
| `CredentialRotated` | A credential was read for the binding. | `Binding`, `Credential` |

The server has no stream, so `Watch` asks `ligo` every `PollInterval`, with a little jitter. The answer to a poll with nothing new is empty.

With `WatchCredentials` the watch also reads the credential:

- after `Added` and after `Changed`, and so on the first poll;
- again at two thirds of a lease, for a credential that has one, so the new credential is ready before the old one ends.

A failed poll keeps the watch's state and emits nothing. The watch logs a warning and waits: the poll interval after the first failure, then twice as long at each further failure, up to five minutes. When `ligo` says when to come back (`Retry-After` on REST, `RetryInfo` on gRPC), the watch waits at least that long. After a success it returns to the poll interval. So a `ligo` restart is invisible to the application: no `Removed`, no `Added`.

## What the application does

- **On `CredentialRotated`,** open new connections with the new credential, and let the old connections finish. With `vault-dynamic` the old credential is valid until its lease ends, so there is no gap.
- **On `Removed`,** close the connections of that binding. The SDK cannot close them: they are yours. `ligo` has already removed the store's policy, so a new `Credential` call fails with `ErrStore`, and the credentials issued before stop working when the platform drops them.
- **When the target refuses the credential,** call `c.Invalidate(b)` and read the credential again. It drops the store login the client remembers, which may have been revoked.

## Writing the handler

The function runs on the watch's goroutine; a slow one delays the next poll. Hand work to your own goroutines, and keep no reference to `ev.Credential.Password` longer than the connection needs it.
