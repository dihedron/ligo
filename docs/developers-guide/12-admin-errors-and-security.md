# Errors and security of the admin client

## Errors

A failed call returns an error that wraps its cause, so use `errors.Is` and `errors.As`.

A problem that the server answers is a `*Problem`: its `Status`, its `Type` (`urn:ligo:problem:` and a slug, which `Slug` returns), its `Title`, its `Detail` and, for a 503 or a 429, the `RetryAfter` the server asked for, at most an hour. The slugs the server sends are mapped to sentinels, and a test fails when the server gains a slug that the client does not map, so a new slug is a decision and not a surprise.

| Sentinel | Meaning | Do |
| :------------------- | :---------------------------------------------------------- | :--------------------- |
| `ErrNotFound` | The resource or the change request does not exist, or the caller may not see it. | Check the name. |
| `ErrConflict` | The revision the change is based on is not the current one (`revision-conflict`, `resource-changed`). | Read again and decide; never overwrite blindly. |
| `ErrState` | The resource or the change request is not in a state that allows it: a binding being applied, a source in use, a request that is no longer pending, and so on. | Wait, or change the state first. |
| `ErrInvalid` | The request is invalid: a field, an immutable field, a regex that widens, a name outside the charter. | Fix the request; the `Detail` says which. |
| `ErrForbidden` | The caller may not, or the approver would be the requester (`four-eyes-violation`). | Ask the right person. |
| `ErrUnauthenticated` | The credentials were refused. | Check the SVID or the LDAP credentials. |
| `ErrUnavailable` | The server is busy, limiting the rate, or behind a proxy that lost it. | Retry later; a GET is retried for you. |
| `ErrMaintenance` | The server is in maintenance mode. | Retry later; honour `RetryAfter`. |
| `ErrTooLarge` | The answer is larger than 8 MiB. | The server is not `ligo`, or a list is not paged. |
| `ErrRedirect` | The server redirected the call. | Fix `ServerURL`: a redirect is never followed. |
| `ErrBindingFailed` | With `UntilBindingActive`, the binding ended `FAILED`. | Read the binding for the reason. |

A response that is not a problem, such as a page of a proxy, is a `*Problem` with its status and nothing else: its text never goes into an error, because it comes from outside `ligo` and may hold anything. An answer that does not match the contract is an error that names the call and the decoding failure, never the body.

## Retries and limits

A **GET** that fails because the connection broke, or because the server answered 429, 502, 503 or 504, is repeated up to `MaxRetries` times (twice by default), after 200 ms doubling to 5 s, with jitter, and after the server's `Retry-After` when it is at most 30 s; a longer one is returned to you, to decide. A refused certificate, a 4xx answer, a malformed answer and a cancelled context are never repeated. A **mutation** is sent once.

Answers are decoded from at most 8 MiB. Every call takes the context you give it, and the `HTTPClient`'s timeout, 60 s by default, bounds each attempt.

## What the package protects, and what it leaves to you

- **It talks only to `ligo`.** The server is verified by `RootCAs` or by its exact SPIFFE ID, with TLS 1.3, and there is no option to skip it. A call never follows a redirect.
- **It does not leak the password.** The password is a `Secret` that prints as `[redacted]`, is held in a closure so that no print of a `Client` shows it, and is in no error and no log. Log your own secrets with the same care: `adminclient.Secret` is there for you to use for others.
- **It cannot approve.** A tool built on it can file, and cannot decide: the server refuses a decision by the requester, and the package has no method for one. Keep it so: a tool that must approve is a human's, and uses the `ligo` CLI.
- **It repeats nothing that changes.** After an uncertain failure of a mutation, read before you file again.
- **It keeps nothing.** There is no cache and no global state, and no file is read or written. The tool decides where its credentials come from and how long they live.
- **It does not validate what the plugins own.** A target's definition, a binding's parameters and an instance's `config` are checked by the server with the plugin's schema, and you see the refusal as `ErrInvalid`.

## Testing a tool

Test against a server you start: an `httptest.NewTLSServer` that answers the paths of the OpenAPI document, with its certificate in `RootCAs` and LDAP credentials in `Basic`.

```go
srv := httptest.NewTLSServer(handler)
t.Cleanup(srv.Close)
roots := x509.NewCertPool()
roots.AddCert(srv.Certificate())
c, err := adminclient.New(adminclient.Config{
    ServerURL: srv.URL,
    RootCAs:   roots,
    Basic:     &adminclient.BasicAuth{Username: "ada", Password: "test"},
    MaxRetries: -1, // fail at once
})
```

Answer a problem as `application/problem+json` with a `type` of `urn:ligo:problem:<slug>`, and the sentinels follow. To test a wait, give the server a change request that turns `APPLIED` on its third read, set `WaitOptions{Interval: time.Second}`, the smallest allowed, and a short deadline.

For an end-to-end test, the lab of the `ligo` repository (`test/lab/lab.sh`) starts a real `ligo` with its PostgreSQL, SPIRE and a secret store.
