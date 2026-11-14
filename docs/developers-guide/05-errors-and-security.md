# Errors and security

## Errors

Every error wraps its cause, so use `errors.Is`:

| Error | Meaning | Do |
| :----------------------- | :------------------------------------------------- | :---------------------- |
| `ErrUnauthorized` | `ligo` refused the caller, or the peer is not `ligo`. | Check the workload's SVID and `ServerID`; do not retry blindly. |
| `ErrUnavailable` | `ligo` cannot answer now, limits the caller's rate, or cannot be reached. | Retry later. |
| `ErrNoCredential` | The binding has no secret store. | Connect with the SVID. |
| `ErrUnsupportedStrategy` | The SDK does not know the strategy. | Update the SDK. |
| `ErrStoreNotAllowed` | The store address is not `https`, or is outside `AllowedStores`. | Check with the platform team. |
| `ErrStore` | The store refused the login or the read, or the binding does not say how to reach it. | The message has the status, never the body. |

Errors never hold a password, a token or a JWT.

## What the SDK protects, and what it leaves to you

- **It talks only to `ligo`.** The server is accepted only with `ServerID`, over mTLS, against the SPIFFE bundle. There is no option to skip verification.
- **It sends the JWT-SVID only to a secret store over TLS.** The store address comes from the binding, that is from `ligo`. Set `AllowedStores` to the stores your platform team uses, so that a wrong answer cannot lead the SDK to another host. The JWT-SVID carries the store's audience, which limits what another host could do with it, but pinning is better.
- **It follows no redirect from a store,** because a redirect would carry the JWT-SVID or the store's token to another host. A Vault standby that redirects to the active node therefore fails: use the address of the active node or of a load balancer.
- **It keeps nothing on disk.** A store token lives in memory until 80 % of its lifetime and is dropped by `Close`. Credentials are not cached: the application holds them.
- **It does not log secrets.** Do not log `cred.Password` yourself.
- **It cannot close your connections** after a revocation, and it cannot know that a target has dropped a credential. Handle `Removed` and `Invalidate`.

## Vault namespaces

When the store instance is in a Vault Enterprise or OpenBao namespace, the binding says so and the SDK sends it with every request. Nothing to configure.

## Testing an application

`client.Config` takes an `X509Source` and a `JWTSource`, so a test can give fixed SVIDs and point `Address` at a `httptest` server that speaks the workload API. The SDK's own tests do this; see `pkg/client/client_test.go`.
