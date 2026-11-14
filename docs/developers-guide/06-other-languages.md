# Other languages

SDKs for Java, Python and JavaScript/TypeScript will follow the Go SDK. They are not written yet; this chapter says what they will do, so that a developer in another language can plan.

Each will wrap that language's SPIFFE library (`java-spiffe`, `py-spiffe`, and the JavaScript equivalent), and be generated from the same protocol buffers, `api/proto/workload/v1alpha1`. Each will offer the same operations with the idioms of its language:

- get the bindings of a target;
- read a binding's credential from its secret store;
- watch for changes and rotations;
- an mTLS configuration for targets that speak SPIFFE.

Until then, a program in another language can call the workload API directly:

- **REST:** `GET https://ligo:8443/v1/bindings?target=NAME`, over mTLS with the workload's X.509-SVID, verifying that the server's SPIFFE ID is `ligo`'s. Send the previous `ETag` in `If-None-Match`; a `304` has no body.
- **gRPC:** `ligo.workload.v1alpha1.WorkloadBindingService`, `GetBindings` and `GetFlows`, on the same port.
- **The credential:** log in to the store at `auth/AUTHMOUNT/login` with `role` and a JWT-SVID for `auth.config.audience`, then read `secretPath` (KV version 2) or `credsPath`, sending the namespace in `X-Vault-Namespace` when the binding has one. Do not follow redirects, and verify the store's certificate.
