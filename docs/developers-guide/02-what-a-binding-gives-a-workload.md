# Part 1: Developing an application

# What a binding gives a workload

When a binding is active, a workload that holds its source's SVID can ask `ligo` for it. The answer, for each binding, has:

| Field | Meaning |
| :----------- | :-------------------------------------------------------- |
| `name` | The binding's name. |
| `target`, `platform`, `platformType` | What it reaches. |
| `accessLevel` | The privileges it was granted. |
| `revision` | Changes when the binding changes. |
| `spec` | How to connect: for a database, the endpoint, the database name and the user. It differs per platform type. |
| `auth` | How to get the credential: the strategy, the secret store and where in it. |

A workload never gets a password from `ligo`. `ligo` says where the credential is, and the workload reads it from the secret store, proving who it is with a JWT-SVID. So `ligo` is not on the path of a connection: a workload that has its credential keeps working when `ligo` is down.

## The strategies

`auth.secretStorageStrategy` says what the workload does:

| Strategy | The workload |
| :----------------- | :----------------------------------------------------------- |
| `svid` | Needs no credential: the target admits its SVID. |
| `vault-static` | Reads a fixed user name and password from the store. |
| `vault-dynamic` | Reads a credential that the store makes on demand, with a lease: it works until the lease ends. |

For `vault-dynamic`, each read makes a new credential. The lease is set by the platform team (the platform's `credential_ttl`, else `plugins.dynamic_credentials` in `server.yaml`, else one hour). A workload therefore reads once, uses the credential, and reads again before the lease ends.

## The six steps, and the SDK

Without an SDK a workload does this by hand:

1. fetch its X.509-SVID from the SPIRE agent;
2. call `ligo`'s workload API over mTLS, accepting only `ligo`'s SPIFFE ID;
3. read each binding's `spec` and `auth`;
4. fetch a JWT-SVID for the secret store's audience;
5. log in to the store with it and read the credential;
6. connect to the target, and repeat from step 4 when the credential rotates.

The Go SDK does steps 1 to 5 and the repetition. Step 6 is the application's: the SDK returns the endpoint, the credential and a TLS configuration, and the application opens the connection with its own driver. The SDK has no database driver, so it adds none to the application.
