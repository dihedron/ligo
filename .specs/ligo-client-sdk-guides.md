# The Go client SDK: guides

- **Spec:** `.specs/ligo-client-sdk.md`
- **Status:** draft (chunk 0). The commands and the lab names are filled in with chunk 6, when the lab has its SDK clients.

These guides are run by hand, one step at a time, against the lab. They need a lab workload with an SVID and an approved binding; the lab's `echo` targets and its PostgreSQL platform give both.

## G-1. Read a binding and its credential

1. **Write a program** with `client.New`, `Bindings` and `Credential` (spec §3.1 to §3.3), for a target the workload is bound to.
2. **Run it on the workload's host.** Expect the binding's name, its endpoint and a user name; the password is shown as hidden.
3. **Run it with `Transport: client.GRPC`.** Expect the same output.
4. **Run it for a target with no binding.** Expect an empty list and no error.

## G-2. A wrong server is refused

1. **Set `ServerID`** to another SPIFFE ID of the same trust domain.
2. **Run the program.** Expect `ErrUnauthorized`, and no request in `ligo`'s log.

## G-3. Follow a rotation

1. **Start a program** that calls `Watch` with `WatchCredentials` on a `vault-dynamic` binding, and prints each event.
2. **Expect** `Added`, then `CredentialRotated` with a user name.
3. **Wait** two thirds of the lease. Expect `CredentialRotated` with another user name.
4. **Connect** to the database with each credential while it is valid. Expect both to work.

## G-4. A revoked binding

1. **With the program of G-3 running, revoke the binding** (`ligo binding delete`, approved by a second user).
2. **Expect** `Removed` within one poll interval.
3. **Call `Credential`** for the old binding. Expect `ErrStore`: the store's policy is gone.

## G-5. `ligo` is away

1. **With the program of G-3 running, stop both replicas** (`lab.sh serve stop`).
2. **Expect** WARN lines with a growing interval, and no event.
3. **Start the replicas.** Expect the watch to resume, with no `Removed` and no `Added`.
