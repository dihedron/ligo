# Network checks in the client SDK

- **Version:** 0.3 (2026-11-19): flow testing moves into the client (§9); 0.2 (2026-11-19): the handshakes of PostgreSQL and SPIFFE (§8) and the lab scenario (chunk 3); 0.1 (2026-11-18), approved by the user in plan mode
- **Backlog:** item 12
- **Branch:** `feature/network-checks`
- **Depends on:** `.specs/ligo-client-sdk.md` (flows as data, §3.4) and netcheck v2 (v2.0.0, tagged 2026-11-18)

## 1. Why

Each binding carries its network flows (`c.Flows`). Today a workload learns that a flow is blocked only when its first connection fails. `pkg/client/flowcheck` checks the flows with netcheck, so a workload or an operator sees which flow a firewall still blocks before the application connects.

## 2. Decisions (the user, 2026-11-18)

| Question | Decision |
|---|---|
| Where | Sub-package `pkg/client/flowcheck`. `pkg/client` stays free of the netcheck dependency. |
| Library | netcheck's own module, `github.com/dihedron/netcheck/v2`, only its core package `pkg/netcheck`. The dependency is netcheck `v2.0.0` (it was pinned to a commit until the tag, 2026-11-18). |
| `tls: true` | Checked up to the TLS handshake against the system roots; the caller may give a `*x509.CertPool`. |
| CIDR destination, port range | Skipped and reported with the reason: never a false pass or fail. |
| When | On demand only. |
| ICMP | Opt-in (`WithICMP`): one echo check per distinct destination host. Flows declare only TCP and UDP, so ICMP is a reachability hint, not a flow. A client that uses it must be allowed raw sockets: `setcap cap_net_raw=+ep` on the application's binary (as the netcheck package does for `/usr/bin/netcheck`), or, unprivileged, a `net.ipv4.ping_group_range` that includes the process's group. |

## 3. The package

```go
res, err := flowcheck.CheckClient(ctx, c, client.Filter{Target: "ledger"}, flowcheck.WithRoots(pool))
for _, r := range res { fmt.Println(r.Flow, r.Destination, r.Port, r.Status, r.Reason) }
```

- `Check(ctx, []client.BindingFlows, ...Option) ([]Result, error)` and `CheckClient(ctx, *client.Client, client.Filter, ...Option) ([]Result, error)`, which calls `Flows` first.
- `Result`: `Binding`, `Target`, `Flow`, `Destination`, `Port`, `Protocol` (`tcp`, `tls`, `udp`, `icmp`), `Status` (`Reachable`, `Unreachable`, `Skipped`), `Reason`, `Err`, `Latency`, `Attempts`. `Results` has `OK()` and `Unreachable()`.
- Mapping, per flow and single port: TCP without TLS is a `tcp` check; TCP with TLS is a `tls` check verifying `ServerName`, or the destination host when it is a name; UDP is a `udp` check (a silent peer passes: it means "no ICMP error", not "the service is up"). A CIDR, a range, or a bare IP with `tls: true` and no `ServerName` is `Skipped`. Two flows to the same address and port with the same kind are checked once and the result is shared.
- Options: `WithRoots`, `WithTimeout` (5 s), `WithRetries` (2), `WithConcurrency` (8), `WithICMP(privileged bool)`, `WithDeniedNetworks` (default: link-local and the cloud metadata ranges; an empty call removes the default), `WithLogger`.
- At most 1,024 checks per call (`netcheck.WithLimits`); more is `ErrTooManyFlows`.
- The context ends the run: unfinished checks are `Skipped` with the reason "interrupted".

## 4. Threat model

| ID | Threat | Mitigation |
|---|---|---|
| T-N1 | A compromised `ligo` makes the SDK probe hosts of its choice. | The server bounds destinations by the platform's `allowed_endpoints` (INV-24, ADR-16); the SDK denies link-local and metadata ranges by default, caps the number of checks and never expands a CIDR or a range. |
| T-N2 | A check leaks secrets. | None are involved; results carry statuses and netcheck's scrubbed errors; logs carry binding, flow, destination, port and status only. |
| T-N3 | False assurance from UDP. | Documented; the `Reason` of a UDP pass says "no ICMP error". |
| T-N4 | Supply chain: the netcheck module brings its requirements into `go.mod`. | `make vuln` on every change; the dependency is a tagged release; only the core package is imported. |
| T-N5 | An application given raw sockets for ICMP does more than ping. | The guide says to grant the capability to a dedicated binary and not to a shell or an interpreter; unprivileged ping sockets are the alternative. |

## 5. Tests first

- **FC-1** The mapping: TCP, TCP with TLS (name and bare IP), UDP, CIDR, range, shared checks.
- **FC-2** Reachable and unreachable against a local listener and a closed port.
- **FC-3** TLS: trusted with `WithRoots`, untrusted with the system roots, wrong `ServerName`.
- **FC-4** A denied network is `Skipped`; the default denies 169.254.0.0/16.
- **FC-5** The context ends the run.
- **FC-6** More than the limit is `ErrTooManyFlows`.
- **FC-7** `CheckClient` against the real workload handler, as the transport tests do.
- **FC-8** Logs carry only the allowed keys.
- **FC-9** `WithICMP` adds one check per distinct host; in an environment without the capability the result is `Unreachable` with a reason that names the capability (the test is skipped where ICMP works unprivileged).
- Fuzz the flow-to-check mapping; benchmark 32 flows.

## 6. Chunks

| Chunk | Content |
|---|---|
| 0 | This spec, the backlog row. |
| 1 | The dependency (pinned), the tests red, then `flowcheck` (FC-1 to FC-9), fuzz, benchmark. |
| 2 | Package doc, `Example`, the Developer's Guide chapter (with the ICMP capability note), README. |
| 3 | Lab scenario `lab.sh serve test-flowcheck`, part of `serve test`: a binding's flows checked against the real servers, one blocked (done 2026-11-19, §8). |
| 4 | After the netcheck soak: the dependency moves to `v2.0.0` (done 2026-11-18). |

## 7. Out of scope

DTLS, SSH, HTTP, SSO checks; a command line; checking on the first fetch; expanding CIDRs or ranges.

## 8. The lab scenario, and the two handshakes it found (0.2, 2026-11-19)

The first lab run reported two real flows unreachable although their ports were open: PostgreSQL negotiates TLS inside its protocol (an `SSLRequest` first), and ligo's workload API presents an X509-SVID, which has a URI SAN and no DNS name, so verification by name against the CA fails. The user decided (2026-11-19) that netcheck gets both handshakes as checks, usable by anyone (netcheck v2.1.0: `postgresql` and `spire`, `netcheck/.specs/netcheck-tls-kinds.md`), and that `flowcheck` uses them as library code.

| Decision | |
|---|---|
| Mapping | `WithHandshake(func(client.Flow, port int) Handshake)` chooses `PostgreSQL`, `SPIFFE` or the plain default for a TCP flow with `tls: true`. A flow does not carry the hint, so the caller maps it; a hint in the flow is backlog item 18. |
| Trust | `WithSPIFFE(x509bundle.Source)`. Without it a SPIFFE flow is `Unreachable`, "no trust bundle". The expected ID is not checked: any ID the bundle vouches for passes. |
| Results | `Protocol` is `postgresql` or `spire` for these flows. A SPIFFE flow needs no server name, so a bare IP is not skipped. |

Tests: **FC-10** the mapping chooses the check of a TLS flow and of no other; **FC-11** a fake PostgreSQL (`SSLRequest`, `S`, TLS) is reachable with the `postgresql` handshake and unreachable with plain TLS; **FC-12** an SVID server is reachable with the SPIFFE handshake and its bundle, unreachable without the bundle, with an empty bundle and with plain TLS.

**Lab** (`TestServeClientFlowcheck`, `lab.sh serve test-flowcheck`, also in `serve test`): a workload binds a `pg-ledger-dynamic` target and checks its four flows (the target's and the platform's PostgreSQL, the secret store, ligo's workload API). **FC-L1** all four are reachable, on OpenBao and on Vault, with the PostgreSQL and SPIFFE handshakes. **FC-L2** `lab.sh` makes ligo1 reject, at once, the connections to the database host of the test's processes only (an `nft` rule on the test's group, so that ligo, which runs as the same user, keeps its database): exactly the two PostgreSQL flows are `Unreachable`, with the refusal as the error, and the others stay reachable. **FC-L3** after the rule is gone, all four are reachable again. **FC-L4** a link-local destination (the cloud metadata address) is `Skipped` as denied, and nothing is sent. **FC-L5** `WithICMP` adds one result per distinct host; unprivileged, each is `Unreachable` with a reason that names `cap_net_raw` and `ping_group_range`. The rule is removed when the run ends, even by a failure.

Observed once, and not again in five later runs: right after a binding was `ACTIVE` for the admin API, the check saw no flows at all. The cause is not found (a delay of the workload API, or the change of group of the test); the test waits up to 30 s for the flows, and the item stays open until it can be reproduced or ruled out.

## 9. Flow testing is a method of the client (0.3, 2026-11-19)

The user observed that neither SDK tests the flows from the client itself: the Go `Client` only enumerates them (`Flows`), and testing is a separate package; the Python SDK has nothing. Decided (2026-11-19): **both SDKs get flow testing as a method of the client, in the public interface**, and, for Go, `pkg/client` stops being free of the netcheck dependency (it reverses §2, row "Where").

**Go.** `pkg/client/flowcheck` moves into `pkg/client`, and the package is deleted (no compatibility code before 1.0.0):

- `func (c *Client) CheckFlows(ctx, Filter, ...CheckOption) (FlowResults, error)` reads the flows and tests them; `func CheckFlowData(ctx, []BindingFlows, ...CheckOption) (FlowResults, error)` tests flows obtained elsewhere.
- Types `FlowResult` (the old `Result`), `FlowStatus` (`Reachable`, `Unreachable`, `Skipped`), `FlowResults` (`OK`, `Unreachable`), `ErrTooManyFlows`, `Handshake` and its constants, `HandshakeFunc`, `CheckOption`. The options keep their names: `WithRoots`, `WithTimeout`, `WithRetries`, `WithConcurrency`, `WithICMP`, `WithDeniedNetworks`, `WithLogger`, `WithHandshake`, `WithSPIFFE`.
- **Defaults come from the client**, so the common case needs no option. The trust bundle of the SPIFFE flows is the client's own X.509 source; a flow with `DeclaredBy == "ligo"` is checked with the SPIFFE handshake; a flow of a binding whose platform type is PostgreSQL's is checked with the PostgreSQL handshake (`CheckFlows` reads the bindings to know it; `CheckFlowData` has no bindings and uses only the first rule). Both are replaced by the hint in the flow when backlog item 18 is done. `WithHandshake` and `WithSPIFFE` override them.
- T-N4 (the supply chain) now concerns every user of the SDK: netcheck's core is the standard library and three small modules, and its `postgres` and `spire` packages add nothing that `pkg/client` does not already link (`go-spiffe`).

Tests: FC-1 to FC-12 move with the code and run on `CheckFlowData`; **FC-13** `CheckFlows` reads the flows and the bindings of the real `workloadhttp` handler and chooses the default handshakes; **FC-14** a `HandshakeFunc` and a `WithSPIFFE` override the defaults. The lab scenario (§8) calls `c.CheckFlows`.

**Python.** `Client.check_flows` and `check_flow_data`, on the standard library: `.specs/ligo-client-sdk-python.md` §5.
