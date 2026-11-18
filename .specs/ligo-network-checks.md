# Network checks in the client SDK

- **Version:** 0.1 (2026-11-18), approved by the user in plan mode
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
| 3 | Lab scenario in `lab.sh serve test`: a binding's flows checked against the real servers, one blocked (proposed, not in this chunk). |
| 4 | After the netcheck soak: the dependency moves to `v2.0.0` (done 2026-11-18). |

## 7. Out of scope

DTLS, SSH, HTTP, SSO checks; a command line; checking on the first fetch; expanding CIDRs or ranges.
