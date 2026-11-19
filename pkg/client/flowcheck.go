// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/dihedron/netcheck/v2/pkg/netcheck"
	"github.com/dihedron/netcheck/v2/pkg/netcheck/postgres"
	"github.com/dihedron/netcheck/v2/pkg/netcheck/spire"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
)

// MaxFlowChecks is the most checks one call runs. A binding has at most 32 flows
// of a few ports each, so the limit is never reached by an honest answer: it
// bounds what a hostile one can make the host connect to.
const MaxFlowChecks = 1024

// ErrTooManyFlows: the flows add up to more than MaxFlowChecks checks.
var ErrTooManyFlows = errors.New("too many flows to check")

// Status is the outcome of one flow.
type FlowStatus string

// The outcomes. Skipped means the flow could not be checked (see Reason),
// which is not a failure.
const (
	Reachable   FlowStatus = "reachable"
	Unreachable FlowStatus = "unreachable"
	Skipped     FlowStatus = "skipped"
)

// FlowResult is the outcome of one flow and port, or of one ICMP check (Flow is
// empty then).
type FlowResult struct {
	Binding, Target, Flow string
	Destination           string
	Port                  int
	Protocol              string // "tcp", "tls", "postgresql", "spire", "udp", "icmp"; empty when the flow was skipped before a check was chosen
	Status                FlowStatus
	Reason                string // why it is unreachable or skipped; for a UDP pass, what the pass means
	Err                   error  // the check's error when unreachable
	Latency               time.Duration
	Attempts              int
}

// FlowResults is the outcome of a call.
type FlowResults []FlowResult

// Unreachable returns the results whose flow is blocked.
func (r FlowResults) Unreachable() FlowResults {
	var out FlowResults
	for _, x := range r {
		if x.Status == Unreachable {
			out = append(out, x)
		}
	}
	return out
}

// OK says that no flow is unreachable. Skipped flows do not count.
func (r FlowResults) OK() bool { return len(r.Unreachable()) == 0 }

type checkOptions struct {
	timeout     time.Duration
	retries     int
	concurrency int
	roots       *x509.CertPool
	denied      []netip.Prefix
	icmp        bool
	privileged  bool
	handshake   HandshakeFunc
	platforms   map[string]string // binding name to platform type, to choose the default handshakes
	spiffe      x509bundle.Source
	log         *slog.Logger
}

// CheckOption tunes a call.
type CheckOption func(*checkOptions)

// WithRoots sets the trust anchors for flows with tls: true; the default is the system roots.
func WithRoots(p *x509.CertPool) CheckOption { return func(o *checkOptions) { o.roots = p } }

// Handshake is how a TLS flow starts its handshake, which a flow does not say.
type Handshake string

// The handshakes. The zero value is a plain TLS handshake, verified by name.
const (
	// HandshakePostgreSQL asks for TLS inside the protocol (an SSLRequest), then verifies like TLS.
	HandshakePostgreSQL Handshake = "postgresql"
	// HandshakeSPIFFE verifies the server's certificate as an X509-SVID against the trust bundle of WithSPIFFE.
	HandshakeSPIFFE Handshake = "spire"
)

// HandshakeFunc says which handshake the flow's port uses. It is called for
// each port of each flow with tls: true over TCP.
type HandshakeFunc func(f Flow, port int) Handshake

// WithHandshake chooses the handshake of the TLS flows; by default every one
// is a plain TLS handshake, which reports HandshakePostgreSQL and HandshakeSPIFFE servers
// unreachable although their ports are open.
func WithHandshake(h HandshakeFunc) CheckOption { return func(o *checkOptions) { o.handshake = h } }

// WithSPIFFE sets the trust bundles that verify the flows whose handshake is
// HandshakeSPIFFE; without them such a flow is unreachable, with a reason that says so.
func WithSPIFFE(s x509bundle.Source) CheckOption { return func(o *checkOptions) { o.spiffe = s } }

// WithTimeout sets the time of one attempt; the default is 5 s.
func WithTimeout(d time.Duration) CheckOption { return func(o *checkOptions) { o.timeout = d } }

// WithRetries sets the attempts in total; the default is 2.
func WithRetries(n int) CheckOption { return func(o *checkOptions) { o.retries = n } }

// WithConcurrency sets the checks in flight; the default is 8.
func WithConcurrency(n int) CheckOption { return func(o *checkOptions) { o.concurrency = n } }

// WithLogger sets the logger; the default discards. The keys are binding,
// flow, destination, port, protocol, status, reason and error.
func WithLogger(l *slog.Logger) CheckOption { return func(o *checkOptions) { o.log = l } }

// WithDeniedNetworks replaces the networks that are never checked: by default
// the link-local and cloud metadata ranges. Call it with no argument to check everything.
func WithDeniedNetworks(p ...netip.Prefix) CheckOption { return func(o *checkOptions) { o.denied = p } }

// WithICMP adds one echo check for each distinct destination host. Flows
// declare TCP and UDP only, so this is a reachability hint, not a flow. The
// process must be allowed to open ICMP sockets: with privileged set, raw
// sockets, which need cap_net_raw on the binary (setcap cap_net_raw=+ep) or
// root; otherwise datagram sockets, which need net.ipv4.ping_group_range to
// include the process's group.
func WithICMP(privileged bool) CheckOption {
	return func(o *checkOptions) { o.icmp, o.privileged = true, privileged }
}

func defaultDenied() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("fd00:ec2::/32")}
}

// CheckFlows reads the flows of the bindings that match f and tests them, so
// that a workload or an operator sees which flow a firewall still blocks
// before the application connects. It runs when it is called and never on its
// own.
//
// A TCP flow is a connection test, or a TLS handshake when the flow says tls;
// a UDP flow passes when no ICMP error comes back, which means "not refused",
// not "the service is up"; a CIDR destination or a port range is skipped and
// reported with its reason. A flow does not say how its TLS starts, so the
// handshake is chosen from what the client knows: a flow declared by ligo is
// verified as an X509-SVID against the client's own trust bundle, and a flow
// that the target or the platform of a PostgreSQL binding declares asks for TLS
// inside the protocol, as PostgreSQL does. WithHandshake and WithSPIFFE
// replace both. WithICMP adds an echo check per host and needs the process to
// be allowed ICMP sockets: cap_net_raw on the binary (setcap
// cap_net_raw=+ep), or a net.ipv4.ping_group_range that includes its group.
func (c *Client) CheckFlows(ctx context.Context, f Filter, opts ...CheckOption) (FlowResults, error) {
	flows, err := c.Flows(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("reading the flows: %w", err)
	}
	bindings, err := c.Bindings(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("reading the bindings: %w", err)
	}
	platforms := make(map[string]string, len(bindings))
	for _, b := range bindings {
		platforms[b.Name] = b.PlatformType
	}
	defaults := []CheckOption{WithSPIFFE(c.source), func(o *checkOptions) { o.platforms = platforms }}
	return CheckFlowData(ctx, flows, append(defaults, opts...)...)
}

// item is one flow and port: either a check to run or the reason it is not run.
type item struct {
	res   FlowResult
	check *netcheck.Check // nil: skipped
	key   string
}

// plan turns the flows of a binding into items. It does no I/O.
func plan(bf BindingFlows, choose func(BindingFlows, Flow, int) Handshake) []item {
	var items []item
	for _, f := range bf.Flows {
		base := FlowResult{Binding: bf.Binding, Target: bf.Target, Flow: f.Name, Destination: f.Destination}
		skip := func(port int, why string) {
			r := base
			r.Port, r.Status, r.Reason = port, Skipped, why
			items = append(items, item{res: r})
		}
		proto := strings.ToUpper(f.Protocol)
		switch {
		case proto != "TCP" && proto != "UDP":
			skip(0, fmt.Sprintf("protocol %q is not checkable", f.Protocol))
			continue
		case strings.Contains(f.Destination, "/"):
			skip(0, "a CIDR destination has no single host to check")
			continue
		case f.Destination == "":
			skip(0, "no destination")
			continue
		case len(f.Ports) == 0:
			skip(0, "no ports")
			continue
		}
		_, isIP := parseAddr(f.Destination)
		for _, p := range f.Ports {
			switch {
			case p.Low != p.High:
				skip(p.Low, fmt.Sprintf("the port range %d-%d is not probed", p.Low, p.High))
				continue
			case p.Low < 1 || p.Low > 65535:
				skip(p.Low, fmt.Sprintf("port %d is not valid", p.Low))
				continue
			}
			r := base
			r.Port = p.Low
			addr := net.JoinHostPort(f.Destination, fmt.Sprint(p.Low))
			c := &netcheck.Check{Name: f.Name, Address: addr}
			switch {
			case proto == "UDP":
				c.Protocol, r.Protocol = netcheck.UDP, "udp"
			case f.TLS && handshakeOf(choose, bf, f, p.Low) == HandshakeSPIFFE:
				c.Protocol, r.Protocol = netcheck.SPIRE, "spire" // an SVID has no name to verify
			case f.TLS:
				name := f.ServerName
				if name == "" && !isIP {
					name = f.Destination
				}
				if name == "" {
					skip(p.Low, "tls with a bare IP address and no server name: there is no name to verify")
					continue
				}
				c.Protocol, r.Protocol = netcheck.TLS, "tls"
				if handshakeOf(choose, bf, f, p.Low) == HandshakePostgreSQL {
					c.Protocol, r.Protocol = netcheck.PostgreSQL, "postgresql"
				}
				c.TLS = &netcheck.TLSOptions{ServerName: name}
			default:
				c.Protocol, r.Protocol = netcheck.TCP, "tcp"
			}
			items = append(items, item{res: r, check: c, key: string(c.Protocol) + "|" + addr + "|" + serverName(c)})
		}
	}
	return items
}

func handshakeOf(choose func(BindingFlows, Flow, int) Handshake, bf BindingFlows, f Flow, port int) Handshake {
	if choose == nil {
		return ""
	}
	return choose(bf, f, port)
}

// handshakeOf is the handshake of a port of a flow: the caller's choice, or the
// default of what the client knows.
func (o *checkOptions) handshakeOf(bf BindingFlows, f Flow, port int) Handshake {
	if o.handshake != nil {
		return o.handshake(f, port)
	}
	switch {
	case f.DeclaredBy == "ligo":
		return HandshakeSPIFFE
	case isPostgres(o.platforms[bf.Binding]) && (strings.HasPrefix(f.DeclaredBy, "target:") || strings.HasPrefix(f.DeclaredBy, "platform:")):
		return HandshakePostgreSQL
	}
	return ""
}

func serverName(c *netcheck.Check) string {
	if c.TLS == nil {
		return ""
	}
	return c.TLS.ServerName
}

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return a, err == nil
}

func denies(denied []netip.Prefix, host string) bool {
	a, ok := parseAddr(host)
	if !ok {
		return false // a name is checked by netcheck, which resolves it and applies the same list
	}
	for _, p := range denied {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// CheckFlowData tests flows obtained elsewhere, as CheckFlows does, but with
// no client: it knows only the flows, so a flow declared by ligo is a SPIFFE
// handshake only when WithSPIFFE gives it a trust bundle, and no flow is
// PostgreSQL's unless WithHandshake says so. A flow that cannot be checked is
// Skipped with its reason; an unreachable one is Unreachable with the check's
// error. The error is for the call itself: too many flows, or a bundle netcheck
// refuses.
func CheckFlowData(ctx context.Context, flows []BindingFlows, opts ...CheckOption) (FlowResults, error) {
	o := checkOptions{timeout: 5 * time.Second, retries: 2, concurrency: 8, denied: defaultDenied(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, opt := range opts {
		opt(&o)
	}
	var items []item
	for _, bf := range flows {
		items = append(items, plan(bf, o.handshakeOf)...)
	}
	if len(items) > MaxFlowChecks {
		return nil, fmt.Errorf("%w: %d checks, at most %d", ErrTooManyFlows, len(items), MaxFlowChecks)
	}

	// one netcheck check for each distinct key; denied literals never reach it
	var checks []netcheck.Check
	index := map[string]int{}
	for i := range items {
		it := &items[i]
		if it.check == nil {
			continue
		}
		host, _, _ := net.SplitHostPort(it.check.Address)
		if denies(o.denied, host) {
			it.check, it.res.Status, it.res.Reason = nil, Skipped, "the destination is in a denied network"
			continue
		}
		if o.roots != nil && it.check.TLS != nil {
			it.check.TLS.RootCAs = o.roots
		}
		if _, ok := index[it.key]; !ok {
			index[it.key] = len(checks)
			checks = append(checks, *it.check)
		}
	}
	icmpAt := map[string]int{}
	var icmpHosts []string
	if o.icmp {
		for _, it := range items {
			if it.check == nil {
				continue
			}
			host, _, _ := net.SplitHostPort(it.check.Address)
			if _, ok := icmpAt[host]; !ok {
				icmpAt[host] = len(checks)
				icmpHosts = append(icmpHosts, host)
				checks = append(checks, netcheck.Check{Name: host, Address: host, Protocol: netcheck.ICMP})
			}
		}
	}

	var report *netcheck.Report
	if len(checks) > 0 {
		d := netcheck.DefaultDefaults()
		d.Ping.Count, d.Ping.Privileged = 3, o.privileged
		var err error
		report, err = netcheck.Run(ctx, &netcheck.Bundle{ID: "flowcheck", Timeout: netcheck.Duration(o.timeout), Retries: o.retries, Concurrency: o.concurrency, Checks: checks},
			netcheck.WithDefaults(d), netcheck.WithDeniedNetworks(o.denied...),
			netcheck.WithRunner(netcheck.PostgreSQL, postgres.Runner()), netcheck.WithRunner(netcheck.SPIRE, spire.Runner(spireOptions(o.spiffe)...)))
		switch {
		case err != nil && ctx.Err() != nil:
			report = interrupted(len(checks)) // the context ended before the run began
		case err != nil:
			return nil, fmt.Errorf("running the checks: %w", err)
		}
	}

	out := make(FlowResults, 0, len(items)+len(icmpHosts))
	for _, it := range items {
		r := it.res
		if it.check != nil {
			fill(&r, report.Results[index[it.key]])
		}
		out = append(out, r)
		logResult(o.log, r)
	}
	for _, host := range icmpHosts {
		r := FlowResult{Destination: host, Protocol: "icmp"}
		fill(&r, report.Results[icmpAt[host]])
		if r.Status == Unreachable {
			r.Reason += "; if ICMP is refused to this process, it needs cap_net_raw (setcap cap_net_raw=+ep on the binary) or a net.ipv4.ping_group_range that includes its group"
		}
		out = append(out, r)
		logResult(o.log, r)
	}
	return out, nil
}

func spireOptions(s x509bundle.Source) []spire.Option {
	if s == nil {
		return nil
	}
	return []spire.Option{spire.WithSource(s)}
}

func interrupted(n int) *netcheck.Report {
	r := &netcheck.Report{Results: make([]netcheck.Result, n)}
	for i := range r.Results {
		r.Results[i].Status = netcheck.Skipped
	}
	return r
}

// fill copies a netcheck result into r.
func fill(r *FlowResult, nr netcheck.Result) {
	r.Latency, r.Attempts = nr.Latency, nr.Attempts
	switch {
	case nr.Status == netcheck.Passed:
		r.Status = Reachable
		if r.Protocol == "udp" {
			r.Reason = "no ICMP error came back; a silent peer passes"
		}
	case errors.Is(nr.Err, netcheck.ErrNetworkNotAllowed):
		r.Status, r.Reason = Skipped, "the destination is in a denied network"
	case nr.Status == netcheck.Skipped:
		r.Status, r.Reason = Skipped, "interrupted"
	default:
		r.Status, r.Err = Unreachable, nr.Err
		if nr.Err != nil {
			r.Reason = nr.Err.Error()
		}
	}
}

func logResult(l *slog.Logger, r FlowResult) {
	attrs := []any{"binding", r.Binding, "flow", r.Flow, "destination", r.Destination, "port", r.Port, "protocol", r.Protocol, "status", string(r.Status)}
	if r.Reason != "" {
		attrs = append(attrs, "reason", r.Reason)
	}
	l.Info("flow checked", attrs...)
}

// isPostgres says whether a platform type is the PostgreSQL provider's.
func isPostgres(platformType string) bool {
	return platformType == "postgres" || strings.HasPrefix(platformType, "postgres.")
}
