package flowcheck

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

	"github.com/dihedron/ligo/pkg/client"
)

// MaxChecks is the most checks one call runs. A binding has at most 32 flows
// of a few ports each, so the limit is never reached by an honest answer: it
// bounds what a hostile one can make the host connect to.
const MaxChecks = 1024

// ErrTooManyFlows: the flows add up to more than MaxChecks checks.
var ErrTooManyFlows = errors.New("too many flows to check")

// Status is the outcome of one flow.
type Status string

// The outcomes. Skipped means the flow could not be checked (see Reason),
// which is not a failure.
const (
	Reachable   Status = "reachable"
	Unreachable Status = "unreachable"
	Skipped     Status = "skipped"
)

// Result is the outcome of one flow and port, or of one ICMP check (Flow is
// empty then).
type Result struct {
	Binding, Target, Flow string
	Destination           string
	Port                  int
	Protocol              string // "tcp", "tls", "udp", "icmp"; empty when the flow was skipped before a check was chosen
	Status                Status
	Reason                string // why it is unreachable or skipped; for a UDP pass, what the pass means
	Err                   error  // the check's error when unreachable
	Latency               time.Duration
	Attempts              int
}

// Results is the outcome of a call.
type Results []Result

// Unreachable returns the results whose flow is blocked.
func (r Results) Unreachable() Results {
	var out Results
	for _, x := range r {
		if x.Status == Unreachable {
			out = append(out, x)
		}
	}
	return out
}

// OK says that no flow is unreachable. Skipped flows do not count.
func (r Results) OK() bool { return len(r.Unreachable()) == 0 }

// Flowser is what CheckClient needs of a client: *client.Client.
type Flowser interface {
	Flows(ctx context.Context, f client.Filter) ([]client.BindingFlows, error)
}

type options struct {
	timeout     time.Duration
	retries     int
	concurrency int
	roots       *x509.CertPool
	denied      []netip.Prefix
	icmp        bool
	privileged  bool
	log         *slog.Logger
}

// Option tunes a call.
type Option func(*options)

// WithRoots sets the trust anchors for flows with tls: true; the default is the system roots.
func WithRoots(p *x509.CertPool) Option { return func(o *options) { o.roots = p } }

// WithTimeout sets the time of one attempt; the default is 5 s.
func WithTimeout(d time.Duration) Option { return func(o *options) { o.timeout = d } }

// WithRetries sets the attempts in total; the default is 2.
func WithRetries(n int) Option { return func(o *options) { o.retries = n } }

// WithConcurrency sets the checks in flight; the default is 8.
func WithConcurrency(n int) Option { return func(o *options) { o.concurrency = n } }

// WithLogger sets the logger; the default discards. The keys are binding,
// flow, destination, port, protocol, status, reason and error.
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.log = l } }

// WithDeniedNetworks replaces the networks that are never checked: by default
// the link-local and cloud metadata ranges. Call it with no argument to check everything.
func WithDeniedNetworks(p ...netip.Prefix) Option { return func(o *options) { o.denied = p } }

// WithICMP adds one echo check for each distinct destination host. Flows
// declare TCP and UDP only, so this is a reachability hint, not a flow. The
// process must be allowed to open ICMP sockets: with privileged set, raw
// sockets, which need cap_net_raw on the binary (setcap cap_net_raw=+ep) or
// root; otherwise datagram sockets, which need net.ipv4.ping_group_range to
// include the process's group.
func WithICMP(privileged bool) Option {
	return func(o *options) { o.icmp, o.privileged = true, privileged }
}

func defaultDenied() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("fd00:ec2::/32")}
}

// CheckClient reads the flows of f from the client and checks them.
func CheckClient(ctx context.Context, c Flowser, f client.Filter, opts ...Option) (Results, error) {
	flows, err := c.Flows(ctx, f)
	if err != nil {
		return nil, fmt.Errorf("reading the flows: %w", err)
	}
	return Check(ctx, flows, opts...)
}

// item is one flow and port: either a check to run or the reason it is not run.
type item struct {
	res   Result
	check *netcheck.Check // nil: skipped
	key   string
}

// plan turns the flows of a binding into items. It does no I/O.
func plan(bf client.BindingFlows) []item {
	var items []item
	for _, f := range bf.Flows {
		base := Result{Binding: bf.Binding, Target: bf.Target, Flow: f.Name, Destination: f.Destination}
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
				c.TLS = &netcheck.TLSOptions{ServerName: name}
			default:
				c.Protocol, r.Protocol = netcheck.TCP, "tcp"
			}
			items = append(items, item{res: r, check: c, key: string(c.Protocol) + "|" + addr + "|" + serverName(c)})
		}
	}
	return items
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

// Check checks the flows. A flow that cannot be checked is Skipped with its
// reason; an unreachable one is Unreachable with the check's error. The error
// is for the call itself: too many flows, or a bundle netcheck refuses.
func Check(ctx context.Context, flows []client.BindingFlows, opts ...Option) (Results, error) {
	o := options{timeout: 5 * time.Second, retries: 2, concurrency: 8, denied: defaultDenied(), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, opt := range opts {
		opt(&o)
	}
	var items []item
	for _, bf := range flows {
		items = append(items, plan(bf)...)
	}
	if len(items) > MaxChecks {
		return nil, fmt.Errorf("%w: %d checks, at most %d", ErrTooManyFlows, len(items), MaxChecks)
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
			netcheck.WithDefaults(d), netcheck.WithDeniedNetworks(o.denied...))
		switch {
		case err != nil && ctx.Err() != nil:
			report = interrupted(len(checks)) // the context ended before the run began
		case err != nil:
			return nil, fmt.Errorf("running the checks: %w", err)
		}
	}

	out := make(Results, 0, len(items)+len(icmpHosts))
	for _, it := range items {
		r := it.res
		if it.check != nil {
			fill(&r, report.Results[index[it.key]])
		}
		out = append(out, r)
		logResult(o.log, r)
	}
	for _, host := range icmpHosts {
		r := Result{Destination: host, Protocol: "icmp"}
		fill(&r, report.Results[icmpAt[host]])
		if r.Status == Unreachable {
			r.Reason += "; if ICMP is refused to this process, it needs cap_net_raw (setcap cap_net_raw=+ep on the binary) or a net.ipv4.ping_group_range that includes its group"
		}
		out = append(out, r)
		logResult(o.log, r)
	}
	return out, nil
}

func interrupted(n int) *netcheck.Report {
	r := &netcheck.Report{Results: make([]netcheck.Result, n)}
	for i := range r.Results {
		r.Results[i].Status = netcheck.Skipped
	}
	return r
}

// fill copies a netcheck result into r.
func fill(r *Result, nr netcheck.Result) {
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

func logResult(l *slog.Logger, r Result) {
	attrs := []any{"binding", r.Binding, "flow", r.Flow, "destination", r.Destination, "port", r.Port, "protocol", r.Protocol, "status", string(r.Status)}
	if r.Reason != "" {
		attrs = append(attrs, "reason", r.Reason)
	}
	l.Info("flow checked", attrs...)
}
