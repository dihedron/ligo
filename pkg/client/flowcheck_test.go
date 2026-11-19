// SPDX-License-Identifier: MIT

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
)

func port(t testing.TB, addr string) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return n
}

// listener returns an open TCP port on 127.0.0.1.
func listener(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	return port(t, l.Addr().String())
}

// closedPort returns a TCP port nobody listens on.
func closedPort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := port(t, l.Addr().String())
	_ = l.Close()
	return p
}

func one(f Flow) []BindingFlows {
	return []BindingFlows{{Binding: "b1", Source: "s", Target: "ledger", Flows: []Flow{f}}}
}

func single(p int) []PortRange { return []PortRange{{Low: p, High: p}} }

func run(t *testing.T, flows []BindingFlows, opts ...CheckOption) []FlowResult {
	t.Helper()
	opts = append([]CheckOption{WithTimeout(time.Second), WithRetries(1)}, opts...)
	res, err := CheckFlowData(context.Background(), flows, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// FC-1, FC-2: the mapping and the plain outcomes.
func TestMapping(t *testing.T) {
	open, closed := listener(t), closedPort(t)
	tests := []struct {
		name   string
		flow   Flow
		status FlowStatus
		proto  string
		reason string // a substring
	}{
		{"tcp open", Flow{Name: "db", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(open)}, Reachable, "tcp", ""},
		{"tcp closed", Flow{Name: "db", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(closed)}, Unreachable, "tcp", ""},
		{"udp to a closed local port is refused", Flow{Name: "dns", Protocol: "UDP", Destination: "127.0.0.1", Ports: single(closed)}, Unreachable, "udp", ""},
		{"cidr skipped", Flow{Name: "net", Protocol: "TCP", Destination: "10.0.0.0/24", Ports: single(443)}, Skipped, "", "CIDR"},
		{"range skipped", Flow{Name: "rng", Protocol: "TCP", Destination: "127.0.0.1", Ports: []PortRange{{Low: 1521, High: 1530}}}, Skipped, "", "range"},
		{"tls on a bare ip skipped", Flow{Name: "tls", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(open), TLS: true}, Skipped, "", "name"},
		{"unknown protocol skipped", Flow{Name: "x", Protocol: "SCTP", Destination: "127.0.0.1", Ports: single(open)}, Skipped, "", "protocol"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := run(t, one(tt.flow))
			if len(res) != 1 {
				t.Fatalf("got %d results: %+v", len(res), res)
			}
			r := res[0]
			if r.Status != tt.status {
				t.Fatalf("status %s (%s, %v), want %s", r.Status, r.Reason, r.Err, tt.status)
			}
			if tt.proto != "" && r.Protocol != tt.proto {
				t.Errorf("protocol %q, want %q", r.Protocol, tt.proto)
			}
			if !strings.Contains(r.Reason, tt.reason) {
				t.Errorf("reason %q lacks %q", r.Reason, tt.reason)
			}
			if r.Binding != "b1" || r.Target != "ledger" || r.Flow != tt.flow.Name {
				t.Errorf("identity lost: %+v", r)
			}
		})
	}
}

// FC-1: two flows to the same address and kind are checked once and both are answered.
func TestSharedChecks(t *testing.T) {
	open := listener(t)
	f := Flow{Name: "a", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(open)}
	g := f
	g.Name = "b"
	res := run(t, []BindingFlows{{Binding: "b1", Target: "t1", Flows: []Flow{f}}, {Binding: "b2", Target: "t2", Flows: []Flow{g}}})
	if len(res) != 2 || res[0].Status != Reachable || res[1].Status != Reachable {
		t.Fatalf("got %+v", res)
	}
	if res[0].Binding != "b1" || res[1].Binding != "b2" {
		t.Errorf("order or identity lost: %+v", res)
	}
}

// FC-1: a flow with several ports gets one result per port.
func TestSeveralPorts(t *testing.T) {
	open, closed := listener(t), closedPort(t)
	res := run(t, one(Flow{Name: "db", Protocol: "TCP", Destination: "127.0.0.1", Ports: []PortRange{{Low: open, High: open}, {Low: closed, High: closed}}}))
	if len(res) != 2 || res[0].Port != open || res[0].Status != Reachable || res[1].Port != closed || res[1].Status != Unreachable {
		t.Fatalf("got %+v", res)
	}
}

// FC-3: TLS against the system roots, the given roots and the wrong name.
func TestTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	flow := Flow{Name: "api", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(port(t, srv.Listener.Addr().String())), TLS: true, ServerName: "example.com"}

	if r := run(t, one(flow), WithRoots(pool))[0]; r.Status != Reachable || r.Protocol != "tls" {
		t.Errorf("with the roots: %+v", r)
	}
	if r := run(t, one(flow))[0]; r.Status != Unreachable {
		t.Errorf("with the system roots the test certificate must not verify: %+v", r)
	}
	flow.ServerName = "other.example.org"
	if r := run(t, one(flow), WithRoots(pool))[0]; r.Status != Unreachable {
		t.Errorf("a wrong name must not verify: %+v", r)
	}
}

// FC-4: a denied network is skipped, by default for link-local and metadata addresses.
func TestDeniedNetworks(t *testing.T) {
	flow := Flow{Name: "meta", Protocol: "TCP", Destination: "169.254.169.254", Ports: single(80)}
	r := run(t, one(flow))[0]
	if r.Status != Skipped || !strings.Contains(r.Reason, "denied") {
		t.Errorf("default: %+v", r)
	}
	open := listener(t)
	local := Flow{Name: "l", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(open)}
	r = run(t, one(local), WithDeniedNetworks(mustPrefix(t, "127.0.0.0/8")))[0]
	if r.Status != Skipped || !strings.Contains(r.Reason, "denied") {
		t.Errorf("explicit: %+v", r)
	}
	if r := run(t, one(flow), WithDeniedNetworks())[0]; r.Status == Skipped {
		t.Errorf("an empty list removes the default: %+v", r)
	}
}

// FC-5: the context ends the run.
func TestContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := CheckFlowData(ctx, one(Flow{Name: "db", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(listener(t))}))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Status != Skipped || !strings.Contains(res[0].Reason, "interrupted") {
		t.Errorf("got %+v", res)
	}
}

// FC-6: more checks than the limit are refused.
func TestLimit(t *testing.T) {
	var flows []Flow
	for i := 0; i < MaxFlowChecks+1; i++ {
		flows = append(flows, Flow{Name: "f" + strconv.Itoa(i), Protocol: "TCP", Destination: "127.0.0." + strconv.Itoa(i%250+1), Ports: single(1000 + i)})
	}
	_, err := CheckFlowData(context.Background(), one2(flows))
	if !errors.Is(err, ErrTooManyFlows) {
		t.Fatalf("got %v", err)
	}
}

func one2(f []Flow) []BindingFlows {
	return []BindingFlows{{Binding: "b", Target: "t", Flows: f}}
}

// flowFake is a transport that answers with fixed flows and bindings.
type flowFake struct {
	flows    []BindingFlows
	bindings []Binding
	err      error
	got      Filter
}

func (f *flowFake) bindings_(context.Context, Filter, string) ([]Binding, string, bool, error) {
	return f.bindings, "", false, f.err
}

func (f *flowFake) flows_(_ context.Context, fl Filter, _ string) ([]BindingFlows, string, bool, error) {
	f.got = fl
	return f.flows, "", false, f.err
}

func (f *flowFake) close() error { return nil }

// flowTransport adapts flowFake to the transport interface.
type flowTransport struct{ *flowFake }

func (f flowTransport) bindings(ctx context.Context, fl Filter, e string) ([]Binding, string, bool, error) {
	return f.bindings_(ctx, fl, e)
}

func (f flowTransport) flows(ctx context.Context, fl Filter, e string) ([]BindingFlows, string, bool, error) {
	return f.flows_(ctx, fl, e)
}

// FC-7, FC-13: CheckFlows asks for the flows of the filter and chooses the handshakes
// from what the client knows.
func TestCheckFlows(t *testing.T) {
	v := newEnv(t)
	// ligo's own flow: an SVID of the client's trust domain, with no DNS name
	svid := v.svid(t, ligoID)
	l, err := tls.Listen("tcp", "127.0.0.1:0", tlsconfig.TLSServerConfig(svid))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	pg := pgServer(t, srv.TLS.Certificates[0])

	flows := []BindingFlows{{Binding: "b1", Target: "ledger", Flows: []Flow{
		{Name: "ledger", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(pg), TLS: true, ServerName: "example.com", DeclaredBy: "target:ledger"},
		{Name: "ligo-workload-api", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(port(t, l.Addr().String())), TLS: true, DeclaredBy: "ligo"},
		{Name: "vault", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(listener(t)), DeclaredBy: "secret-store:vault"},
	}}}
	fake := &flowFake{flows: flows, bindings: []Binding{{Name: "b1", PlatformType: "postgres.v1"}}}
	c, err := New(t.Context(), Config{Address: "ligo.lab:8443", ServerID: ligoID, X509Source: v.source})
	if err != nil {
		t.Fatal(err)
	}
	c.transport = flowTransport{fake}
	res, err := c.CheckFlows(t.Context(), Filter{Target: "ledger"}, WithRoots(pool), WithTimeout(time.Second), WithRetries(1))
	if err != nil || fake.got.Target != "ledger" || len(res) != 3 {
		t.Fatalf("got %+v, %v, filter %+v", res, err, fake.got)
	}
	want := map[string]string{"ledger": "postgresql", "ligo-workload-api": "spire", "vault": "tcp"}
	for _, r := range res {
		if r.Status != Reachable || r.Protocol != want[r.Flow] {
			t.Errorf("%s: %+v, want a %s check that is reachable", r.Flow, r, want[r.Flow])
		}
	}

	// another platform: the flow is a plain TLS check, which a PostgreSQL server fails
	fake.bindings = []Binding{{Name: "b1", PlatformType: "oracle.v1"}}
	res, err = c.CheckFlows(t.Context(), Filter{Target: "ledger"}, WithRoots(pool), WithTimeout(time.Second), WithRetries(1))
	if err != nil || res[0].Protocol != "tls" || res[0].Status != Unreachable {
		t.Errorf("another platform: %+v, %v", res[0], err)
	}

	fake.err = ErrUnavailable
	if _, err := c.CheckFlows(t.Context(), Filter{}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("got %v", err)
	}
}

// FC-9: WithICMP adds one echo check per distinct host. Where the process may
// not open ICMP sockets the result says so, naming the capability.
func TestICMP(t *testing.T) {
	open := listener(t)
	f := Flow{Name: "a", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(open)}
	g := f
	g.Name = "b"
	res := run(t, one2([]Flow{f, g}), WithICMP(false))
	var icmp []FlowResult
	for _, r := range res {
		if r.Protocol == "icmp" {
			icmp = append(icmp, r)
		}
	}
	if len(res) != 3 || len(icmp) != 1 {
		t.Fatalf("want two tcp results and one icmp: %+v", res)
	}
	if icmp[0].Status == Unreachable && !strings.Contains(icmp[0].Reason, "cap_net_raw") {
		t.Errorf("a refused ICMP must name the capability: %+v", icmp[0])
	}
}

// FlowResults helpers.
func TestResults(t *testing.T) {
	r := FlowResults{{Status: Reachable}, {Status: Skipped}}
	if !r.OK() || len(r.Unreachable()) != 0 {
		t.Errorf("reachable and skipped are OK: %+v", r)
	}
	r = append(r, FlowResult{Status: Unreachable})
	if r.OK() || len(r.Unreachable()) != 1 {
		t.Errorf("an unreachable flow is not OK: %+v", r)
	}
}

// FC-8: the logger gets binding, flow, destination, port and status, and nothing else.
func TestLogKeys(t *testing.T) {
	var keys = map[string]bool{}
	run(t, one(Flow{Name: "db", Protocol: "TCP", Destination: "127.0.0.1", Ports: single(listener(t))}), WithLogger(recordKeys(keys)))
	for k := range keys {
		switch k {
		case "binding", "flow", "destination", "port", "status", "protocol", "reason", "error":
		default:
			t.Errorf("unexpected log key %q", k)
		}
	}
	if len(keys) == 0 {
		t.Error("nothing was logged")
	}
}

func FuzzMapping(f *testing.F) {
	f.Add("TCP", "db.example.org", 5432, 5432, true, "db.example.org")
	f.Add("UDP", "10.0.0.0/8", 53, 60, false, "")
	f.Add("", "", 0, -1, true, "")
	f.Fuzz(func(t *testing.T, proto, dest string, low, high int, tls bool, name string) {
		_ = plan(BindingFlows{Binding: "b", Target: "t", Flows: []Flow{{
			Name: "f", Protocol: proto, Destination: dest, Ports: []PortRange{{Low: low, High: high}}, TLS: tls, ServerName: name}}}, nil)
	})
}

func BenchmarkPlan(b *testing.B) {
	var flows []Flow
	for i := 0; i < 32; i++ {
		flows = append(flows, Flow{Name: "f" + strconv.Itoa(i), Protocol: "TCP", Destination: "db" + strconv.Itoa(i) + ".example.org", Ports: single(5432), TLS: true})
	}
	bf := one2(flows)[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = plan(bf, nil)
	}
}
