package workloadhttp

import (
	"crypto/x509"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/resolution"
	"github.com/dihedron/ligo/pkg/client"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// TestClientSDKTransports is CS-5 (.specs/ligo-client-sdk.md): against the
// real handler, the SDK's REST and gRPC transports return equal bindings
// and flows, and both are answered "not modified" for the ETag they hold.
func TestClientSDKTransports(t *testing.T) {
	v, f, _ := apiSetup(t)
	w := v.ca.SVID(t, worker)
	svid, err := x509svid.ParseRaw(w.GetX509Svid(), w.GetX509SvidKey())
	if err != nil {
		t.Fatal(err)
	}
	source := struct {
		*x509svid.SVID
		*x509bundle.Bundle
	}{svid, x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("prod.lab"), []*x509.Certificate{v.ca.Cert})}
	var bindings [][]client.Binding
	var flows [][]client.BindingFlows
	for _, transport := range []client.Transport{client.REST, client.GRPC} {
		c, err := client.New(t.Context(), client.Config{Address: strings.TrimPrefix(v.srv.URL, "https://"), ServerID: "spiffe://prod.lab/ns/sys/sa/ligo",
			Transport: transport, X509Source: source})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		for range 2 { // the second call holds the ETag
			b, err := c.Bindings(t.Context(), client.Filter{Target: "ledger-schema", PlatformType: "oracle.v1"})
			if err != nil || len(b) != 1 || b[0].Name != "workers-ledger" || b[0].Revision != 4 || b[0].Spec["host"] != "ledger-db" || b[0].Auth.StoreInstance != "vault-prod" {
				t.Fatalf("%s: bindings %+v (%v)", transport, b, err)
			}
			if f.target != "ledger-schema" || f.ptype != "oracle.v1" {
				t.Errorf("%s: filters %q %q", transport, f.target, f.ptype)
			}
			fl, err := c.Flows(t.Context(), client.Filter{})
			if err != nil || len(fl) != 1 || len(fl[0].Flows) == 0 {
				t.Fatalf("%s: flows %+v (%v)", transport, fl, err)
			}
			bindings, flows = append(bindings, b), append(flows, fl)
		}
	}
	for i := 1; i < len(bindings); i++ {
		if !reflect.DeepEqual(bindings[0], bindings[i]) || !reflect.DeepEqual(flows[0], flows[i]) {
			t.Errorf("answer %d differs:\n%+v\n%+v\n%+v\n%+v", i, bindings[0], bindings[i], flows[0], flows[i])
		}
	}
	f.err = resolution.ErrStale
	for _, transport := range []client.Transport{client.REST, client.GRPC} {
		c, err := client.New(t.Context(), client.Config{Address: strings.TrimPrefix(v.srv.URL, "https://"), ServerID: "spiffe://prod.lab/ns/sys/sa/ligo",
			Transport: transport, X509Source: source})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		if _, err := c.Bindings(t.Context(), client.Filter{}); !errors.Is(err, client.ErrUnavailable) {
			t.Errorf("%s: stale: %v", transport, err)
		}
	}
}
