package pluginsdk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc/codes"
)

const testID = "spiffe://prod.lab/ligo/plugin/test"

// agentSocket serves one SVID, testID, on a fresh socket.
func agentSocket(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sdk") // t.TempDir can exceed a unix socket's path length
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ca := spiffetest.NewCA(t, "prod.lab")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	agent := &spiffetest.Agent{Key: key, SVIDs: []*workload.X509SVID{ca.SVID(t, testID)},
		Bundles: map[string][]byte{"prod.lab": ca.Cert.Raw}}
	return agent.Serve(t, dir, "prod")
}

func descriptor(name, match string) *pluginv1.InstanceDescriptor {
	return &pluginv1.InstanceDescriptor{Name: name, TrustDomain: "prod.lab",
		SvidSelector: &pluginv1.SVIDSelectorConfig{MatchExpr: match}}
}

// TestSelectInstance: one instance's SVID is resolved; a selector matching
// nothing is SVID_SELECTION_FAILED, a malformed one INVALID_SELECTOR.
func TestSelectInstance(t *testing.T) {
	socket := agentSocket(t)
	sel, id, err := SelectInstance(t.Context(), socket, descriptor("a", `path == "/ligo/plugin/test"`))
	if err != nil || sel == nil || id != testID {
		t.Fatalf("got %v %q %v", sel, id, err)
	}
	for match, code := range map[string]string{`path == "/none"`: "SVID_SELECTION_FAILED", `path ==`: "INVALID_SELECTOR"} {
		_, _, err := SelectInstance(t.Context(), socket, descriptor("a", match))
		if c, d := FromError(err); c != codes.InvalidArgument && c != codes.FailedPrecondition || d.GetCode() != code {
			t.Errorf("%s: got %v %v", match, c, d)
		}
	}
}

// TestWorkloadClientShared: every call for one socket uses one Workload API
// client, so repeated configuration opens no new connection.
func TestWorkloadClientShared(t *testing.T) {
	socket := agentSocket(t)
	a, err := WorkloadAPIClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	b, err := WorkloadAPIClient(socket)
	if err != nil || a != b {
		t.Fatalf("two clients for one socket: %p %p %v", a, b, err)
	}
	r := &pluginv1.ConfigureInstancesRequest{SpiffeWorkloadSocket: socket,
		Instances: []*pluginv1.InstanceDescriptor{descriptor("a", `path == "/ligo/plugin/test"`)}}
	for range 3 {
		if _, out, err := SelectInstances(t.Context(), r); err != nil || len(out.GetResolved()) != 1 {
			t.Fatalf("got %v %v", out, err)
		}
	}
	if c, _ := WorkloadAPIClient(socket); c != a {
		t.Error("SelectInstances opened another client")
	}
}

// TestParseRoots: no PEM is the system roots (nil); text with no certificate
// is refused, naming ca_pem.
func TestParseRoots(t *testing.T) {
	if r, err := ParseRoots(""); r != nil || err != nil {
		t.Errorf("empty: %v %v", r, err)
	}
	ca := spiffetest.NewCA(t, "prod.lab")
	good := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw}))
	if r, err := ParseRoots(good); r == nil || err != nil {
		t.Errorf("good: %v %v", r, err)
	}
	if _, err := ParseRoots("not a certificate"); err == nil || !strings.Contains(err.Error(), "ca_pem") {
		t.Errorf("bad: %v", err)
	}
}

// TestEndpoint: a URL's host:port, with the scheme's default port.
func TestEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"https://vault.lab:8200":     "vault.lab:8200",
		"https://vault.lab":          "vault.lab:443",
		"ldaps://ldap.lab":           "ldap.lab:636",
		"ldap://ldap.lab":            "ldap.lab:389",
		"ldaps://[2001:db8::1]:1636": "[2001:db8::1]:1636",
	} {
		if got, err := Endpoint(in); got != want || err != nil {
			t.Errorf("%s: got %q %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"vault.lab:8200", "https://", "ftp://x", "%"} {
		if got, err := Endpoint(in); err == nil {
			t.Errorf("%s: got %q, want an error", in, got)
		}
	}
	c := BootstrapCredentialConfig{Address: "https://vault.lab:8200"}
	if got, err := c.Endpoint(); got != "vault.lab:8200" || err != nil {
		t.Errorf("bootstrap: %q %v", got, err)
	}
}

// TestValidateInstance: the check's endpoints and the selected SVID are the
// answer; a check that fails is INVALID_CONFIG, naming the instance, and no
// SVID is selected for it.
func TestValidateInstance(t *testing.T) {
	socket := agentSocket(t)
	r := &pluginv1.ValidateInstanceRequest{SpiffeWorkloadSocket: socket, Instance: descriptor("a", `path == "/ligo/plugin/test"`)}
	ok := func(*pluginv1.InstanceDescriptor) ([]string, error) { return []string{"db.lab:5432"}, nil }
	got, err := ValidateInstance(t.Context(), r, ok)
	if err != nil || got.GetSpiffeId() != testID || len(got.GetEndpoints()) != 1 || got.GetEndpoints()[0] != "db.lab:5432" {
		t.Fatalf("got %v %v", got, err)
	}
	bad := func(*pluginv1.InstanceDescriptor) ([]string, error) { return nil, errors.New("host is required") }
	r.SpiffeWorkloadSocket = "unix:///nonexistent" // the check comes first: no agent is reached
	_, err = ValidateInstance(t.Context(), r, bad)
	if c, d := FromError(err); c != codes.InvalidArgument || d.GetCode() != "INVALID_CONFIG" || !strings.Contains(d.GetPublicMessage(), "instance a: host is required") {
		t.Errorf("got %v %v", c, d)
	}
}
