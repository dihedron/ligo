package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/go-ldap/ldap/v3"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc/codes"
)

const (
	pluginID = "spiffe://prod.lab/ligo/plugin/openldap"
	selector = `path == "/ligo/plugin/openldap"`
)

// world is what ConfigureInstances meets: a SPIRE agent, and a Vault whose
// certificate the instance's ca_file trusts, also for the directory.
type world struct {
	socket, caFile string
	vault          *httptest.Server
	bindUser       string
	vaultStatus    int
}

func newWorld(t *testing.T) *world {
	t.Helper()
	// t.TempDir can exceed the length of a unix socket's path
	dir, err := os.MkdirTemp("", "openldap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ca := spiffetest.NewCA(t, "prod.lab")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	agent := &spiffetest.Agent{Key: key, SVIDs: []*workload.X509SVID{ca.SVID(t, pluginID)},
		Bundles: map[string][]byte{"prod.lab": ca.Cert.Raw}}
	w := &world{socket: agent.Serve(t, dir, "prod"), bindUser: "cn=ligo-bootstrap,dc=ligo,dc=lab", vaultStatus: http.StatusOK}
	w.vault = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.vaultStatus != http.StatusOK {
			rw.WriteHeader(w.vaultStatus)
			return
		}
		if r.Method == http.MethodPost {
			_ = json.NewEncoder(rw).Encode(map[string]any{"auth": map[string]string{"client_token": "t"}})
			return
		}
		_ = json.NewEncoder(rw).Encode(map[string]any{"data": map[string]any{"data": map[string]string{"username": w.bindUser, "password": "p"}}})
	}))
	t.Cleanup(w.vault.Close)
	w.caFile = filepath.Join(dir, "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.vault.Certificate().Raw})
	if err := os.WriteFile(w.caFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) instanceConfig(addr string) string {
	return fmt.Sprintf(`{"url":"ldaps://%s","service_ou_dn":%q,"allowed_endpoints":[%q],"ca_file":%q,
		"bootstrap_credential":{"source":"vault","address":%q,"auth_mount":"jwt-spiffe","role":"r","jwt_audience":"a","kv_path":"kv/data/b"}}`,
		addr, ou, addr, w.caFile, w.vault.URL)
}

func (w *world) configure(p *plugin, addr, match, trustDomain string) (*pluginv1.ConfigureInstancesResponse, error) {
	return p.ConfigureInstances(context.Background(), &pluginv1.ConfigureInstancesRequest{SpiffeWorkloadSocket: w.socket,
		Instances: []*pluginv1.InstanceDescriptor{{Name: "ldap-prod", TrustDomain: trustDomain, ConfigJson: w.instanceConfig(addr),
			SvidSelector: &pluginv1.SVIDSelectorConfig{MatchExpr: match, JwtAudience: []string{"a"}}}}})
}

// directoryAnswering is an ldaps listener that answers every bind with
// result, an LDAP result code; it knows no other operation.
func directoryAnswering(t *testing.T, w *world, result byte) string {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: w.vault.TLS.Certificates, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 512)
				if _, err := conn.Read(buf); err != nil {
					return
				}
				// LDAPMessage{id 1, BindResponse{result, "", ""}}; a client's first message is its bind
				_, _ = conn.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, result, 0x04, 0x00, 0x04, 0x00})
				_, _ = conn.Read(buf) // until the client closes
			}()
		}
	}()
	return l.Addr().String()
}

func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

// TestConfigure: a configured instance reports the SVID it selected, then
// reaches the directory with the credential Vault holds, over the ca_file's
// trust; each way of failing keeps its code (§6).
func TestConfigure(t *testing.T) {
	health := func(p *plugin) bool {
		r, err := p.Health(context.Background(), &pluginv1.HealthRequest{Instance: "ldap-prod"})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetServing()
	}
	w := newWorld(t)
	for name, tc := range map[string]struct {
		addr    string
		before  func()
		serving bool
		code    string
	}{
		"bind accepted":  {addr: directoryAnswering(t, w, byte(ldap.LDAPResultSuccess)), serving: true},
		"bind rejected":  {addr: directoryAnswering(t, w, byte(ldap.LDAPResultInvalidCredentials)), code: "BOOTSTRAP_CREDENTIAL_REJECTED"},
		"directory down": {addr: closedPort(t), code: "DIRECTORY_UNAVAILABLE"},
		"username not a DN": {addr: closedPort(t), code: "BOOTSTRAP_CREDENTIAL_UNAVAILABLE",
			before: func() { w.bindUser = "not a dn" }},
		"vault refuses": {addr: closedPort(t), code: "BOOTSTRAP_CREDENTIAL_UNAVAILABLE",
			before: func() { w.vaultStatus = http.StatusForbidden }},
	} {
		t.Run(name, func(t *testing.T) {
			w.bindUser, w.vaultStatus = "cn=ligo-bootstrap,dc=ligo,dc=lab", http.StatusOK
			if tc.before != nil {
				tc.before()
			}
			p := &plugin{}
			r, err := w.configure(p, tc.addr, selector, "prod.lab")
			if err != nil {
				t.Fatal(err)
			}
			if got := r.GetResolved(); len(got) != 1 || got[0].GetInstance() != "ldap-prod" || got[0].GetSpiffeId() != pluginID {
				t.Errorf("resolved %v", got)
			}
			if got := health(p); got != tc.serving {
				t.Errorf("serving = %v", got)
			}
			if tc.code != "" {
				if _, err := ensure(p, principal, true); !hasCode(err, tc.code) {
					t.Errorf("ensure: %v, want %s", err, tc.code)
				}
			}
		})
	}
}

// TestConfigureRefusals: a selector or an agent that does not give the
// instance its SVID leaves the previous instances in place.
func TestConfigureRefusals(t *testing.T) {
	w := newWorld(t)
	for name, tc := range map[string]struct {
		match, trustDomain string
		grpc               codes.Code
		code               string
	}{
		"selector does not compile": {"hint +", "prod.lab", codes.InvalidArgument, "INVALID_SELECTOR"},
		"selector matches nothing":  {`path == "/other"`, "prod.lab", codes.FailedPrecondition, "SVID_SELECTION_FAILED"},
		"foreign trust domain":      {selector, "test.lab", codes.FailedPrecondition, "SVID_SELECTION_FAILED"},
	} {
		t.Run(name, func(t *testing.T) {
			p := testPlugin(newFake(nil), nil)
			_, err := w.configure(p, closedPort(t), tc.match, tc.trustDomain)
			if c, code, _ := codeOf(err); c != tc.grpc || code != tc.code {
				t.Errorf("%v %s (%v)", c, code, err)
			}
			if _, err := p.instance("ldap-prod"); err != nil {
				t.Errorf("the previous instance is gone: %v", err)
			}
		})
	}
	_, err := (&plugin{}).ConfigureInstances(context.Background(), &pluginv1.ConfigureInstancesRequest{SpiffeWorkloadSocket: "not-a-socket",
		Instances: []*pluginv1.InstanceDescriptor{{Name: "ldap-prod", ConfigJson: w.instanceConfig(closedPort(t))}}})
	if c, code, retry := codeOf(err); c != codes.Unavailable || code != "WORKLOAD_API_UNAVAILABLE" || !retry {
		t.Errorf("no agent: %v %s %v (%v)", c, code, retry, err)
	}
}

// TestParseConfigCAFile: a file with no certificate is refused like a
// missing one, and the JSON must parse.
func TestParseConfigCAFile(t *testing.T) {
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("no certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	extra := fmt.Sprintf(`,"ca_file":%q`, empty)
	_, err := parseConfig([]byte(configJSON("ldaps://ldap.ligo.lab", ou, `["ldap.ligo.lab:636"]`, extra)))
	if err == nil || !strings.Contains(err.Error(), "ca_file") {
		t.Errorf("err = %v", err)
	}
	if _, err := parseConfig([]byte("{")); err == nil {
		t.Error("broken JSON accepted")
	}
}

// TestCleanupErrors: cleanup fails like ensure, and removes nothing it did
// not read.
func TestCleanupErrors(t *testing.T) {
	request := func(name string) *pluginv1.CleanupIdentityRequest {
		return &pluginv1.CleanupIdentityRequest{Instance: "ldap-prod", Binding: &pluginv1.BindingContext{BindingId: bindingID, DerivedPrincipalName: name}}
	}
	denied := ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("no"))
	ctx := context.Background()
	if _, err := (&plugin{}).CleanupIdentity(ctx, request(principal)); !hasCode(err, "UNKNOWN_INSTANCE") {
		t.Errorf("unknown instance: %v", err)
	}
	if _, err := testPlugin(newFake(nil), nil).CleanupIdentity(ctx, request("Not,A,Principal")); err == nil {
		t.Error("a name outside the grammar reached the directory")
	}
	if _, err := testPlugin(newFake(nil), denied).CleanupIdentity(ctx, request(principal)); !hasCode(err, "DIRECTORY_ACCESS_DENIED") {
		t.Errorf("dial: %v", err)
	}
	f := newFake(map[string][]string{dn: {mine}})
	f.readErr = denied
	if _, err := testPlugin(f, nil).CleanupIdentity(ctx, request(principal)); !hasCode(err, "DIRECTORY_ACCESS_DENIED") {
		t.Errorf("read: %v", err)
	}
	f = newFake(map[string][]string{dn: {mine}})
	f.delErr = denied
	if _, err := testPlugin(f, nil).CleanupIdentity(ctx, request(principal)); !hasCode(err, "DIRECTORY_ACCESS_DENIED") {
		t.Errorf("delete: %v", err)
	}
}
