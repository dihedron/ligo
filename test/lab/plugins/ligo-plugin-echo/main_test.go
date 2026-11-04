package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/spiffetest"
	"github.com/dihedron/ligo/test/lab/plugins/labkit"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

const (
	serverID  = "spiffe://prod.lab/ns/lab/sa/echo-server"
	pluginID  = "spiffe://prod.lab/ligo/plugin/echo"
	bindingID = "01a19270-0000-7000-8000-000000000001"
	regex     = `^spiffe://prod\.lab/ns/echo/sa/bound$`
)

// fake is the echo server's control API: it records the calls and keeps
// the users.
type fake struct {
	mu    sync.Mutex
	calls []string
	users map[string]string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	f.calls = append(f.calls, r.Method+" "+r.URL.Path+" "+string(body))
	name, isUser := strings.CutPrefix(r.URL.Path, "/users/")
	switch {
	case isUser && r.Method == http.MethodGet:
		if _, ok := f.users[name]; !ok {
			http.NotFound(w, r)
			return
		}
	case isUser && r.Method == http.MethodPut:
		var b struct{ Password string }
		_ = json.Unmarshal(body, &b)
		f.users[name] = b.Password
	case isUser && r.Method == http.MethodDelete:
		delete(f.users, name)
	}
	w.WriteHeader(http.StatusNoContent)
}

func svid(t *testing.T, ca *spiffetest.CA, id string) *x509svid.SVID {
	t.Helper()
	w := ca.SVID(t, id)
	s, err := x509svid.ParseRaw(w.GetX509Svid(), w.GetX509SvidKey())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// setup is a plugin with one instance in mode against a fake control API
// presenting serverAs.
func setup(t *testing.T, mode, serverAs string) (*plugin, *fake) {
	t.Helper()
	ca := spiffetest.NewCA(t, "prod.lab")
	bundle := x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("prod.lab"), []*x509.Certificate{ca.Cert})
	f := &fake{users: map[string]string{}}
	srv := httptest.NewUnstartedServer(f)
	server := svid(t, ca, serverAs)
	srv.TLS = tlsconfig.MTLSServerConfig(server, bundle, tlsconfig.AuthorizeID(spiffeid.RequireFromString(pluginID)))
	// httptest adds its own certificate when Certificates is empty, which crypto/tls prefers without SNI
	cert, err := tlsconfig.GetCertificate(server)(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS.Certificates, srv.TLS.GetCertificate = []tls.Certificate{*cert}, nil
	srv.StartTLS()
	t.Cleanup(srv.Close)
	own := svid(t, ca, pluginID)
	in := &instance{Instance: &labkit.Instance{Name: "echo",
		X509:    func(context.Context) (*x509svid.SVID, error) { return own, nil },
		Bundles: func(context.Context) (*x509bundle.Set, error) { return x509bundle.NewSet(bundle), nil }},
		config: config{DataAddress: "ligo1.ligo.lab:7101", ControlAddress: strings.TrimPrefix(srv.URL, "https://"), ServerID: serverID, Mode: mode}}
	if err := in.check(modes[mode]); err != nil {
		t.Fatal(err)
	}
	in.control = in.controlClient()
	return &plugin{instances: map[string]*instance{"echo": in}}, f
}

func binding(rotate bool) *pluginv1.BindingContext {
	return &pluginv1.BindingContext{BindingId: bindingID, SourceSvidRegex: regex, DerivedPrincipalName: "bnd_0123456789abcdef", RotateStaticSecrets: rotate}
}

// TestConfig: the mode must agree with the platform's identity mode, and
// the addresses and the server ID must be well formed.
func TestConfig(t *testing.T) {
	good := config{DataAddress: "h:1", ControlAddress: "h:2", ServerID: serverID, Mode: "svid"}
	for name, c := range map[string]struct {
		cfg  config
		mode pluginv1.IdentityMode
	}{
		"mode disagrees":  {good, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL},
		"unknown mode":    {config{DataAddress: "h:1", ControlAddress: "h:2", ServerID: serverID, Mode: "x"}, pluginv1.IdentityMode_IDENTITY_MODE_SVID},
		"no port":         {config{DataAddress: "h", ControlAddress: "h:2", ServerID: serverID, Mode: "svid"}, pluginv1.IdentityMode_IDENTITY_MODE_SVID},
		"not a SPIFFE ID": {config{DataAddress: "h:1", ControlAddress: "h:2", ServerID: "nope", Mode: "svid"}, pluginv1.IdentityMode_IDENTITY_MODE_SVID},
	} {
		if err := (&instance{config: c.cfg}).check(c.mode); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := (&instance{config: good}).check(pluginv1.IdentityMode_IDENTITY_MODE_SVID); err != nil {
		t.Error(err)
	}
}

// TestValidate: an empty definition and grants; every level grants echo;
// the spec names the server.
func TestValidate(t *testing.T) {
	p, _ := setup(t, "svid", serverID)
	ctx := context.Background()
	resp, err := p.ValidateTarget(ctx, &pluginv1.ValidateTargetRequest{Instance: "echo", DefinitionJson: []byte("{}"),
		AccessLevels: []*pluginv1.AccessLevelInput{{Name: "echo", GrantsJson: []byte("{}")}}})
	if err != nil || !resp.GetValid() || resp.GetAccessLevels()[0].GetPrivileges()[0] != "echo" {
		t.Errorf("valid target: %v %v", resp, err)
	}
	if resp, _ := p.ValidateTarget(ctx, &pluginv1.ValidateTargetRequest{Instance: "echo", DefinitionJson: []byte(`{"x":1}`)}); resp.GetValid() {
		t.Error("a definition was accepted")
	}
	b, err := p.ValidateBinding(ctx, &pluginv1.ValidateBindingRequest{Instance: "echo"})
	if err != nil || string(b.GetRequestedSpecJson()) != `{"host":"ligo1.ligo.lab","port":7101,"serverId":"`+serverID+`","mode":"svid"}` {
		t.Errorf("binding: %s %v", b.GetRequestedSpecJson(), err)
	}
	if b, _ := p.ValidateBinding(ctx, &pluginv1.ValidateBindingRequest{Instance: "echo", ParametersJson: []byte(`{"x":1}`)}); b.GetValid() {
		t.Error("parameters were accepted")
	}
}

// TestSVIDMode: the binding's regex goes on the access list and comes off;
// another identity mode is refused.
func TestSVIDMode(t *testing.T) {
	p, f := setup(t, "svid", serverID)
	ctx := context.Background()
	svidMode := &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_SVID}
	resp, err := p.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "echo", Binding: binding(false), Identity: svidMode})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.GetFinalizedClientSpecJson()) != `{"endpoint":"ligo1.ligo.lab:7101","mode":"svid","serverId":"`+serverID+`"}` ||
		resp.GetSecretPayload().GetMode() != pluginv1.IdentityMode_IDENTITY_MODE_SVID || resp.GetSecretPayload().GetPayload() != nil {
		t.Errorf("ensure: %s %v", resp.GetFinalizedClientSpecJson(), resp.GetSecretPayload())
	}
	if _, err := p.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "echo", Binding: binding(false)}); err != nil {
		t.Fatal(err)
	}
	want := []string{"PUT /acl/" + bindingID + ` {"regex":"` + strings.ReplaceAll(regex, `\`, `\\`) + `"}`, "DELETE /acl/" + bindingID + " "}
	if strings.Join(f.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls %q, want %q", f.calls, want)
	}
	local := &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL}
	if _, err := p.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "echo", Binding: binding(false), Identity: local}); err == nil {
		t.Error("TARGET_LOCAL accepted by an svid server")
	}
}

// TestPasswordMode: a new user gets a password the store keeps; it stays
// until rotated; cleanup removes the user.
func TestPasswordMode(t *testing.T) {
	p, f := setup(t, "password", serverID)
	ctx := context.Background()
	local := &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL}
	ensure := func(rotate bool) *pluginv1.EnsureTargetResponse {
		t.Helper()
		resp, err := p.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "echo", Binding: binding(rotate), Identity: local})
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	first := ensure(false)
	secret := first.GetSecretPayload().GetStaticSecret()
	if secret.GetUsername() != "bnd_0123456789abcdef" || len(secret.GetPassword()) < 32 || f.users["bnd_0123456789abcdef"] != secret.GetPassword() ||
		!strings.Contains(string(first.GetFinalizedClientSpecJson()), `"user":"bnd_0123456789abcdef"`) {
		t.Fatalf("first: %v %s", first.GetSecretPayload(), first.GetFinalizedClientSpecJson())
	}
	if again := ensure(false); !again.GetSecretPayload().GetSecretUnchanged() || again.GetSecretPayload().GetStaticSecret() != nil {
		t.Errorf("again: %v", again.GetSecretPayload())
	}
	if rotated := ensure(true).GetSecretPayload().GetStaticSecret(); rotated.GetPassword() == secret.GetPassword() || f.users["bnd_0123456789abcdef"] != rotated.GetPassword() {
		t.Error("rotation kept the password")
	}
	if _, err := p.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "echo", Binding: binding(false)}); err != nil || len(f.users) != 0 {
		t.Errorf("cleanup: %v %v", err, f.users)
	}
	if _, err := p.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "echo", Binding: binding(false)}); err != nil {
		t.Errorf("cleanup again: %v", err)
	}
}

// TestServerIdentity: the plugin talks only to the server it was told.
func TestServerIdentity(t *testing.T) {
	p, f := setup(t, "svid", "spiffe://prod.lab/ns/lab/sa/impostor")
	_, err := p.EnsureTarget(context.Background(), &pluginv1.EnsureTargetRequest{Instance: "echo", Binding: binding(false),
		Identity: &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_SVID}})
	if err == nil || len(f.calls) != 0 {
		t.Errorf("an impostor server: %v %v", err, f.calls)
	}
}
