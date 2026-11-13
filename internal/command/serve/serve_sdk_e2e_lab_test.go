//go:build lab

package serve

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/pkg/client"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// mintedSVID is the workload's X.509-SVID that lab.sh minted, with the
// prod.lab bundle.
type mintedSVID struct {
	*x509svid.SVID
	*x509bundle.Bundle
}

// mintedJWT serves the JWT-SVID that lab.sh minted for the secrets backend.
type mintedJWT struct{ file string }

func (m mintedJWT) FetchJWTSVID(_ context.Context, p jwtsvid.Params) (*jwtsvid.SVID, error) {
	token, err := os.ReadFile(m.file)
	if err != nil {
		return nil, err
	}
	return jwtsvid.ParseInsecure(strings.TrimSpace(string(token)), []string{p.Audience})
}

// sdkClient is the Go client SDK as the workload, on transport.
func sdkClient(t *testing.T, transport client.Transport) *client.Client {
	t.Helper()
	dir := e2eEnv(t, "LIGO_E2E_DIR")
	svid, err := x509svid.Load(filepath.Join(dir, "workload-svid.pem"), filepath.Join(dir, "workload-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := x509bundle.Load(spiffeid.RequireTrustDomainFromString("prod.lab"), filepath.Join(dir, "workload-bundle.pem"))
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(e2eEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	storeRoots := x509.NewCertPool()
	storeRoots.AppendCertsFromPEM(pem)
	c, err := client.New(t.Context(), client.Config{Address: strings.TrimPrefix(e2eEnv(t, "LIGO_E2E_WORKLOAD"), "https://"),
		ServerID: "spiffe://prod.lab/ns/sys/sa/ligo", Transport: transport, X509Source: mintedSVID{svid, bundle},
		JWTSource: mintedJWT{filepath.Join(dir, "workload-store-jwt")}, StoreRoots: storeRoots, PollInterval: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestServeClientSDK: CS-L2 and CS-L3 (.specs/ligo-client-sdk.md). A
// workload that watches with the Go client SDK sees a vault-dynamic binding
// appear and receives a credential that connects; over gRPC it reads the
// same binding and its flows; once the binding is revoked the watch reports
// it, a new credential is refused and the old one is gone.
func TestServeClientSDK(t *testing.T) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	source := topologySource(t, olga, dora, "sdk-src-"+x, "prod.lab", "spiffe://prod.lab/ns/e2e/sa/w"+x)
	target := topologyTarget(t, olga, dora, "sdk-ledger-"+x, "pg-ledger-dynamic", "dc/corp-prod/ledger")
	binding := "sdk-" + x

	events := make(chan client.Event, 16)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	watcher := sdkClient(t, client.REST)
	go func() {
		_ = watcher.Watch(ctx, client.Filter{Target: target, WatchCredentials: true}, func(ev client.Event) { events <- ev })
	}()
	next := func(want client.EventKind) client.Event {
		t.Helper()
		deadline := time.After(120 * time.Second)
		for {
			select {
			case ev := <-events:
				if ev.Kind == client.CredentialRotated && want != client.CredentialRotated {
					continue // a lease ran on while the test did something else
				}
				if ev.Kind != want {
					t.Fatalf("event %s, want %s", ev.Kind, want)
				}
				return ev
			case <-deadline:
				t.Fatalf("no %s event after 120s", want)
				return client.Event{}
			}
		}
	}

	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": binding, "source": source, "target": target, "accessLevel": "read"})
	if code != http.StatusAccepted {
		t.Fatalf("binding: %d %v", code, filed)
	}
	approveAll(t, dora, filed)
	b := phase(t, olga, binding, "ACTIVE")

	added := next(client.Added)
	if added.Binding.Name != binding || added.Binding.Target != target || added.Binding.Auth.Strategy != "vault-dynamic" || added.Binding.Endpoint() == "" {
		t.Errorf("Added: %+v", added.Binding)
	}
	rotated := next(client.CredentialRotated)
	cred := rotated.Credential
	// the platform's credential_ttl, 90s, not the hour of plugins.dynamic_credentials
	if lease := time.Until(cred.Expires); lease < time.Minute || lease > 90*time.Second {
		t.Errorf("the credential expires in %s", lease)
	}
	record(t, cred.Password)
	reads(t, cred.Username, cred.Password)
	if strings.Contains(fmt.Sprint(rotated), cred.Password) {
		t.Error("an event prints its password")
	}

	// the other transport gives the same binding, and its flows
	grpc := sdkClient(t, client.GRPC)
	same, err := grpc.Bindings(t.Context(), client.Filter{Target: target})
	if err != nil || len(same) != 1 || !reflect.DeepEqual(same[0], added.Binding) {
		t.Errorf("gRPC: %+v (%v), REST: %+v", same, err, added.Binding)
	}
	flows, err := grpc.Flows(t.Context(), client.Filter{Target: target})
	if err != nil || len(flows) != 1 || len(flows[0].Flows) == 0 {
		t.Errorf("flows: %+v (%v)", flows, err)
	}
	// a second read makes a second credential, which connects too
	second, err := grpc.Credential(t.Context(), same[0])
	if err != nil || second.Username == cred.Username {
		t.Fatalf("a second credential: %s (%v)", second.Username, err)
	}
	record(t, second.Password)
	reads(t, second.Username, second.Password)

	// at two thirds of the lease the watch reads a new credential, which connects
	started := time.Now()
	renewed := next(client.CredentialRotated).Credential
	if renewed.Username == cred.Username || time.Since(started) > 80*time.Second {
		t.Errorf("the renewed credential %s after %s", renewed.Username, time.Since(started))
	}
	record(t, renewed.Password)
	reads(t, renewed.Username, renewed.Password)

	revoke(t, olga, dora, binding, b)
	if gone := next(client.Removed); gone.Previous.Name != binding {
		t.Errorf("Removed: %+v", gone.Previous)
	}
	grpc.Invalidate(same[0])
	if _, err := grpc.Credential(t.Context(), same[0]); !errors.Is(err, client.ErrStore) {
		t.Errorf("a credential of a revoked binding: %v", err)
	}
	for _, c := range []client.Credential{cred, second, renewed} {
		if conn, err := ledgerConn(t, c.Username, c.Password); err == nil {
			_ = conn.Close(context.Background())
			t.Errorf("the credential %s of a revoked binding still connects", c.Username)
		}
	}
	if list, err := grpc.Bindings(t.Context(), client.Filter{Target: target}); err != nil || len(list) != 0 {
		t.Errorf("after the revocation: %+v (%v)", list, err)
	}
}

// record appends a password to the file lab.sh searches the logs with
// (INV-03).
func record(t *testing.T, password string) {
	t.Helper()
	f, err := os.OpenFile(e2eEnv(t, "LIGO_E2E_SECRETS"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := fmt.Fprintln(f, password); err != nil {
		t.Fatal(err)
	}
}
