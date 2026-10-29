package workflows

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestCall: retryable errors are retried with backoff up to the attempts,
// others fail at once; a PluginErrorDetail decides over the gRPC code, and
// only the code and public message are kept (§6.1 rules 3 to 5).
func TestCall(t *testing.T) {
	e := &Engine{Backoff: Backoff{Attempts: 3, Initial: time.Millisecond, Max: 2 * time.Millisecond}}
	for name, tc := range map[string]struct {
		err   error
		calls int
		code  string
	}{
		"retryable code":            {status.Error(codes.Unavailable, "down"), 3, "Unavailable"},
		"terminal code":             {status.Error(codes.PermissionDenied, "no"), 1, "PermissionDenied"},
		"detail retryable":          {pluginsdk.Error(codes.FailedPrecondition, "LOCKED", "busy", true), 3, "LOCKED"},
		"detail overrides the code": {pluginsdk.Error(codes.Unavailable, "GONE", "gone for good", false), 1, "GONE"},
	} {
		calls := 0
		err := e.call(context.Background(), func(context.Context) error { calls++; return tc.err })
		var se *StepError
		if calls != tc.calls || !errors.As(err, &se) || se.Code != tc.code {
			t.Errorf("%s: %d calls, %v", name, calls, err)
		}
	}
	calls := 0
	err := e.call(context.Background(), func(context.Context) error {
		if calls++; calls < 2 {
			return status.Error(codes.Unavailable, "blip")
		}
		return nil
	})
	if err != nil || calls != 2 {
		t.Errorf("recovered call: %d calls, %v", calls, err)
	}
	if se := sanitize(status.Error(codes.Internal, "SELECT password FROM users")); se.Message != "the plugin call failed" {
		t.Errorf("an internal message leaked: %q", se.Message)
	}
}

// TestManager: the adapter mediates every plugin call through the plugin
// manager (§5.3); here with the built-in identity provider and store, and a
// platform that is not configured.
func TestManager(t *testing.T) {
	zone := config.Zone{Name: "prod", TrustDomain: "prod.lab"}
	m := pluginmgr.New([]pluginmgr.Spec{
		{Type: "target-local.v1", Kind: pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, Builtin: true, Zone: zone,
			Instances: []*pluginv1.InstanceDescriptor{{Name: "local-prod", ConfigJson: "{}"}}},
		{Type: "none.v1", Kind: pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, Builtin: true, Zone: zone,
			Instances: []*pluginv1.InstanceDescriptor{{Name: "none-prod", ConfigJson: "{}"}}},
	}, pluginmgr.Options{RPCTimeout: 5 * time.Second, MaxConcurrentRPCsPerInstance: 2, Logger: slog.New(slog.DiscardHandler)})
	t.Cleanup(m.Stop)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, p := context.Background(), Manager(m)
	binding := &pluginv1.BindingContext{BindingId: "01a1890a-b363-7e0c-b649-384f55a42e50", DerivedPrincipalName: "LIGO_TEST"}
	if err := p.Health(ctx, pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, "local-prod"); err != nil {
		t.Errorf("health: %v", err)
	}
	id, err := p.EnsureIdentity(ctx, &pluginv1.EnsureIdentityRequest{Instance: "local-prod", Binding: binding})
	if err != nil || id.GetArtifact().GetMode() != pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL {
		t.Errorf("EnsureIdentity: %v (%v)", id, err)
	}
	if _, err := p.CleanupIdentity(ctx, &pluginv1.CleanupIdentityRequest{Instance: "local-prod", Binding: binding}); err != nil {
		t.Errorf("CleanupIdentity: %v", err)
	}
	_, err = p.EnsureSecretStore(ctx, &pluginv1.EnsureSecretStoreRequest{Instance: "none-prod", Binding: binding})
	t.Logf("EnsureSecretStore on none.v1: %v", err) // reached through the manager, whatever none.v1 answers
	if _, err := p.CleanupSecretStore(ctx, &pluginv1.CleanupSecretStoreRequest{Instance: "none-prod", Binding: binding}); err != nil {
		t.Errorf("CleanupSecretStore: %v", err)
	}
	if _, err := p.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "pg-ledger"}); err == nil {
		t.Error("EnsureTarget on an unknown platform")
	}
	if _, err := p.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "pg-ledger"}); err == nil {
		t.Error("CleanupTarget on an unknown platform")
	}
	if p.OutputValidator(pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, "local-prod") != nil {
		t.Error("a built-in with an output schema") // built-ins declare none
	}
}
