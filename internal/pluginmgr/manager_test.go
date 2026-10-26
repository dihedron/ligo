package pluginmgr

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const target = pluginv2.PluginKind_PLUGIN_KIND_TARGET_PROVIDER

var (
	prod = config.Zone{Name: "prod", TrustDomain: "prod.lab", SPIFFEWorkloadSocket: "unix:///run/spire/prod/agent.sock"}
	test = config.Zone{Name: "test", TrustDomain: "test.lab", SPIFFEWorkloadSocket: "unix:///run/spire/test/agent.sock"}
)

func instance(name, expr string, shared bool) *pluginv2.InstanceDescriptor {
	return &pluginv2.InstanceDescriptor{Name: name, SvidSelector: &pluginv2.SVIDSelectorConfig{MatchExpr: expr}, AllowSharedSvid: shared}
}

// syncBuffer collects log output written from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// newManager runs a manager over the test plugin, one process per spec.
func newManager(t *testing.T, specs ...Spec) (*Manager, *syncBuffer, error) {
	t.Helper()
	dir := pluginDir(t)
	sum := checksum(t, testPlugin)
	for i := range specs {
		specs[i].Binary, specs[i].SHA256 = "testplugin", sum
		if specs[i].Type == "" {
			specs[i].Type = "test.v1"
		}
		if specs[i].Kind == pluginv2.PluginKind_PLUGIN_KIND_UNSPECIFIED {
			specs[i].Kind = target
		}
	}
	logs := &syncBuffer{}
	m := New(specs, Options{
		Directory: dir, Owner: me(), RPCTimeout: 5 * time.Second, MaxConcurrentRPCsPerInstance: 2,
		Backoff: config.Backoff{Initial: 10 * time.Millisecond, Max: 40 * time.Millisecond},
		Logger:  slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	err := m.Start(context.Background())
	t.Cleanup(m.Stop)
	return m, logs, err
}

func health(ctx context.Context, m *Manager, name string) (string, error) {
	var msg string
	err := m.Call(ctx, target, name, false, func(ctx context.Context, c *Client) error {
		h, err := c.Control.Health(ctx, &pluginv2.HealthRequest{Instance: name})
		msg = h.GetPublicMessage()
		return err
	})
	return msg, err
}

// TestManagerStart: one process per (type, zone), each configured with its
// zone's instances and socket; the resolved SPIFFE IDs are logged (§5.2,
// ADR-03).
func TestManagerStart(t *testing.T) {
	m, logs, err := newManager(t,
		Spec{Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("pg-prod", "a", false), instance("pg-dr", "b", false)}},
		Spec{Zone: test, Instances: []*pluginv2.InstanceDescriptor{instance("pg-test", "c", false)}},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"pg-prod": "spiffe://prod.lab/plugin/pg-prod",
		"pg-dr":   "spiffe://prod.lab/plugin/pg-dr",
		"pg-test": "spiffe://test.lab/plugin/pg-test",
	}
	for name, id := range want {
		if got := m.Resolved(target, name); got != id {
			t.Errorf("%s resolved to %q, want %q", name, got, id)
		}
		if !strings.Contains(logs.String(), id) {
			t.Errorf("%s not logged", id)
		}
	}
	if msg, err := health(context.Background(), m, "pg-test"); err != nil || msg != "ok pg-test mtls=true" {
		t.Errorf("Health = (%q, %v)", msg, err)
	}
	if err := m.Call(context.Background(), target, "nowhere", false, func(context.Context, *Client) error { return nil }); err == nil {
		t.Error("a call to an unknown instance ran")
	}
}

// TestManagerStartRefusals: startup fails, naming the instance, on every
// violation of ADR-03, INV-10 and AC-15, and on a plugin that describes
// itself otherwise than configured.
func TestManagerStartRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		specs []Spec
		want  string
	}{
		"two SVIDs (AC-15)": {[]Spec{{Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("pg-prod", "two", false)}}},
			`"pg-prod" matched more than one SVID`},
		"foreign trust domain (INV-10)": {[]Spec{{Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("pg-prod", "foreign", false)}}},
			"pg-prod"},
		"unresolved": {[]Spec{{Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("pg-prod", "skip", false)}}},
			"pg-prod"},
		"shared SVID": {[]Spec{{Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("pg-prod", "shared", true), instance("pg-dr", "shared", false)}}},
			"pg-dr"},
		"wrong kind": {[]Spec{{Zone: prod, Env: []string{"TESTPLUGIN_KIND=store"}, Instances: []*pluginv2.InstanceDescriptor{instance("pg-prod", "a", false)}}},
			"kind"},
		"wrong type": {[]Spec{{Type: "oracle.v1", Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("pg-prod", "a", false)}}},
			"oracle.v1"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := newManager(t, tc.specs...); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// instances that all allow it may share an SVID
	if _, _, err := newManager(t, Spec{Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("pg-prod", "shared", true), instance("pg-dr", "shared", true)}}); err != nil {
		t.Errorf("allowed shared SVID: %v", err)
	}
}

// TestManagerRestart: a crashed process fails its in-flight RPC with a
// retryable error and is restarted with backoff (§5.2).
func TestManagerRestart(t *testing.T) {
	m, _, err := newManager(t, Spec{Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("crash", "a", false)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, err = health(ctx, m, "crash")
	if code, d := pluginsdk.FromError(err); code != codes.Unavailable || !d.GetRetryable() || d.GetCode() != "PLUGIN_UNAVAILABLE" {
		t.Fatalf("in-flight RPC: %v (%v %+v)", err, code, d)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := m.Call(ctx, target, "crash", false, func(ctx context.Context, c *Client) error {
			_, err := c.Control.Describe(ctx, &pluginv2.DescribeRequest{})
			return err
		})
		if err == nil {
			break
		}
		if _, d := pluginsdk.FromError(err); !d.GetRetryable() || time.Now().After(deadline) {
			t.Fatalf("not restarted: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if m.Resolved(target, "crash") != "spiffe://prod.lab/plugin/crash" {
		t.Error("not reconfigured after the restart")
	}
}

// TestManagerCallLimits: every RPC has the rpc_timeout deadline; mutating
// RPCs of one instance run at most max_concurrent_rpcs_per_instance at once
// (§5.3 rules 6-7).
func TestManagerCallLimits(t *testing.T) {
	m, _, err := newManager(t, Spec{Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("pg-prod", "a", false)}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_ = m.Call(ctx, target, "pg-prod", false, func(ctx context.Context, _ *Client) error {
		if d, ok := ctx.Deadline(); !ok || time.Until(d) > 5*time.Second || time.Until(d) < 4*time.Second {
			t.Errorf("deadline %v %v", d, ok)
		}
		return nil
	})

	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			_ = m.Call(ctx, target, "pg-prod", true, func(context.Context, *Client) error {
				n := running.Add(1)
				for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
				}
				time.Sleep(30 * time.Millisecond)
				running.Add(-1)
				return nil
			})
		})
	}
	wg.Wait()
	if peak.Load() != 2 {
		t.Errorf("peak concurrency %d, want 2", peak.Load())
	}

	// an error with a detail passes through unchanged
	err = m.Call(ctx, target, "pg-prod", false, func(context.Context, *Client) error {
		return pluginsdk.ErrOwnedByOtherBinding("role x")
	})
	if _, d := pluginsdk.FromError(err); d.GetCode() != "RESOURCE_OWNED_BY_OTHER_BINDING" {
		t.Errorf("detail lost: %v", err)
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("code %v", status.Code(err))
	}
}

// TestManagerLogs: plugin stderr and hclog output reach the log redacted
// (§5.3 rule 5).
func TestManagerLogs(t *testing.T) {
	m, logs, err := newManager(t, Spec{Zone: prod, Instances: []*pluginv2.InstanceDescriptor{instance("log", "a", false)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := health(context.Background(), m, "log"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "connecting") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := logs.String()
	if !strings.Contains(got, "connecting") || !strings.Contains(got, "admin") {
		t.Errorf("plugin log missing: %s", got)
	}
	for _, leak := range []string{"pw-leak", "raw-leak"} {
		if strings.Contains(got, leak) {
			t.Errorf("%s leaked: %s", leak, got)
		}
	}
}

// TestSpecs: the example configuration gives one process per external
// (type, zone), with its zone's instances; builtin types run in ligo.
func TestSpecs(t *testing.T) {
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	data = regexp.MustCompile(`<64-hex-sha256-of-[a-z-]+>`).ReplaceAll(data, []byte(strings.Repeat("ab", 32)))
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	specs, err := Specs(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, s := range specs {
		key := s.Type + "/" + s.Zone.Name
		for _, in := range s.Instances {
			got[key] = append(got[key], in.GetName())
			if !json.Valid([]byte(in.GetConfigJson())) {
				t.Errorf("%s: config_json %q", in.GetName(), in.GetConfigJson())
			}
		}
		if hex.EncodeToString(s.SHA256) != strings.Repeat("ab", 32) || s.Binary == "" {
			t.Errorf("%s: binary %q sha256 %x", key, s.Binary, s.SHA256)
		}
	}
	want := map[string][]string{
		"openldap.v1/prod": {"ldap-prod"},
		"vault.v1/prod":    {"vault-prod"},
		"vault.v1/test":    {"vault-test"},
		"oracle.v1/prod":   {"oracle-prod"},
		"oracle.v1/test":   {"oracle-test-dynamic"},
	}
	if len(got) != len(want) {
		t.Errorf("processes %v, want %v", got, want)
	}
	for k, v := range want {
		if strings.Join(got[k], ",") != strings.Join(v, ",") {
			t.Errorf("%s: %v, want %v", k, got[k], v)
		}
	}
	for _, s := range specs {
		for _, in := range s.Instances {
			if in.GetName() == "oracle-prod" && (in.GetIdentityProviderType() != "openldap.v1" || in.GetIdentityProviderInstance() != "ldap-prod" ||
				in.GetSecretStoreType() != "vault.v1" || in.GetSecretStoreInstance() != "vault-prod" || in.GetSvidSelector().GetMatchExpr() == "") {
				t.Errorf("oracle-prod wiring: %+v", in)
			}
		}
	}
}
