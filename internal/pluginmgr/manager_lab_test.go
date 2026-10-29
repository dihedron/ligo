//go:build integration && lab

package pluginmgr

import (
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/config"
)

const store = pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE

// labEnv reads a variable of "lab.sh env --on ligo1"; these tests run only
// on ligo1, as the user ligo.
func labEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: run the lab tests with test/lab/lab.sh test --on ligo1", name)
	}
	return v
}

// labprobe is the spec of the lab's probe plugin in the zone prod, with one
// instance selecting by expr.
func labprobe(t *testing.T, expr string) Spec {
	t.Helper()
	sum, err := hex.DecodeString(labEnv(t, "LIGO_TEST_LABPROBE_SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{"bootstrap_credential":{"source":"vault","address":"` + labEnv(t, "LIGO_TEST_BAO_PROD_ADDR") +
		`","auth_mount":"jwt-spiffe","role":"ligo-plugin-labprobe","jwt_audience":"` + labEnv(t, "LIGO_TEST_BAO_PROD_AUDIENCE") +
		`","kv_path":"kv/data/ligo/bootstrap/labprobe"},"ca_file":"` + labEnv(t, "LIGO_TEST_CA") + `"}`
	return Spec{
		Type: "labprobe.v1", Kind: store, Binary: "labprobe", SHA256: sum,
		Zone: config.Zone{Name: "prod", TrustDomain: "prod.lab", SPIFFEWorkloadSocket: labEnv(t, "LIGO_TEST_SPIRE_PROD_SOCKET")},
		Instances: []*pluginv1.InstanceDescriptor{{
			Name: "labprobe-prod", ConfigJson: cfg,
			SvidSelector: &pluginv1.SVIDSelectorConfig{MatchExpr: expr, JwtAudience: []string{labEnv(t, "LIGO_TEST_BAO_PROD_AUDIENCE")}},
		}},
	}
}

func labManager(t *testing.T, spec Spec) (*Manager, error) {
	t.Helper()
	m := New([]Spec{spec}, Options{
		Directory: labEnv(t, "LIGO_TEST_PLUGIN_DIR"), Owner: Root, RPCTimeout: 30 * time.Second, MaxConcurrentRPCsPerInstance: 4,
		Backoff: config.Backoff{Initial: time.Second, Max: 10 * time.Second},
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	t.Cleanup(m.Stop)
	return m, m.Start(context.Background())
}

// TestLabPlugin: ligo starts a root-owned plugin, which SPIRE attests by its
// hash; the plugin selects its own SVID and reads its bootstrap credential
// from bao-prod with its JWT-SVID (§5.3, §5.4, §5.5, ADR-03, INV-10).
func TestLabPlugin(t *testing.T) {
	m, err := labManager(t, labprobe(t, `hint == instance_name`))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Resolved(store, "labprobe-prod"); got != "spiffe://prod.lab/ligo/plugin/labprobe" {
		t.Errorf("resolved %q", got)
	}
	var msg string
	err = m.Call(context.Background(), store, "labprobe-prod", false, func(ctx context.Context, c *Client) error {
		h, err := c.Control.Health(ctx, &pluginv1.HealthRequest{Instance: "labprobe-prod"})
		msg = h.GetPublicMessage()
		return err
	})
	if err != nil || msg != "credential for lab-admin" {
		t.Errorf("Health = (%q, %v)", msg, err)
	}
}

// TestLabPluginRefusals: a selector matching ligo's core SVID as well as the
// plugin's fails startup naming the instance (AC-15, real SVIDs); a wrong
// hash is refused before the plugin runs (§5.3 rule 4).
func TestLabPluginRefusals(t *testing.T) {
	if _, err := labManager(t, labprobe(t, `trust_domain == "prod.lab"`)); err == nil || !strings.Contains(err.Error(), `"labprobe-prod" matched more than one SVID`) {
		t.Errorf("two SVIDs: %v", err)
	}
	spec := labprobe(t, `hint == instance_name`)
	spec.SHA256 = make([]byte, 32)
	if _, err := labManager(t, spec); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("wrong hash: %v", err)
	}
}
