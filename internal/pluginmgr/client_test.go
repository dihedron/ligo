package pluginmgr

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// testPlugin is the test plugin's binary, built once by TestMain where the
// Go toolchain is (not on ligo1, which runs only the lab tests).
var testPlugin string

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("go"); err != nil {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "pluginmgr")
	if err != nil {
		panic(err)
	}
	testPlugin = filepath.Join(dir, "testplugin")
	if out, err := exec.Command("go", "build", "-o", testPlugin, "./testdata/testplugin").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func checksum(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return h.Sum(nil)
}

func quiet() hclog.Logger { return hclog.NewNullLogger() }

// TestStart: one binary serves PluginControl and its kind's service over
// gRPC with AutoMTLS (§5.3 rules 1-2, EXT-10).
func TestStart(t *testing.T) {
	c, err := Start(exec.Command(testPlugin), pluginv2.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, checksum(t, testPlugin), quiet(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Kill)
	ctx := context.Background()
	d, err := c.Control.Describe(ctx, &pluginv2.DescribeRequest{})
	if err != nil || d.GetPluginType() != "test.v1" || d.GetKind() != pluginv2.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER {
		t.Fatalf("Describe = (%v, %v)", d, err)
	}
	r, err := c.Control.ConfigureInstances(ctx, &pluginv2.ConfigureInstancesRequest{Zone: "prod", Instances: []*pluginv2.InstanceDescriptor{{Name: "pg-prod", TrustDomain: "prod.lab"}}})
	if err != nil || len(r.GetResolved()) != 1 || r.GetResolved()[0].GetSpiffeId() != "spiffe://prod.lab/plugin/pg-prod" {
		t.Errorf("ConfigureInstances = (%v, %v)", r, err)
	}
	if h, err := c.Control.Health(ctx, &pluginv2.HealthRequest{Instance: "pg-prod"}); err != nil || !h.GetServing() || h.GetPublicMessage() != "ok pg-prod mtls=true" {
		t.Errorf("Health = (%v, %v)", h, err)
	}
	// the kind's service is on the same connection; the test plugin does
	// not implement it
	if _, err := c.Platform.ValidateTarget(ctx, &pluginv2.ValidateTargetRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("ValidateTarget: %v", err)
	}
	if c.Identity != nil || c.Store != nil {
		t.Error("services of other kinds were dispensed")
	}
}

// TestStartKinds: the identity and store services are dispensed for their
// kinds.
func TestStartKinds(t *testing.T) {
	for kind, env := range map[pluginv2.PluginKind]string{
		pluginv2.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER: "identity",
		pluginv2.PluginKind_PLUGIN_KIND_SECRET_STORE:      "store",
	} {
		cmd := exec.Command(testPlugin)
		cmd.Env = append(os.Environ(), "TESTPLUGIN_KIND="+env)
		c, err := Start(cmd, kind, checksum(t, testPlugin), quiet(), nil)
		if err != nil {
			t.Fatalf("%s: %v", env, err)
		}
		ctx := context.Background()
		switch env {
		case "identity":
			_, err = c.Identity.EnsureIdentity(ctx, &pluginv2.EnsureIdentityRequest{})
		case "store":
			_, err = c.Store.EnsureSecretStore(ctx, &pluginv2.EnsureSecretStoreRequest{})
		}
		if status.Code(err) != codes.Unimplemented || c.Platform != nil {
			t.Errorf("%s: %v", env, err)
		}
		c.Kill()
	}
	// a plugin of another kind than the host expects has no such service
	cmd := exec.Command(testPlugin)
	cmd.Env = append(os.Environ(), "TESTPLUGIN_KIND=store")
	c, err := Start(cmd, pluginv2.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, checksum(t, testPlugin), quiet(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Kill()
	if _, err := c.Platform.ValidateTarget(context.Background(), &pluginv2.ValidateTargetRequest{}); status.Code(err) != codes.Unimplemented {
		t.Errorf("wrong kind: %v", err)
	}
}

// TestStartRefusals: a plugin of another handshake protocol, a wrong checksum
// (SecureConfig, EXT-11) and an unknown kind are refused.
func TestStartRefusals(t *testing.T) {
	sum := checksum(t, testPlugin)
	v2 := exec.Command(testPlugin)
	v2.Env = append(os.Environ(), "TESTPLUGIN_PROTOCOL=2")
	if c, err := Start(v2, pluginv2.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, sum, quiet(), nil); err == nil || !strings.Contains(err.Error(), "incompatible API version") {
		if c != nil {
			c.Kill()
		}
		t.Errorf("protocol 2: %v", err)
	}
	bad := append([]byte{}, sum...)
	bad[0] ^= 0xff
	if c, err := Start(exec.Command(testPlugin), pluginv2.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, bad, quiet(), nil); err == nil || !strings.Contains(err.Error(), "checksum") {
		if c != nil {
			c.Kill()
		}
		t.Errorf("wrong checksum: %v", err)
	}
	if _, err := Start(exec.Command(testPlugin), pluginv2.PluginKind_PLUGIN_KIND_UNSPECIFIED, sum, quiet(), nil); err == nil {
		t.Error("an unspecified kind was accepted")
	}
}
