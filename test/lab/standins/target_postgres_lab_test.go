//go:build integration && lab

package standins

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/hashicorp/go-hclog"
	"github.com/jackc/pgx/v5"
)

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

// bootstrap is the bootstrap_credential of a lab plugin on bao-prod.
func bootstrap(t *testing.T, name string) string {
	return `{"source":"vault","address":"` + labEnv(t, "LIGO_TEST_BAO_PROD_ADDR") + `","auth_mount":"jwt-spiffe","role":"ligo-plugin-` + name +
		`","jwt_audience":"` + labEnv(t, "LIGO_TEST_BAO_PROD_AUDIENCE") + `","kv_path":"kv/data/ligo/bootstrap/` + name + `"}`
}

// start launches a lab plugin from the plugins directory with the
// production checks, and configures its one instance in the zone prod.
func start(t *testing.T, binary string, kind pluginv1.PluginKind, in *pluginv1.InstanceDescriptor) *pluginmgr.Client {
	t.Helper()
	sum, err := hex.DecodeString(labEnv(t, "LIGO_TEST_"+strings.ToUpper(strings.ReplaceAll(binary, "-", "_"))+"_SHA256"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := pluginmgr.OpenBinary(labEnv(t, "LIGO_TEST_PLUGIN_DIR"), binary, sum, pluginmgr.Root)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pluginmgr.Start(b.Command(), kind, b.Checksum(), hclog.NewNullLogger(), os.Stderr)
	_ = b.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Kill)
	in.Zone, in.TrustDomain = "prod", "prod.lab"
	in.SvidSelector = &pluginv1.SVIDSelectorConfig{MatchExpr: `path == "/ligo/plugin/` + binary + `"`,
		JwtAudience: []string{labEnv(t, "LIGO_TEST_BAO_PROD_AUDIENCE")}}
	if _, err := c.Control.ConfigureInstances(context.Background(), &pluginv1.ConfigureInstancesRequest{Zone: "prod",
		SpiffeWorkloadSocket: labEnv(t, "LIGO_TEST_SPIRE_PROD_SOCKET"), Instances: []*pluginv1.InstanceDescriptor{in}}); err != nil {
		t.Fatal(err)
	}
	return c
}

func code(err error) string {
	_, d := pluginsdk.FromError(err)
	return d.GetCode()
}

// targetPostgres starts the stand-in with the instance pg-ledger.
func targetPostgres(t *testing.T, strategy string) *pluginmgr.Client {
	t.Helper()
	cfg := `{"host":"pg.ligo.lab","port":5432,"database":"ledger","grantable_roles":["LEDGER_RO_ROLE","LEDGER_RW_ROLE"],"ca_file":"` +
		labEnv(t, "LIGO_TEST_CA") + `","bootstrap_credential":` + bootstrap(t, "target-postgres") + `}`
	return start(t, "target-postgres", pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER,
		&pluginv1.InstanceDescriptor{Name: "pg-ledger", ConfigJson: cfg, SecretStorageStrategy: strategy})
}

func level(name, roles string) *pluginv1.AccessLevelInput {
	return &pluginv1.AccessLevelInput{Name: name, GrantsJson: []byte(`{"roles":` + roles + `}`)}
}

// binding is the context of a new binding, with its own principal name.
func binding() *pluginv1.BindingContext {
	id := uuid.NewV7()
	return &pluginv1.BindingContext{BindingId: id.String(), BindingName: "b-" + id.String()[24:], Revision: 1, Attempt: 1,
		DerivedPrincipalName: "bnd_" + strings.ReplaceAll(id.String(), "-", "")[16:32]}
}

// TestLabTargetPostgres: the stand-in validates targets and bindings without
// changing anything, creates a converging, owned login role in TARGET_LOCAL,
// and cleans up only what it owns (§5.8).
func TestLabTargetPostgres(t *testing.T) {
	ctx := context.Background()
	c := targetPostgres(t, "vault-static")
	def := []byte(`{"database":"ledger","schema":"ledger"}`)

	vt, err := c.Platform.ValidateTarget(ctx, &pluginv1.ValidateTargetRequest{Instance: "pg-ledger", DefinitionJson: def, CheckExistence: true,
		AccessLevels: []*pluginv1.AccessLevelInput{level("read", `["LEDGER_RO_ROLE"]`), level("write", `["LEDGER_RW_ROLE","LEDGER_RO_ROLE"]`)}})
	if err != nil || !vt.GetValid() || strings.Join(vt.GetAccessLevels()[1].GetPrivileges(), ",") != "role:LEDGER_RO_ROLE,role:LEDGER_RW_ROLE" {
		t.Fatalf("ValidateTarget = %v (%v)", vt, err)
	}
	for name, req := range map[string]*pluginv1.ValidateTargetRequest{
		"role outside grantable_roles": {Instance: "pg-ledger", DefinitionJson: def, AccessLevels: []*pluginv1.AccessLevelInput{level("x", `["PG_READ_ALL_DATA"]`)}},
		"missing schema":               {Instance: "pg-ledger", DefinitionJson: []byte(`{"database":"ledger","schema":"nope"}`), CheckExistence: true, AccessLevels: []*pluginv1.AccessLevelInput{level("read", `["LEDGER_RO_ROLE"]`)}},
		"bad identifier":               {Instance: "pg-ledger", DefinitionJson: []byte(`{"database":"ledger","schema":"x; drop"}`), AccessLevels: []*pluginv1.AccessLevelInput{level("read", `["LEDGER_RO_ROLE"]`)}},
	} {
		if r, err := c.Platform.ValidateTarget(ctx, req); err == nil && r.GetValid() {
			t.Errorf("%s: valid", name)
		}
	}

	vb, err := c.Platform.ValidateBinding(ctx, &pluginv1.ValidateBindingRequest{Instance: "pg-ledger", DefinitionJson: def, AccessLevel: "read",
		AccessLevelGrantsJson: []byte(`{"roles":["LEDGER_RO_ROLE"]}`), ParametersJson: []byte(`{"connectionLimit":5}`)})
	if err != nil || !vb.GetValid() || strings.Join(vb.GetPrivileges(), ",") != "role:LEDGER_RO_ROLE" {
		t.Fatalf("ValidateBinding = %v (%v)", vb, err)
	}
	if r, err := c.Platform.ValidateBinding(ctx, &pluginv1.ValidateBindingRequest{Instance: "pg-ledger", DefinitionJson: def, AccessLevel: "read",
		AccessLevelGrantsJson: []byte(`{"roles":["LEDGER_RO_ROLE"]}`), ParametersJson: []byte(`{"roles":["LEDGER_RW_ROLE"]}`)}); err == nil && r.GetValid() {
		t.Error("parameters adding a role are valid")
	}

	b := binding()
	identity := &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, PrincipalId: b.GetDerivedPrincipalName()}
	ensure := func(b *pluginv1.BindingContext) (*pluginv1.EnsureTargetResponse, error) {
		return c.Platform.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "pg-ledger", Binding: b, Identity: identity, RequestedSpecJson: vb.GetRequestedSpecJson()})
	}
	t.Cleanup(func() {
		_, _ = c.Platform.CleanupTarget(context.Background(), &pluginv1.CleanupTargetRequest{Instance: "pg-ledger", Binding: b, Identity: identity})
	})
	r, err := ensure(b)
	if err != nil {
		t.Fatal(err)
	}
	secret := r.GetSecretPayload().GetStaticSecret()
	if secret.GetUsername() != b.GetDerivedPrincipalName() || len(secret.GetPassword()) < 32 {
		t.Fatalf("secret for %q, %d characters", secret.GetUsername(), len(secret.GetPassword()))
	}
	var spec struct{ Endpoint, Database, User string }
	if err := json.Unmarshal(r.GetFinalizedClientSpecJson(), &spec); err != nil || spec.Endpoint != "pg.ligo.lab:5432" || spec.User != secret.GetUsername() {
		t.Errorf("client spec %s (%v)", r.GetFinalizedClientSpecJson(), err)
	}
	conn, err := pgx.Connect(ctx, fmt.Sprintf("postgres://%s:%s@pg.ligo.lab:5432/ledger?sslmode=verify-full&sslrootcert=%s",
		secret.GetUsername(), secret.GetPassword(), labEnv(t, "LIGO_TEST_CA")))
	if err != nil {
		t.Fatalf("the new role cannot connect: %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT count(*) FROM ledger.entries"); err != nil {
		t.Errorf("read at level read: %v", err)
	}
	if _, err := conn.Exec(ctx, "INSERT INTO ledger.entries VALUES (1, 1)"); err == nil {
		t.Error("write at level read")
	}
	_ = conn.Close(ctx)

	again, err := ensure(b)
	if err != nil || !again.GetSecretPayload().GetSecretUnchanged() || again.GetSecretPayload().GetStaticSecret() != nil {
		t.Errorf("second ensure: %v (%v)", again.GetSecretPayload(), err)
	}
	other := binding()
	other.DerivedPrincipalName = b.GetDerivedPrincipalName()
	if _, err := ensure(other); code(err) != "RESOURCE_OWNED_BY_OTHER_BINDING" {
		t.Errorf("another binding's role: %v", err)
	}
	if cr, err := c.Platform.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "pg-ledger", Binding: other, Identity: identity}); err != nil || !cr.GetSkippedNotOwner() {
		t.Errorf("cleanup of a foreign role: %v (%v)", cr, err)
	}
	for range 2 { // the second finds nothing: success
		if cr, err := c.Platform.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "pg-ledger", Binding: b, Identity: identity}); err != nil || cr.GetSkippedNotOwner() {
			t.Errorf("cleanup: %v (%v)", cr, err)
		}
	}
	if _, err := pgx.Connect(ctx, fmt.Sprintf("postgres://%s:%s@pg.ligo.lab:5432/ledger?sslmode=verify-full&sslrootcert=%s",
		secret.GetUsername(), secret.GetPassword(), labEnv(t, "LIGO_TEST_CA"))); err == nil {
		t.Error("the dropped role still connects")
	}
}

// TestLabTargetPostgresDynamic: in DELEGATED_DYNAMIC the stand-in creates
// the parent role and returns the statements OpenBao runs (§5.6).
func TestLabTargetPostgresDynamic(t *testing.T) {
	ctx := context.Background()
	c := targetPostgres(t, "vault-dynamic")
	b := binding()
	identity := &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC, PrincipalId: b.GetDerivedPrincipalName()}
	spec := []byte(`{"database":"ledger","schema":"ledger","roles":["LEDGER_RO_ROLE"],"connectionLimit":0}`)
	t.Cleanup(func() {
		_, _ = c.Platform.CleanupTarget(context.Background(), &pluginv1.CleanupTargetRequest{Instance: "pg-ledger", Binding: b, Identity: identity})
	})
	r, err := c.Platform.EnsureTarget(ctx, &pluginv1.EnsureTargetRequest{Instance: "pg-ledger", Binding: b, Identity: identity, RequestedSpecJson: spec})
	if err != nil {
		t.Fatal(err)
	}
	d := r.GetSecretPayload().GetDelegatedRole()
	if d.GetRoleType() != "database-dynamic" || len(d.GetCreationStatements()) == 0 ||
		!strings.Contains(d.GetCreationStatements()[0], `IN ROLE "`+b.GetDerivedPrincipalName()+`"`) || len(d.GetRevocationStatements()) == 0 {
		t.Errorf("delegated role %v", d)
	}
	if cr, err := c.Platform.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "pg-ledger", Binding: b, Identity: identity}); err != nil || cr.GetSkippedNotOwner() {
		t.Errorf("cleanup: %v (%v)", cr, err)
	}
}
