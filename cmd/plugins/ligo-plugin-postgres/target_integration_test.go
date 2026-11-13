//go:build integration

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/jackc/pgx/v5"
)

// env is a plugin on the real target database, and how to connect as a role.
type env struct {
	p   *plugin
	dsn string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dsn := os.Getenv("LIGO_TEST_TARGET_ADMIN_DSN")
	if dsn == "" {
		t.Fatal("LIGO_TEST_TARGET_ADMIN_DSN is not set: run the integration tests with test/lab/lab.sh test")
	}
	c, err := parseConfig([]byte(strings.ReplaceAll(goodConfig, `["RO","RW"]`, `["LEDGER_RO_ROLE","LEDGER_RW_ROLE","LEDGER_DDL_ROLE","LEDGER_GONE_ROLE"]`)), 0)
	if err != nil {
		t.Fatal(err)
	}
	c.DirectoryGroup = "ligo_ldap"
	return &env{dsn: dsn, p: &plugin{instances: map[string]*instance{"pg": {config: *c, dial: func(ctx context.Context) (*pgx.Conn, error) {
		return pgx.Connect(ctx, dsn)
	}}}}}
}

// as connects to the database as a role.
func (v *env) as(ctx context.Context, user, password string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(v.dsn)
	if err != nil {
		return nil, err
	}
	cfg.User, cfg.Password = user, password
	return pgx.ConnectConfig(ctx, cfg)
}

func (v *env) admin(t *testing.T, ctx context.Context) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, v.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func newBinding(t *testing.T, v *env) *pluginv1.BindingContext {
	t.Helper()
	id := uuid.NewV7().String()
	b := &pluginv1.BindingContext{BindingId: id, DerivedPrincipalName: "bnd_" + strings.ReplaceAll(id, "-", "")[16:32]}
	t.Cleanup(func() {
		_, _ = v.p.CleanupTarget(context.Background(), &pluginv1.CleanupTargetRequest{Instance: "pg", Binding: b})
	})
	return b
}

func ensure(v *env, b *pluginv1.BindingContext, mode pluginv1.IdentityMode, roles string) (*pluginv1.EnsureTargetResponse, error) {
	return v.p.EnsureTarget(context.Background(), &pluginv1.EnsureTargetRequest{Instance: "pg", Binding: b,
		Identity:          &pluginv1.IdentityArtifact{Mode: mode},
		RequestedSpecJson: []byte(`{"database":"ledger","schema":"ledger","roles":` + roles + `,"connectionLimit":3}`)})
}

const local = pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL

// memberOf lists a role's memberships, sorted.
func memberOf(t *testing.T, conn *pgx.Conn, role string) string {
	t.Helper()
	var out string
	if err := conn.QueryRow(context.Background(), `SELECT coalesce(string_agg(r.rolname, ',' ORDER BY r.rolname), '') FROM pg_auth_members m
		JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles u ON u.oid = m.member WHERE u.rolname = $1`, role).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestTargetLocal: PG-4, PG-5 and PG-6.
func TestTargetLocal(t *testing.T) {
	ctx := context.Background()
	v := newEnv(t)
	b := newBinding(t, v)
	admin := v.admin(t, ctx)

	r, err := ensure(v, b, local, `["LEDGER_RO_ROLE"]`)
	if err != nil {
		t.Fatal(err)
	}
	first := r.GetSecretPayload().GetStaticSecret().GetPassword()
	conn, err := v.as(ctx, b.GetDerivedPrincipalName(), first)
	if err != nil {
		t.Fatalf("the password does not connect: %v", err)
	}
	_ = conn.Close(ctx)
	var limit int
	var comment string
	if err := admin.QueryRow(ctx, "SELECT rolconnlimit, shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname = $1", b.GetDerivedPrincipalName()).Scan(&limit, &comment); err != nil || limit != 3 || comment != "ligo:binding_id="+b.GetBindingId() {
		t.Errorf("limit %d, comment %q (%v)", limit, comment, err)
	}

	r, err = ensure(v, b, local, `["LEDGER_RO_ROLE"]`)
	if err != nil || !r.GetSecretPayload().GetSecretUnchanged() || r.GetSecretPayload().GetStaticSecret() != nil {
		t.Fatalf("not rotated: %v (%v)", r.GetSecretPayload(), err)
	}
	conn, err = v.as(ctx, b.GetDerivedPrincipalName(), first)
	if err != nil {
		t.Fatalf("the old password stopped connecting: %v", err)
	}
	_ = conn.Close(ctx)

	rotate := &pluginv1.BindingContext{BindingId: b.GetBindingId(), DerivedPrincipalName: b.GetDerivedPrincipalName(), RotateStaticSecrets: true}
	r, err = ensure(v, rotate, local, `["LEDGER_RW_ROLE"]`)
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := v.as(ctx, b.GetDerivedPrincipalName(), first); err == nil {
		_ = conn.Close(ctx)
		t.Error("the old password still connects")
	}
	conn, err = v.as(ctx, b.GetDerivedPrincipalName(), r.GetSecretPayload().GetStaticSecret().GetPassword())
	if err != nil {
		t.Fatalf("the new password does not connect: %v", err)
	}
	_ = conn.Close(ctx)
	if got := memberOf(t, admin, b.GetDerivedPrincipalName()); got != "LEDGER_RW_ROLE" {
		t.Errorf("memberships %q", got)
	}
}

// TestOtherModes: a directory-verified role joins the group, with no password;
// a parent role has no login, and Vault's statements name it.
func TestOtherModes(t *testing.T) {
	ctx := context.Background()
	v := newEnv(t)
	admin := v.admin(t, ctx)
	b := newBinding(t, v)
	r, err := ensure(v, b, pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR, `["LEDGER_RO_ROLE"]`)
	if err != nil || r.GetSecretPayload().GetStaticSecret() != nil {
		t.Fatalf("%v %v", r, err)
	}
	if got := memberOf(t, admin, b.GetDerivedPrincipalName()); got != "LEDGER_RO_ROLE,ligo_ldap" {
		t.Errorf("memberships %q", got)
	}
	if _, err := ensure(v, b, pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR, `["LEDGER_RO_ROLE"]`); err != nil {
		t.Errorf("again: %v", err)
	}
	d := newBinding(t, v)
	r, err = ensure(v, d, pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC, `["LEDGER_RO_ROLE"]`)
	// no lease on the platform: 0, for ligo to fill
	if role := r.GetSecretPayload().GetDelegatedRole(); err == nil && (role.GetDefaultTtlSeconds() != 0 || role.GetMaxTtlSeconds() != 0) {
		t.Errorf("lease %d, %d without credential_ttl", role.GetDefaultTtlSeconds(), role.GetMaxTtlSeconds())
	}
	v.p.instances["pg"].ttl, v.p.instances["pg"].maxTTL = 90*time.Second, 4*time.Hour
	if again, err := ensure(v, d, pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC, `["LEDGER_RO_ROLE"]`); err != nil ||
		again.GetSecretPayload().GetDelegatedRole().GetDefaultTtlSeconds() != 90 || again.GetSecretPayload().GetDelegatedRole().GetMaxTtlSeconds() != 14400 {
		t.Errorf("the platform's lease: %v (%v)", again.GetSecretPayload().GetDelegatedRole(), err)
	}
	if err != nil || !strings.Contains(r.GetSecretPayload().GetDelegatedRole().GetCreationStatements()[0], `IN ROLE "`+d.GetDerivedPrincipalName()+`"`) {
		t.Fatalf("%v %v", r, err)
	}
	var login bool
	if err := admin.QueryRow(ctx, "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", d.GetDerivedPrincipalName()).Scan(&login); err != nil || login {
		t.Errorf("the parent can log in (%v)", err)
	}
	vt, err := v.p.ValidateTarget(ctx, &pluginv1.ValidateTargetRequest{Instance: "pg", CheckExistence: true, DefinitionJson: []byte(`{"database":"ledger","schema":"ledger"}`),
		AccessLevels: []*pluginv1.AccessLevelInput{{Name: "l", GrantsJson: []byte(`{"roles":["LEDGER_RO_ROLE"]}`)}}})
	if err != nil || !vt.GetValid() {
		t.Errorf("existing: %v %v", vt, err)
	}
	for name, req := range map[string]*pluginv1.ValidateTargetRequest{
		"no schema": {Instance: "pg", CheckExistence: true, DefinitionJson: []byte(`{"database":"ledger","schema":"nope"}`)},
		"no role": {Instance: "pg", CheckExistence: true, DefinitionJson: []byte(`{"database":"ledger","schema":"ledger"}`),
			AccessLevels: []*pluginv1.AccessLevelInput{{Name: "l", GrantsJson: []byte(`{"roles":["LEDGER_GONE_ROLE"]}`)}}},
	} {
		if vt, err := v.p.ValidateTarget(ctx, req); err != nil || vt.GetValid() {
			t.Errorf("%s: valid (%v)", name, err)
		}
	}
	if h, err := v.p.Health(ctx, &pluginv1.HealthRequest{Instance: "pg"}); err != nil || !h.GetServing() {
		t.Errorf("health: %v %v", h, err)
	}
}

// TestForeign: PG-7, a role of another binding, or untagged, is left alone.
func TestForeign(t *testing.T) {
	ctx := context.Background()
	v := newEnv(t)
	b := newBinding(t, v)
	if _, err := ensure(v, b, local, `["LEDGER_RO_ROLE"]`); err != nil {
		t.Fatal(err)
	}
	thief := &pluginv1.BindingContext{BindingId: uuid.NewV7().String(), DerivedPrincipalName: b.GetDerivedPrincipalName()}
	_, err := ensure(v, thief, local, `["LEDGER_RW_ROLE"]`)
	if code, retry := errorCode(t, err); code != "RESOURCE_OWNED_BY_OTHER_BINDING" || retry {
		t.Errorf("%s %v", code, retry)
	}
	c, err := v.p.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "pg", Binding: thief})
	if err != nil || !c.GetSkippedNotOwner() {
		t.Errorf("%v %v", c, err)
	}
	if got := memberOf(t, v.admin(t, ctx), b.GetDerivedPrincipalName()); got != "LEDGER_RO_ROLE" {
		t.Errorf("touched: %q", got)
	}
}

// TestAtomic: PG-8, a failure after CREATE ROLE leaves nothing, so a retry
// does not find an untagged role and call it foreign. LEDGER_GONE_ROLE is in
// the bounds and not in the database.
func TestAtomic(t *testing.T) {
	ctx := context.Background()
	v := newEnv(t)
	b := newBinding(t, v)
	_, err := ensure(v, b, local, `["LEDGER_GONE_ROLE"]`)
	if code, retry := errorCode(t, err); code != "ROLE_NOT_FOUND" || retry {
		t.Fatalf("%s %v", code, retry)
	}
	if exists, _, err := owner(ctx, v.admin(t, ctx), b.GetDerivedPrincipalName()); err != nil || exists {
		t.Errorf("a role is left (%v)", err)
	}
	if _, err := ensure(v, b, local, `["LEDGER_RO_ROLE"]`); err != nil {
		t.Errorf("the retry: %v", err)
	}
}

// TestCleanup: PG-9, the role's session ends with it, and a second call
// succeeds; PG-10, a role that owns objects is a terminal error.
func TestCleanup(t *testing.T) {
	ctx := context.Background()
	v := newEnv(t)
	b := newBinding(t, v)
	r, err := ensure(v, b, local, `["LEDGER_RO_ROLE"]`)
	if err != nil {
		t.Fatal(err)
	}
	session, err := v.as(ctx, b.GetDerivedPrincipalName(), r.GetSecretPayload().GetStaticSecret().GetPassword())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = session.Close(ctx) }()
	for range 2 {
		if c, err := v.p.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "pg", Binding: b}); err != nil || c.GetSkippedNotOwner() {
			t.Fatalf("%v %v", c, err)
		}
	}
	var one int
	if err := session.QueryRow(ctx, "SELECT 1").Scan(&one); err == nil {
		t.Error("the revoked role's session still answers")
	}

	o := newBinding(t, v)
	r, err = ensure(v, o, local, `["LEDGER_DDL_ROLE"]`)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := v.as(ctx, o.GetDerivedPrincipalName(), r.GetSecretPayload().GetStaticSecret().GetPassword())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	table := pgx.Identifier{"ledger", "t_" + o.GetDerivedPrincipalName()}.Sanitize()
	if _, err := conn.Exec(ctx, "CREATE TABLE "+table+" (id int)"); err != nil {
		t.Fatal(err)
	}
	_, err = v.p.CleanupTarget(ctx, &pluginv1.CleanupTargetRequest{Instance: "pg", Binding: o})
	if code, retry := errorCode(t, err); code != "ROLE_OWNS_OBJECTS" || retry {
		t.Errorf("%s %v", code, retry)
	}
	conn2, err := v.as(ctx, o.GetDerivedPrincipalName(), r.GetSecretPayload().GetStaticSecret().GetPassword())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn2.Close(ctx) }()
	if _, err := conn2.Exec(ctx, "DROP TABLE "+table); err != nil {
		t.Error(err)
	}
}
