//go:build integration

package accounts

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// insecure: CI's container has no TLS; the lab's DSNs use verify-full.
var insecure = os.Getenv("CI") != ""

var structure = &charter.Accounts{Jurisdiction: "cloud/{account}"}

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

func caller(name, role string, jurisdictions ...string) changerequests.Caller {
	return changerequests.Caller{Principal: authz.Principal{Name: name}, Grants: authz.Grants{{Role: role, Jurisdictions: jurisdictions}}}
}

var registrar = caller("reg", config.RoleAccountAdmin)

func slug(err error) string {
	var e *changerequests.Error
	if errors.As(err, &e) {
		return e.Slug
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

type env struct {
	app, owner *pgxpool.Pool
	x          string // makes this test's names unique
}

func setup(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), store.Limits{}, insecure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	v := &env{app: pools.App, owner: owner, x: "t" + uuid.NewV7().String()[24:]}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "delete from sources where account like $1", v.x+"%")
		_, _ = owner.Exec(ctx, "delete from targets where account like $1", v.x+"%")
		_, _ = owner.Exec(ctx, "delete from accounts where name like $1", v.x+"%")
	})
	return v
}

// source inserts a source of account straight into the table: what the
// triggers refuse here, they refuse for every code path.
func (v *env) source(ctx context.Context, q store.Querier, account string) (uuid.UUID, error) {
	id := uuid.NewV7()
	_, err := q.Exec(ctx, `insert into sources (id, name, jurisdiction, account, trust_domain, svid_regex, created_by, updated_by)
		values ($1, $2, $3, $4, 'cloud.internal', '^spiffe://cloud\.internal/x$', 't', 't')`,
		id, "src-"+id.String()[24:], "cloud/"+account+"/app/p1", account)
	return id, err
}

func (v *env) audited(t *testing.T, action, name string) int {
	t.Helper()
	var n int
	if err := v.owner.QueryRow(context.Background(), "select count(*) from audit_log where action = $1 and snapshot->>'name' = $2", action, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestRegister(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	a, err := Register(ctx, v.app, registrar, v.x, "ACME Corp")
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != v.x || a.DisplayName != "ACME Corp" || a.Status != "ACTIVE" || a.RegisteredBy != "reg" {
		t.Errorf("registered: %+v", a)
	}
	if n := v.audited(t, "SYSTEM_ACCOUNT_REGISTERED", v.x); n != 1 {
		t.Errorf("audited %d times", n)
	}
	if _, err := Register(ctx, v.app, registrar, v.x, ""); slug(err) != "account-exists" {
		t.Errorf("twice: %v", err)
	}
	for _, name := range []string{"", "a-b", "a_b", "ACME", "1abc", "cloud/x", strings.Repeat("a", 31)} {
		if _, err := Register(ctx, v.app, registrar, name, ""); slug(err) != "validation-failed" {
			t.Errorf("name %q: %v", name, err)
		}
	}
	if _, err := Register(ctx, v.app, registrar, v.x+"long", strings.Repeat("x", 129)); slug(err) != "validation-failed" {
		t.Errorf("display name: %v", err)
	}
}

// TN-17: only account_admin and admin.full_access change the registry.
func TestWhoMayChange(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	if _, err := Register(ctx, v.app, registrar, v.x, ""); err != nil {
		t.Fatal(err)
	}
	for _, c := range []changerequests.Caller{
		caller("vera", config.RoleViewer, "*"), caller("olga", config.RoleOperator, "*"), caller("dora", config.RoleApprover, "*"),
		caller("bea", config.RoleBreakGlass, "*"), caller("bot", config.RoleTrustedAutomation, "*"),
	} {
		if _, err := Register(ctx, v.app, c, v.x+"n", ""); slug(err) != "forbidden" {
			t.Errorf("%s registers: %v", c.ID(), err)
		}
		if _, err := Retire(ctx, v.app, c, v.x); slug(err) != "forbidden" {
			t.Errorf("%s retires: %v", c.ID(), err)
		}
	}
	root := caller("root", config.RoleFullAccess, "*")
	if _, err := Register(ctx, v.app, root, v.x+"n", ""); err != nil {
		t.Errorf("full access: %v", err)
	}
}

func TestMaintenance(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	if _, err := Register(ctx, v.app, registrar, v.x, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := v.owner.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = v.owner.Exec(context.Background(), "update system_settings set maintenance_mode = false")
	})
	if _, err := Register(ctx, v.app, registrar, v.x+"n", ""); slug(err) != "maintenance" {
		t.Errorf("register: %v", err)
	}
	if _, err := Retire(ctx, v.app, registrar, v.x); slug(err) != "maintenance" {
		t.Errorf("retire: %v", err)
	}
}

// TN-6, and a retired name is never reused.
func TestRetire(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	if _, err := Register(ctx, v.app, registrar, v.x, ""); err != nil {
		t.Fatal(err)
	}
	id, err := v.source(ctx, v.app, v.x)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Retire(ctx, v.app, registrar, v.x); slug(err) != "account-in-use" {
		t.Fatalf("with a source: %v", err)
	}
	if n := v.audited(t, "SYSTEM_ACCOUNT_RETIRED", v.x); n != 0 {
		t.Errorf("a refused retirement audited %d times", n)
	}
	if _, err := v.app.Exec(ctx, "update sources set state = 'RETIRED' where id = $1", id); err != nil {
		t.Fatal(err)
	}
	a, err := Retire(ctx, v.app, registrar, v.x)
	if err != nil {
		t.Fatal(err)
	}
	if a.Status != "RETIRED" || a.RetiredBy != "reg" || a.RetiredAt == nil {
		t.Errorf("retired: %+v", a)
	}
	if n := v.audited(t, "SYSTEM_ACCOUNT_RETIRED", v.x); n != 1 {
		t.Errorf("audited %d times", n)
	}
	if _, err := Retire(ctx, v.app, registrar, v.x); slug(err) != "invalid-transition" {
		t.Errorf("twice: %v", err)
	}
	if _, err := Register(ctx, v.app, registrar, v.x, ""); slug(err) != "account-exists" {
		t.Errorf("reused: %v", err)
	}
	if _, err := Retire(ctx, v.app, registrar, v.x+"none"); slug(err) != "not-found" {
		t.Errorf("unknown: %v", err)
	}
}

func TestRequire(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	if _, err := Register(ctx, v.app, registrar, v.x, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Register(ctx, v.app, registrar, v.x+"old", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := Retire(ctx, v.app, registrar, v.x+"old"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		accounts           *charter.Accounts
		jurisdiction, want string
		slug               string
		description        string
	}{
		{nil, "cloud/" + v.x + "none/app/p", "", "", "no accounts configured"},
		{structure, "dc/corp-prod/ledger", "", "", "not account-managed"},
		{structure, "cloud/" + v.x + "/app/p1", v.x, "", "registered"},
		{structure, "cloud/" + v.x, v.x, "", "the account's root"},
		{structure, "cloud/" + v.x + "none/app/p", "", "account-not-registered", "TN-4: unregistered"},
		{structure, "cloud/" + v.x + "old/app/p", "", "account-not-registered", "retired"},
		{structure, "cloud/a-b/app/p", "", "account-not-registered", "TN-3: outside the grammar, not unmanaged"},
		{structure, "cloud/ACME/app/p", "", "account-not-registered", "upper case"},
	} {
		got, err := Require(ctx, v.app, c.accounts, c.jurisdiction)
		if got != c.want || slug(err) != c.slug {
			t.Errorf("%s: %q, %v", c.description, got, err)
		}
	}
}

// The triggers hold whatever the code above them does.
func TestTriggers(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	if _, err := Register(ctx, v.app, registrar, v.x, ""); err != nil {
		t.Fatal(err)
	}
	code := func(err error) string {
		var pe *pgconn.PgError
		if errors.As(err, &pe) {
			return pe.Code
		}
		return ""
	}
	if _, err := v.source(ctx, v.app, v.x+"none"); code(err) != "23503" { // foreign key
		t.Errorf("unregistered: %v", err)
	}
	id, err := v.source(ctx, v.app, v.x)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.app.Exec(ctx, "update sources set account = null where id = $1", id); err == nil {
		t.Error("the account of a source changed outside the transfer procedure")
	}
	if _, err := v.app.Exec(ctx, "update accounts set status = 'RETIRED', retired_by = 'x', retired_at = now() where name = $1", v.x); code(err) != codeInUse {
		t.Errorf("retired with a source: %v", err)
	}
	if _, err := v.app.Exec(ctx, "update sources set state = 'RETIRED' where id = $1", id); err != nil {
		t.Fatal(err)
	}
	if _, err := v.app.Exec(ctx, "update accounts set status = 'RETIRED', retired_by = 'x', retired_at = now() where name = $1", v.x); err != nil {
		t.Fatal(err)
	}
	if _, err := v.source(ctx, v.app, v.x); code(err) != codeRetired {
		t.Errorf("a new source on a retired account: %v", err)
	}
	for _, sql := range []string{
		"update accounts set status = 'ACTIVE', retired_by = null, retired_at = null where name = $1",
		"update accounts set display_name = 'changed' where name = $1",
		"update accounts set name = name || 'x' where name = $1",
		"delete from accounts where name = $1",
	} {
		if _, err := v.app.Exec(ctx, sql, v.x); err == nil {
			t.Errorf("allowed: %s", sql)
		}
	}
	// a transfer cannot move a resource onto a retired account either
	if _, err := Register(ctx, v.app, registrar, v.x+"b", ""); err != nil {
		t.Fatal(err)
	}
	moved, err := v.source(ctx, v.app, v.x+"b")
	if err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(ctx, v.app, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ligo.transfer = 'on'"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "update sources set account = $2 where id = $1", moved, v.x)
		return err
	})
	if code(err) != codeRetired {
		t.Errorf("transferred onto a retired account: %v", err)
	}
}

// A retirement and a new source at the same moment: one of them loses, and
// an active source never sits on a retired account.
func TestRetireRace(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	wins := map[string]int{}
	for i := range 20 {
		name := v.x + string(rune('a'+i))
		if _, err := Register(ctx, v.app, registrar, name, ""); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var retired, inserted error
		wg.Add(2)
		go func() { defer wg.Done(); _, retired = Retire(ctx, v.app, registrar, name) }()
		go func() { defer wg.Done(); _, inserted = v.source(ctx, v.app, name) }()
		wg.Wait()
		if retired != nil && inserted != nil || retired == nil && inserted == nil {
			t.Errorf("%s: retire %v, insert %v", name, retired, inserted)
		}
		if retired == nil {
			wins["retire"]++
		} else {
			wins["insert"]++
		}
	}
	var bad int
	if err := v.owner.QueryRow(ctx, `select count(*) from sources s join accounts a on a.name = s.account
		where a.name like $1 and a.status = 'RETIRED' and s.state <> 'RETIRED'`, v.x+"%").Scan(&bad); err != nil || bad != 0 {
		t.Errorf("%d active sources on retired accounts (%v)", bad, err)
	}
	t.Log(wins)
}

// The two orders of TestRetireRace, forced: the first to take the account's
// row decides, and the other waits for it.
func TestRetireOrder(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	first, second := v.x+"a", v.x+"b"
	for _, n := range []string{first, second} {
		if _, err := Register(ctx, v.app, registrar, n, ""); err != nil {
			t.Fatal(err)
		}
	}

	// a new source first: the retirement waits, then counts it
	tx, err := v.app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := v.source(ctx, tx, first); err != nil {
		t.Fatal(err)
	}
	retired := make(chan error, 1)
	go func() { _, err := Retire(ctx, v.app, registrar, first); retired <- err }()
	select {
	case err := <-retired:
		t.Fatalf("the retirement did not wait for the source: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-retired; slug(err) != "account-in-use" {
		t.Errorf("retired under a new source: %v", err)
	}

	// the retirement first: the new source waits, then is refused
	tx, err = v.app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "update accounts set status = 'RETIRED', retired_by = 't', retired_at = now() where name = $1", second); err != nil {
		t.Fatal(err)
	}
	inserted := make(chan error, 1)
	go func() { _, err := v.source(ctx, v.app, second); inserted <- err }()
	select {
	case err := <-inserted:
		t.Fatalf("the source did not wait for the retirement: %v", err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var pe *pgconn.PgError
	if err := <-inserted; !errors.As(err, &pe) || pe.Code != codeRetired {
		t.Errorf("a source on an account retired meanwhile: %v", err)
	}
	if err := Refused(pe); slug(err) != "account-not-registered" {
		t.Errorf("Refused: %v", err)
	}
}

func TestReads(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	acme, globex := v.x+"a", v.x+"g"
	for _, n := range []string{acme, globex} {
		if _, err := Register(ctx, v.app, registrar, n, n+" display"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := v.source(ctx, v.app, acme); err != nil {
		t.Fatal(err)
	}
	list := func(c changerequests.Caller) []string {
		t.Helper()
		var names []string
		after := v.x
		for {
			page, more, err := List(ctx, v.app, c, structure, after, 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range page {
				if strings.HasPrefix(a.Name, v.x) {
					names = append(names, a.Name)
				}
				after = a.Name
			}
			if !more {
				return names
			}
		}
	}
	for _, tc := range []struct {
		who  changerequests.Caller
		want string
	}{
		{registrar, acme + "," + globex},
		{caller("root", config.RoleFullAccess, "*"), acme + "," + globex},
		{caller("vera", config.RoleViewer, "*"), acme + "," + globex},
		{caller("dom", config.RoleOperator, "cloud/*"), acme + "," + globex},
		{caller("acct", config.RoleApprover, "cloud/"+acme+"/*"), acme},
		{caller("proj", config.RoleOperator, "cloud/"+acme+"/app/p1"), acme}, // a project's role is a role on its account
		{caller("other", config.RoleOperator, "dc/*"), ""},
		{caller("bea", config.RoleBreakGlass, "*"), ""},
	} {
		if got := strings.Join(list(tc.who), ","); got != tc.want {
			t.Errorf("%s lists %q, want %q", tc.who.ID(), got, tc.want)
		}
	}
	a, err := Get(ctx, v.app, registrar, structure, acme)
	if err != nil {
		t.Fatal(err)
	}
	if a.DisplayName != acme+" display" || a.Counts == nil || a.Counts.Sources != 1 || a.Counts.Targets != 0 || a.Counts.Bindings != 0 {
		t.Errorf("get: %+v %+v", a, a.Counts)
	}
	if _, err := Get(ctx, v.app, caller("acct", config.RoleApprover, "cloud/"+globex+"/*"), structure, acme); slug(err) != "not-found" {
		t.Errorf("another account's: %v", err)
	}
	if _, err := Get(ctx, v.app, registrar, structure, v.x+"none"); slug(err) != "not-found" {
		t.Errorf("unknown: %v", err)
	}
}

// TestRegistry: TN-8 and TN-15 on one database: a change reaches a running
// registry by notification, well before its periodic reload.
func TestRegistry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v := setup(t)
	db, name := v.app, "reg"+v.x
	r := NewRegistry(db, time.Hour)
	if err := r.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if r.Active(name) {
		t.Fatal("active before registering")
	}
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	defer func() { cancel(); <-done }()
	waitFor := func(want bool) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if r.Active(name) == want {
				return
			}
		}
		t.Fatalf("Active(%s) never became %v", name, want)
	}
	if _, err := Register(ctx, db, registrar, name, ""); err != nil {
		t.Fatal(err)
	}
	waitFor(true)
	if _, err := Retire(ctx, db, registrar, name); err != nil {
		t.Fatal(err)
	}
	waitFor(false)
}

// TestRegistrySparesThePool: the listener must not take a connection from the
// pool it reads from. On a host with few CPUs, pgx's default pool is 4, which
// the leader's lock loops nearly fill: found on the lab, where every admin
// request then hung.
func TestRegistrySparesThePool(t *testing.T) {
	v := setup(t)
	cfg, err := pgxpool.ParseConfig(dsn(t, "APP"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	r := NewRegistry(db, time.Hour)
	if err := r.Load(ctx); err != nil {
		t.Fatal(err)
	}
	loops, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); r.Run(loops) }()
	t.Cleanup(func() { stop(); <-done })

	name := "s" + v.x
	t.Cleanup(func() { _, _ = v.owner.Exec(context.Background(), "delete from accounts where name = $1", name) })
	if _, err := Register(ctx, v.app, registrar, name, ""); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); !r.Active(name); time.Sleep(50 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the registration did not reach the registry: its listener holds the only connection")
		}
	}
	query, cancelQuery := context.WithTimeout(ctx, 5*time.Second)
	defer cancelQuery()
	var one int
	if err := db.QueryRow(query, "select 1").Scan(&one); err != nil {
		t.Errorf("the pool is unavailable beside the listener: %v", err)
	}
}
