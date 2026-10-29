//go:build integration

package bindings

import (
	"context"
	"slices"
	"testing"
	"uuid"

	"github.com/jackc/pgx/v5/pgxpool"
)

// enqueue changes the source of binding name to regex, a new revision,
// and queues the binding as §6.2.1 step 5 does; it returns the cause.
func enqueue(t *testing.T, o *pgxpool.Pool, name, regex string, priority int) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	cr := uuid.NewV7()
	if regex != "" {
		if _, err := o.Exec(ctx, `update sources set svid_regex = $2, revision = revision + 1
			where id = (select source_id from bindings where name = $1)`, name, regex); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := o.Exec(ctx, `insert into binding_propagation_queue (binding_id, cause_change_request_id, cause, priority)
		select id, $2, 'SOURCE', $3 from bindings where name = $1`, name, cr, priority); err != nil {
		t.Fatal(err)
	}
	return cr
}

// source adds a source in dc/corp-prod for one more binding.
func source(t *testing.T, o *pgxpool.Pool, w *world, n string) string {
	t.Helper()
	name := "dc-src-" + n + "-" + w.suffix
	if _, err := o.Exec(context.Background(), `insert into sources (id, name, scope, trust_domain, svid_regex, visibility, created_by, updated_by)
		values ($1, $2, 'dc/corp-prod', 'prod.internal', $3, 'PUBLIC', 't', 't')`, uuid.NewV7(), name,
		`^spiffe://prod\.internal/ns/payments/sa/`+n+`-`+w.suffix+`$`); err != nil {
		t.Fatal(err)
	}
	return name
}

type propagated struct {
	phase, workflow, updatedBy string
	revision, sourceRevision   int64
	rotate, queued             bool
}

func propagation(t *testing.T, o *pgxpool.Pool, name string) propagated {
	t.Helper()
	var p propagated
	err := o.QueryRow(context.Background(), `select b.phase, b.workflow_id, b.updated_by, b.revision, b.source_revision, b.rotate_static_secrets,
		exists (select 1 from binding_propagation_queue q where q.binding_id = b.id) from bindings b where b.name = $1`, name).Scan(
		&p.phase, &p.workflow, &p.updatedBy, &p.revision, &p.sourceRevision, &p.rotate, &p.queued)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func audited(t *testing.T, o *pgxpool.Pool, name, action string) (n int, cr uuid.UUID) {
	t.Helper()
	if err := o.QueryRow(context.Background(), `select count(*), coalesce(max(change_request_id::text), $3)::uuid from audit_log
		where resource_name = $1 and action = $2`, name, action, uuid.Nil().String()).Scan(&n, &cr); err != nil {
		t.Fatal(err)
	}
	return n, cr
}

// TestAC61: a narrowed source regex queues its binding with priority 0;
// the propagator re-applies it at a new revision composed from the new
// source, with rotation, and audits PROPAGATION_STARTED with the cause
// (§6.8, INV-26).
func TestAC61(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	var started []uuid.UUID
	s.Start = func(_ context.Context, id uuid.UUID) error { started = append(started, id); return nil }
	name := "dd-" + w.suffix
	active(t, s, o, dcOp, name, w.dcSrc, w.dcShared, "read", "", dcApp)
	before := propagation(t, o, name)
	cr := enqueue(t, o, name, `^spiffe://prod\.internal/ns/payments/sa/`+w.suffix+`-a$`, 0)
	if p := propagation(t, o, name); !p.queued {
		t.Fatal("not queued") // INV-26: queued until re-applied
	}
	if _, err := (&Propagator{Service: s, MaxConcurrent: 100}).Propagate(ctx); err != nil {
		t.Log(err) // rows of other packages' tests
	}
	p := propagation(t, o, name)
	var id uuid.UUID
	if err := o.QueryRow(ctx, "select id from bindings where name = $1", name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if p.phase != "PROVISIONING" || p.revision != 2 || p.sourceRevision != before.sourceRevision+1 || !p.rotate || p.queued ||
		p.updatedBy != "system:propagator" || p.workflow != "ligo:apply:"+id.String()+":r2:a2" {
		t.Errorf("binding %+v", p)
	}
	if n, by := audited(t, o, name, "PROPAGATION_STARTED"); n != 1 || by != cr {
		t.Errorf("PROPAGATION_STARTED %d by %s", n, by)
	}
	if !slices.Contains(started, id) {
		t.Errorf("not started: %v", started)
	}
}

// TestAC76: during maintenance only narrowings (priority 0) start; a busy
// binding keeps its row, deferred and audited once; at most max_concurrent
// propagations run; the rest start once there is room (§6.8).
func TestAC76(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	narrow, other, busy := "dd-n-"+w.suffix, "dd-o-"+w.suffix, "dd-b-"+w.suffix
	active(t, s, o, dcOp, narrow, source(t, o, w, "n"), w.dcShared, "read", "", dcApp)
	active(t, s, o, dcOp, other, source(t, o, w, "o"), w.dcShared, "read", "", dcApp)
	active(t, s, o, dcOp, busy, source(t, o, w, "b"), w.dcShared, "read", "", dcApp)
	enqueue(t, o, narrow, "", 0)
	enqueue(t, o, other, "", 1)
	enqueue(t, o, busy, "", 0)
	if _, err := o.Exec(ctx, "update bindings set phase = 'PROVISIONING' where name = $1", busy); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Exec(ctx, "update system_settings set maintenance_mode = true"); err != nil {
		t.Fatal(err)
	}
	p := &Propagator{Service: s, MaxConcurrent: 2}
	_, err := p.Propagate(ctx)
	_, err2 := p.Propagate(ctx) // the busy one deferred again, audited once
	_, _ = o.Exec(ctx, "update system_settings set maintenance_mode = false")
	if err != nil || err2 != nil {
		t.Log(err, err2)
	}
	if r := propagation(t, o, narrow); r.revision != 2 || r.queued {
		t.Errorf("narrowing during maintenance %+v", r)
	}
	if r := propagation(t, o, other); r.revision != 1 || !r.queued {
		t.Errorf("priority 1 during maintenance %+v", r)
	}
	var attempts int
	if err := o.QueryRow(ctx, "select attempts from binding_propagation_queue q join bindings b on b.id = q.binding_id where b.name = $1",
		busy).Scan(&attempts); err != nil || attempts != 2 {
		t.Errorf("busy row: %d attempts (%v)", attempts, err)
	}
	if n, _ := audited(t, o, busy, "PROPAGATION_DEFERRED"); n != 1 {
		t.Errorf("PROPAGATION_DEFERRED %d times", n)
	}

	// the narrowing still runs: max_concurrent 1 starts nothing more
	p.MaxConcurrent = 1
	if _, err := p.Propagate(ctx); err != nil {
		t.Log(err)
	}
	if r := propagation(t, o, other); r.revision != 1 {
		t.Errorf("beyond max_concurrent %+v", r)
	}
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = any($1)", []string{narrow, busy}); err != nil {
		t.Fatal(err)
	}
	p.MaxConcurrent = 2
	if _, err := p.Propagate(ctx); err != nil {
		t.Log(err)
	}
	for _, name := range []string{other, busy} {
		if r := propagation(t, o, name); r.revision != 2 || r.queued {
			t.Errorf("%s after the drain %+v", name, r)
		}
	}
}
