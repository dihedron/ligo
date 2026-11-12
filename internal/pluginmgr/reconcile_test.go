package pluginmgr

import (
	"context"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/instances"
	"github.com/dihedron/ligo/internal/metrics"
)

// TestReconcile: instances added, changed and removed at run time reach the
// running process with no restart; a new (type, realm) starts a process and
// an empty one stops it (.specs/ligo-instances.md §7.2).
func TestReconcile(t *testing.T) {
	ctx := context.Background()
	m, _, err := newManager(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false)}})
	if err != nil {
		t.Fatal(err)
	}
	// one more instance in the running process, and a process for a new realm
	if err := m.Reconcile(ctx, prepare(t,
		Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false), instance("pg-dr", "b", false)}},
		Spec{Realm: test, Instances: []*pluginv1.InstanceDescriptor{instance("pg-test", "c", false)}})); err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{"pg-prod": "spiffe://prod.lab/plugin/pg-prod", "pg-dr": "spiffe://prod.lab/plugin/pg-dr", "pg-test": "spiffe://test.lab/plugin/pg-test"} {
		if got := m.Resolved(target, name); got != id {
			t.Errorf("%s resolved %q", name, got)
		}
		if msg, err := health(ctx, m, name); err != nil || !strings.HasPrefix(msg, "ok "+name) {
			t.Errorf("%s: (%q, %v)", name, msg, err)
		}
	}
	if n := len(m.procs); n != 4 { // two test.v1, svid.v1, none.v1
		t.Errorf("%d processes", n)
	}
	// pg-dr removed, the test realm emptied
	if err := m.Reconcile(ctx, prepare(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false)}})); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"pg-dr", "pg-test"} {
		if _, err := health(ctx, m, gone); err == nil {
			t.Errorf("%s still answers", gone)
		}
	}
	if _, err := health(ctx, m, "pg-prod"); err != nil {
		t.Errorf("pg-prod: %v", err)
	}
	if n := len(m.procs); n != 3 {
		t.Errorf("%d processes after the test realm emptied", n)
	}
	// nothing left: every process stops
	if err := m.Reconcile(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if n := len(m.procs); n != 0 {
		t.Errorf("%d processes with no instance", n)
	}
}

// TestReconcileRefused: a set the plugin or ligo refuses leaves the process
// serving its previous one, and is counted.
func TestReconcileRefused(t *testing.T) {
	ctx := context.Background()
	m, _, err := newManager(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false)}})
	if err != nil {
		t.Fatal(err)
	}
	before := metrics.Count(metrics.ReconfigureFailures, "test.v1", "prod")
	for name, extra := range map[string]*pluginv1.InstanceDescriptor{
		"the plugin refuses":         instance("pg-two", "two", false),
		"a shared SVID, not allowed": instance("pg-shared", "shared", false),
		"a foreign trust domain":     instance("pg-foreign", "foreign", false),
	} {
		specs := prepare(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false), extra}})
		if name == "a shared SVID, not allowed" {
			specs = prepare(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "shared", false), extra}})
		}
		if err := m.Reconcile(ctx, specs); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if got := m.Resolved(target, "pg-prod"); got != "spiffe://prod.lab/plugin/pg-prod" {
			t.Errorf("%s: pg-prod now resolves %q", name, got)
		}
		if _, err := health(ctx, m, extra.GetName()); err == nil {
			t.Errorf("%s: the refused instance answers", name)
		}
	}
	if got := metrics.Count(metrics.ReconfigureFailures, "test.v1", "prod") - before; got != 3 {
		t.Errorf("%v failures counted", got)
	}
}

// TestNotifyDebounced: changes in quick succession are reconciled once, to
// the last set.
func TestNotifyDebounced(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m, logs, err := newManager(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false)}})
	if err != nil {
		t.Fatal(err)
	}
	go m.Run(ctx)
	for _, extra := range []string{"pg-1", "pg-2", "pg-3"} {
		m.Notify(prepare(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false), instance(extra, extra, false)}}))
		time.Sleep(20 * time.Millisecond)
	}
	deadline := time.Now().Add(5 * time.Second)
	for m.Resolved(target, "pg-3") == "" && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if m.Resolved(target, "pg-3") == "" || m.Resolved(target, "pg-1") != "" {
		t.Fatalf("pg-1 %q, pg-3 %q", m.Resolved(target, "pg-1"), m.Resolved(target, "pg-3"))
	}
	if n := strings.Count(logs.String(), "plugin instances reconfigured"); n != 1 {
		t.Errorf("%d reconfigurations", n)
	}
}

// TestRestartAfterReconcile: a crashed process comes back with the instances
// in force now, not those of the first start.
func TestRestartAfterReconcile(t *testing.T) {
	ctx := context.Background()
	m, _, err := newManager(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Reconcile(ctx, prepare(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false), instance("crash", "c", false)}})); err != nil {
		t.Fatal(err)
	}
	_, _ = health(ctx, m, "crash") // the test plugin exits
	deadline := time.Now().Add(5 * time.Second)
	for {
		if msg, err := health(ctx, m, "pg-prod"); err == nil && strings.HasPrefix(msg, "ok") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not restarted")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := m.Resolved(target, "crash"); got != "spiffe://prod.lab/plugin/crash" {
		t.Errorf("the restarted process lost the reconciled instance: %q", got)
	}
}

// TestValidateTransient: the first instance of a (type, realm) is checked
// by a process started for the check, which does not stay.
func TestValidateTransient(t *testing.T) {
	m, _, err := newManager(t, Spec{Realm: prod, Instances: []*pluginv1.InstanceDescriptor{instance("pg-prod", "a", false)}})
	if err != nil {
		t.Fatal(err)
	}
	m.opts.Realms["test"] = test
	before := len(m.procs)
	d := &instances.Definition{Kind: "Platform", Type: "test.v1", Metadata: instances.Metadata{Name: "pg-new", Realm: "test"},
		SVIDSelector: &instances.SVIDSelector{MatchExpr: "x"}, Config: []byte(`{"endpoints":["db.test.lab:5432"]}`)}
	id, endpoints, err := Instances(m).Validate(context.Background(), instances.Platform, d)
	if err != nil || id != "spiffe://test.lab/plugin/pg-new" || len(endpoints) != 1 || endpoints[0] != "db.test.lab:5432" {
		t.Fatalf("got %q %v %v", id, endpoints, err)
	}
	if len(m.procs) != before {
		t.Errorf("the check's process stayed: %d processes", len(m.procs))
	}
	d.Metadata.Realm = "mars"
	if _, _, err := Instances(m).Validate(context.Background(), instances.Platform, d); err == nil || !strings.Contains(err.Error(), "mars") {
		t.Errorf("unknown realm: %v", err)
	}
}
