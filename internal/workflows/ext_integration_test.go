//go:build integration

package workflows

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	"github.com/jackc/pgx/v5"
)

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

// counted is a step's output: a plain DTO with JSON tags (EXT-07).
type counted struct {
	Input string `json:"input"`
	Runs  int64  `json:"runs"`
}

// runs counts the executions of the step, to see what DBOS replays.
var runs atomic.Int64

func countingWorkflow(ctx dbos.Context, input string) (counted, error) {
	return dbos.RunAsStep(ctx, func(context.Context) (counted, error) {
		return counted{Input: input, Runs: runs.Add(1)}, nil
	}, dbos.WithStepName("count"))
}

// TestEXT checks the SDK assumptions of §12 on the pinned DBOS version,
// with its own DSN and role (EXT-01 to EXT-09).
func TestEXT(t *testing.T) {
	ctx := context.Background()
	d, err := dbos.NewContext(ctx, dbos.Config{AppName: "ligo-ext-test", DatabaseURL: dsn(t, "DBOS"),
		DatabaseSchema: "dbos", ApplicationVersion: "ext-v1"})
	if err != nil {
		t.Fatalf("EXT-08: DBOS on ligo_dbos and its schema: %v", err)
	}
	dbos.RegisterWorkflow(d, countingWorkflow)
	if err := dbos.Launch(d); err != nil {
		t.Fatalf("EXT-08: launch: %v", err)
	}
	t.Cleanup(func() { _ = dbos.Shutdown(d, 5*time.Second) })

	// EXT-01, EXT-02, EXT-07: steps; a caller-supplied ID; a JSON DTO output
	id := "ligo:apply:" + uuid.NewV7().String() + ":r1:a1"
	h, err := dbos.RunWorkflow(d, countingWorkflow, "x", dbos.WithWorkflowID(id))
	if err != nil {
		t.Fatal(err)
	}
	first, err := h.GetResult()
	if err != nil || first.Input != "x" || first.Runs == 0 {
		t.Fatalf("EXT-01/07: result %+v (%v)", first, err)
	}
	// EXT-02: starting a known ID again is idempotent: the step is not run again
	h2, err := dbos.RunWorkflow(d, countingWorkflow, "x", dbos.WithWorkflowID(id))
	if err != nil {
		t.Fatalf("EXT-02: restart: %v", err)
	}
	again, err := h2.GetResult()
	if err != nil || again != first {
		t.Errorf("EXT-02: second start gave %+v (%v), want %+v", again, err, first)
	}

	// EXT-03: status by ID, through the SDK and read-only through SQL
	got, err := dbos.RetrieveWorkflow[counted](d, id)
	if err != nil {
		t.Fatalf("EXT-03: retrieve: %v", err)
	}
	st, err := got.GetStatus()
	if err != nil || st.Status != dbos.WorkflowStatusSuccess {
		t.Errorf("EXT-03: status %v (%v)", st.Status, err)
	}
	// EXT-09: the workflow records the application version that ran it
	if st.ApplicationVersion != "ext-v1" {
		t.Errorf("EXT-09: application version %q", st.ApplicationVersion)
	}
	conn, err := pgx.Connect(ctx, dsn(t, "DBOS"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	var status string
	if err := conn.QueryRow(ctx, "SELECT status FROM dbos.workflow_status WHERE workflow_uuid = $1", id).Scan(&status); err != nil || status != "SUCCESS" {
		t.Errorf("EXT-03: SQL status %q (%v)", status, err)
	}
	if _, err := dbos.RetrieveWorkflow[counted](d, "ligo:apply:missing"); err == nil {
		t.Error("EXT-03: an unknown ID was found")
	}

	// EXT-08: ligo_dbos has no access to the application's tables
	if _, err := conn.Exec(ctx, "SELECT 1 FROM public.bindings LIMIT 1"); err == nil {
		t.Error("EXT-08: ligo_dbos reads public.bindings")
	}

	// EXT-06: retention: finished workflows can be listed by age and deleted
	old, err := dbos.ListWorkflows(d, dbos.WithFilterWorkflowIDs(id), dbos.WithFilterCreatedBefore(time.Now().Add(time.Minute)), dbos.WithFilterStatus(dbos.WorkflowStatusSuccess))
	if err != nil || len(old) != 1 {
		t.Fatalf("EXT-06: list %d (%v)", len(old), err)
	}
	if err := dbos.DeleteWorkflows(d, []string{id}); err != nil {
		t.Fatalf("EXT-06: delete: %v", err)
	}
	if err := conn.QueryRow(ctx, "SELECT status FROM dbos.workflow_status WHERE workflow_uuid = $1", id).Scan(&status); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("EXT-06: deleted workflow still there (%v)", err)
	}
}

// ext20Runs counts the step of ext20Workflow; while ext20Hang is set the
// workflow stops after it, as if its replica had died.
var (
	ext20Runs atomic.Int64
	ext20Hang atomic.Bool
)

func ext20Workflow(ctx dbos.Context, input string) (counted, error) {
	c, err := dbos.RunAsStep(ctx, func(context.Context) (counted, error) {
		return counted{Input: input, Runs: ext20Runs.Add(1)}, nil
	}, dbos.WithStepName("count"))
	if err == nil && ext20Hang.Load() {
		select {} // never returns: the row stays PENDING, the replica is gone
	}
	return c, err
}

// TestEXT20: ResumeWorkflows runs the PENDING workflow of a dead executor on
// the caller's, without repeating its finished steps, and that executor does
// not run it again when it comes back (§10.2).
func TestEXT20(t *testing.T) {
	x := uuid.NewV7().String()
	launch := func(executor string) dbos.Context {
		t.Helper()
		d, err := dbos.NewContext(context.Background(), dbos.Config{AppName: "ligo-ext-test", DatabaseURL: dsn(t, "DBOS"),
			DatabaseSchema: "dbos", ApplicationVersion: "ext-v1", ExecutorID: executor})
		if err != nil {
			t.Fatal(err)
		}
		dbos.RegisterWorkflow(d, ext20Workflow)
		if err := dbos.Launch(d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	gone, there := "ext20-gone-"+x, "ext20-there-"+x
	id := "ligo:apply:" + x + ":r1:a1"

	ext20Hang.Store(true)
	a := launch(gone)
	if _, err := dbos.RunWorkflow(a, ext20Workflow, "x", dbos.WithWorkflowID(id)); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(10 * time.Second); ext20Runs.Load() == 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the step did not run")
		}
	}
	time.Sleep(200 * time.Millisecond) // its output is checkpointed
	_ = dbos.Shutdown(a, time.Second)
	ext20Hang.Store(false)

	b := launch(there)
	t.Cleanup(func() { _ = dbos.Shutdown(b, 5*time.Second) })
	pending, err := dbos.ListWorkflows(b, dbos.WithFilterStatus(dbos.WorkflowStatusPending), dbos.WithFilterExecutorIDs(gone),
		dbos.WithFilterLoadInput(false), dbos.WithFilterLoadOutput(false))
	if err != nil || len(pending) != 1 || pending[0].ID != id || pending[0].ApplicationVersion != "ext-v1" {
		t.Fatalf("EXT-20: pending of the dead executor: %+v (%v)", pending, err)
	}
	handles, err := dbos.ResumeWorkflows[counted](b, []string{id})
	if err != nil || len(handles) != 1 {
		t.Fatalf("EXT-20: resume: %d (%v)", len(handles), err)
	}
	got, err := handles[0].GetResult()
	if err != nil || got.Runs != 1 || ext20Runs.Load() != 1 {
		t.Fatalf("EXT-20: result %+v (%v), the step ran %d times", got, err, ext20Runs.Load())
	}
	st, err := handles[0].GetStatus()
	if err != nil || st.ExecutorID != there || st.Status != dbos.WorkflowStatusSuccess {
		t.Fatalf("EXT-20: status %+v (%v)", st, err)
	}

	back := launch(gone)
	t.Cleanup(func() { _ = dbos.Shutdown(back, 5*time.Second) })
	time.Sleep(3 * time.Second) // recovery and a few polls of the queue
	if ext20Runs.Load() != 1 {
		t.Errorf("EXT-20: the returning executor ran the step: %d runs", ext20Runs.Load())
	}
	if st, err := handles[0].GetStatus(); err != nil || st.ExecutorID != there {
		t.Errorf("EXT-20: after the executor came back: %+v (%v)", st, err)
	}
}
