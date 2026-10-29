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
