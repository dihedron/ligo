package workflows

import (
	"context"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
)

// ExecutorID is this replica's executor ID.
func (e *Engine) ExecutorID() string { return e.DBOS.GetExecutorID() }

// ApplicationVersion is the version of the workflows this replica runs.
func (e *Engine) ApplicationVersion() string { return e.DBOS.GetApplicationVersion() }

// Pending lists the PENDING workflows of every executor, without their
// inputs and outputs.
func (e *Engine) Pending(context.Context) ([]dbos.WorkflowStatus, error) {
	return dbos.ListWorkflows(e.DBOS, dbos.WithFilterStatus(dbos.WorkflowStatusPending),
		dbos.WithFilterLoadInput(false), dbos.WithFilterLoadOutput(false))
}

// Resume re-enqueues workflows; the replica that dequeues one becomes its
// executor (§10.2, EXT-20).
func (e *Engine) Resume(_ context.Context, ids []string) error {
	_, err := dbos.ResumeWorkflows[any](e.DBOS, ids)
	return err
}
