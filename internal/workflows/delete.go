package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
)

// stageRow is a binding_stage_state row: the wiring the stage was ensured
// with and its non-secret artifact (§4.2).
type stageRow struct {
	providerType, providerInstance string
	artifact                       json.RawMessage
}

func (e *Engine) stageRow(ctx context.Context, in ApplyInput, stage string) (*stageRow, error) {
	r := &stageRow{}
	err := e.DB.QueryRow(ctx, "SELECT provider_type, provider_instance, artifact FROM binding_stage_state WHERE binding_id = $1 AND stage = $2",
		in.BindingID, stage).Scan(&r.providerType, &r.providerInstance, &r.artifact)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// delete is DeleteBindingWorkflow (§6.5): the stages cleaned in reverse
// order with the wiring recorded in their rows, then the binding removed.
func (e *Engine) delete(ctx dbos.Context, in ApplyInput) (string, error) {
	id, err := uuid.Parse(in.BindingID)
	if err != nil {
		return "", err
	}
	f := fence{bindingID: id, workflowID: in.WorkflowID}
	fail := func(name string, err error) (string, error) {
		if errors.Is(err, store.ErrFenced) || err.Error() == store.ErrFenced.Error() {
			return "", err
		}
		se := sanitize(err)
		if se.Code == "PLUGIN_ERROR" && !errors.As(err, new(*StepError)) {
			se = &StepError{Code: "WORKFLOW_ERROR", Message: err.Error()}
		}
		if _, ferr := dbos.RunAsStep(ctx, func(c context.Context) (struct{}, error) { return struct{}{}, e.markFailed(c, f, name, se, in) },
			dbos.WithStepName("markFailed")); ferr != nil {
			return "", ferr
		}
		return "DELETE_FAILED", se
	}
	for _, stage := range []string{"SECRET_STORE", "TARGET", "IDENTITY"} {
		name := "cleanup:" + stage
		if _, err := dbos.RunAsStep(ctx, func(c context.Context) (struct{}, error) { return struct{}{}, e.cleanup(c, f, in, stage) },
			dbos.WithStepName(name)); err != nil {
			return fail(name, err)
		}
	}
	if _, err := dbos.RunAsStep(ctx, func(c context.Context) (struct{}, error) { return struct{}{}, e.remove(c, f, in) },
		dbos.WithStepName("deleteBinding")); err != nil {
		return fail("deleteBinding", err)
	}
	return "DELETED", nil
}

// cleanup cleans one stage: skipped when it has no row; its row deleted,
// fenced, once the plugin succeeded (§6.5 steps 1 to 4, INV-04).
func (e *Engine) cleanup(ctx context.Context, f fence, in ApplyInput, stage string) error {
	row, err := e.stageRow(ctx, in, stage)
	if err != nil || row == nil {
		return err
	}
	if err := store.MarkStep(ctx, e.DB, f.bindingID, f.workflowID, "CLEANUP_"+stage, ""); err != nil {
		return err
	}
	identity := &pluginv1.IdentityArtifact{}
	if id, err := e.stageRow(ctx, in, "IDENTITY"); err != nil {
		return err
	} else if id != nil && string(id.artifact) != "{}" {
		if err := protojson.Unmarshal(id.artifact, identity); err != nil {
			return err
		}
	}
	var output struct {
		FinalizedClientSpec json.RawMessage `json:"finalizedClientSpec"`
		FinalizedClientAuth json.RawMessage `json:"finalizedClientAuth"`
	}
	_ = json.Unmarshal(row.artifact, &output) // an empty artifact is tolerated (AC-10)
	b := in.bindingContext()
	var skipped bool
	err = e.call(ctx, func(c context.Context) error {
		switch stage {
		case "SECRET_STORE":
			r, err := e.Plugins.CleanupSecretStore(c, &pluginv1.CleanupSecretStoreRequest{Instance: row.providerInstance, Binding: b,
				FinalizedClientAuthJson: output.FinalizedClientAuth, Identity: identity, SecretStorageStrategy: in.Wiring.Strategy})
			skipped = r.GetSkippedNotOwner()
			return err
		case "TARGET":
			r, err := e.Plugins.CleanupTarget(c, &pluginv1.CleanupTargetRequest{Instance: row.providerInstance, Binding: b, Identity: identity,
				RequestedSpecJson: in.RequestedSpec, FinalizedClientSpecJson: output.FinalizedClientSpec})
			skipped = r.GetSkippedNotOwner()
			return err
		}
		r, err := e.Plugins.CleanupIdentity(c, &pluginv1.CleanupIdentityRequest{Instance: row.providerInstance, Binding: b, PreviousArtifact: identity})
		skipped = r.GetSkippedNotOwner()
		return err
	})
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		if err := store.MarkStep(ctx, tx, f.bindingID, f.workflowID, "CLEANED_"+stage, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM binding_stage_state WHERE binding_id = $1 AND stage = $2", f.bindingID, stage); err != nil {
			return err
		}
		if !skipped {
			return nil
		}
		snap, _ := json.Marshal(map[string]string{"stage": stage, "provider": row.providerType + "/" + row.providerInstance})
		_, err := audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &f.bindingID, ResourceName: in.BindingName,
			Action: "CLEANUP_SKIPPED_NOT_OWNER", Actor: "system:workflow", Revision: &in.Revision, Attempt: &in.Attempt, WorkflowID: f.workflowID, Snapshot: snap})
		return err
	})
}

// remove deletes the binding, its stage rows cascading, and audits
// DELETE_COMPLETED in one fenced transaction (§6.5).
func (e *Engine) remove(ctx context.Context, f fence, in ApplyInput) error {
	return pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "DELETE FROM bindings WHERE id = $1 AND workflow_id = $2 AND phase = 'DELETING'", f.bindingID, f.workflowID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrFenced
		}
		if _, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &f.bindingID, ResourceName: in.BindingName,
			Action: "DELETE_COMPLETED", Actor: "system:workflow", Revision: &in.Revision, Attempt: &in.Attempt, WorkflowID: f.workflowID}); err != nil {
			return err
		}
		return revertOutcome(ctx, tx, f, in, true)
	})
}
