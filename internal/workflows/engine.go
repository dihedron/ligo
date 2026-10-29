// Package workflows runs the durable binding workflows on DBOS (§6): the
// apply and reapply workflow that provisions a binding's three stages, and
// the operations that start it.
package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/outputvalidation"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
)

// Plugins are the plugin calls the workflows make; Manager adapts the
// plugin manager.
type Plugins interface {
	Health(ctx context.Context, kind pluginv1.PluginKind, instance string) error
	EnsureIdentity(ctx context.Context, req *pluginv1.EnsureIdentityRequest) (*pluginv1.EnsureIdentityResponse, error)
	EnsureTarget(ctx context.Context, req *pluginv1.EnsureTargetRequest) (*pluginv1.EnsureTargetResponse, error)
	EnsureSecretStore(ctx context.Context, req *pluginv1.EnsureSecretStoreRequest) (*pluginv1.EnsureSecretStoreResponse, error)
	CleanupIdentity(ctx context.Context, req *pluginv1.CleanupIdentityRequest) (*pluginv1.CleanupIdentityResponse, error)
	CleanupTarget(ctx context.Context, req *pluginv1.CleanupTargetRequest) (*pluginv1.CleanupTargetResponse, error)
	CleanupSecretStore(ctx context.Context, req *pluginv1.CleanupSecretStoreRequest) (*pluginv1.CleanupSecretStoreResponse, error)
	OutputValidator(kind pluginv1.PluginKind, instance string) *outputvalidation.Validator
}

// Backoff is plugins.retry (§6.1 rule 3).
type Backoff struct {
	Attempts     int
	Initial, Max time.Duration
}

// DefaultBackoff is §6.1 rule 3's: 5 attempts, from 2s to 60s.
var DefaultBackoff = Backoff{Attempts: 5, Initial: 2 * time.Second, Max: 60 * time.Second}

// Engine runs the workflows.
type Engine struct {
	DB      *pgxpool.Pool // the app pool
	DBOS    dbos.Context
	Plugins Plugins
	Sealer  *sealing.Sealer
	Backoff Backoff
}

// Register registers the workflows with DBOS; call it before dbos.Launch.
func (e *Engine) Register() {
	dbos.RegisterWorkflow(e.DBOS, e.apply, dbos.WithWorkflowName("ApplyBindingWorkflow"))
	dbos.RegisterWorkflow(e.DBOS, e.delete, dbos.WithWorkflowName("DeleteBindingWorkflow"))
}

// StepError is a plugin or workflow error as it may be persisted: its code
// and public message only (§6.1 rule 5).
type StepError struct {
	Code, Message string
	Retryable     bool
}

func (e *StepError) Error() string { return e.Code + ": " + e.Message }

// retryable is §6.1 rule 4's classification of gRPC codes.
var retryable = map[codes.Code]bool{codes.Unavailable: true, codes.DeadlineExceeded: true, codes.ResourceExhausted: true, codes.Aborted: true}

// sanitize reduces a plugin error to its code and public message; a
// PluginErrorDetail decides whether it is retryable, else the gRPC code.
func sanitize(err error) *StepError {
	if se := (*StepError)(nil); errors.As(err, &se) {
		return se
	}
	code, d := pluginsdk.FromError(err)
	if d.GetCode() == "PLUGIN_ERROR" && d.GetPublicMessage() == "" { // no detail: the transport's error
		return &StepError{Code: code.String(), Message: "the plugin call failed", Retryable: retryable[code]}
	}
	return &StepError{Code: d.GetCode(), Message: d.GetPublicMessage(), Retryable: d.GetRetryable()}
}

// call runs fn, retrying retryable errors with full-jitter exponential
// backoff; the error it returns is sanitized.
func (e *Engine) call(ctx context.Context, fn func(context.Context) error) error {
	b := e.Backoff
	if b.Attempts == 0 {
		b = DefaultBackoff
	}
	delay := b.Initial
	for attempt := 1; ; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		se := sanitize(err)
		if !se.Retryable || attempt >= b.Attempts {
			return se
		}
		select {
		case <-ctx.Done():
			return se
		case <-time.After(time.Duration(rand.Int64N(int64(delay) + 1))): // #nosec G404 -- jitter, not a secret
		}
		delay = min(delay*2, b.Max)
	}
}

// Manager adapts the plugin manager: every call is mediated by it (§5.3).
func Manager(m *pluginmgr.Manager) Plugins { return managed{m} }

type managed struct{ m *pluginmgr.Manager }

func (p managed) Health(ctx context.Context, kind pluginv1.PluginKind, instance string) error {
	return p.m.Call(ctx, kind, instance, false, func(ctx context.Context, c *pluginmgr.Client) error {
		h, err := c.Control.Health(ctx, &pluginv1.HealthRequest{Instance: instance})
		if err == nil && !h.GetServing() {
			return pluginsdk.Error(codes.Unavailable, "PLUGIN_UNHEALTHY", "the plugin instance is not serving", true)
		}
		return err
	})
}

func (p managed) EnsureIdentity(ctx context.Context, req *pluginv1.EnsureIdentityRequest) (resp *pluginv1.EnsureIdentityResponse, err error) {
	err = p.m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, req.GetInstance(), true, func(ctx context.Context, c *pluginmgr.Client) error {
		resp, err = c.Identity.EnsureIdentity(ctx, req)
		return err
	})
	return resp, err
}

func (p managed) EnsureTarget(ctx context.Context, req *pluginv1.EnsureTargetRequest) (resp *pluginv1.EnsureTargetResponse, err error) {
	err = p.m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, req.GetInstance(), true, func(ctx context.Context, c *pluginmgr.Client) error {
		resp, err = c.Platform.EnsureTarget(ctx, req)
		return err
	})
	return resp, err
}

func (p managed) EnsureSecretStore(ctx context.Context, req *pluginv1.EnsureSecretStoreRequest) (resp *pluginv1.EnsureSecretStoreResponse, err error) {
	err = p.m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, req.GetInstance(), true, func(ctx context.Context, c *pluginmgr.Client) error {
		resp, err = c.Store.EnsureSecretStore(ctx, req)
		return err
	})
	return resp, err
}

func (p managed) CleanupIdentity(ctx context.Context, req *pluginv1.CleanupIdentityRequest) (resp *pluginv1.CleanupIdentityResponse, err error) {
	err = p.m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, req.GetInstance(), true, func(ctx context.Context, c *pluginmgr.Client) error {
		resp, err = c.Identity.CleanupIdentity(ctx, req)
		return err
	})
	return resp, err
}

func (p managed) CleanupTarget(ctx context.Context, req *pluginv1.CleanupTargetRequest) (resp *pluginv1.CleanupTargetResponse, err error) {
	err = p.m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, req.GetInstance(), true, func(ctx context.Context, c *pluginmgr.Client) error {
		resp, err = c.Platform.CleanupTarget(ctx, req)
		return err
	})
	return resp, err
}

func (p managed) CleanupSecretStore(ctx context.Context, req *pluginv1.CleanupSecretStoreRequest) (resp *pluginv1.CleanupSecretStoreResponse, err error) {
	err = p.m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, req.GetInstance(), true, func(ctx context.Context, c *pluginmgr.Client) error {
		resp, err = c.Store.CleanupSecretStore(ctx, req)
		return err
	})
	return resp, err
}

func (p managed) OutputValidator(kind pluginv1.PluginKind, instance string) *outputvalidation.Validator {
	return p.m.OutputValidator(kind, instance)
}

// Wiring is a binding's three plugin instances and its storage strategy,
// fixed at creation (INV-08).
type Wiring struct {
	IdentityType     string `json:"identityType"`
	IdentityInstance string `json:"identityInstance"`
	PlatformType     string `json:"platformType"`
	Platform         string `json:"platform"`
	StoreType        string `json:"storeType"`
	StoreInstance    string `json:"storeInstance"`
	Strategy         string `json:"strategy"`
}

// ApplyInput is the input of an apply or reapply workflow: what the
// binding row says for this attempt (step outputs and inputs are JSON DTOs,
// never Protobuf, EXT-07).
type ApplyInput struct {
	BindingID            string          `json:"bindingId"`
	BindingName          string          `json:"bindingName"`
	WorkflowID           string          `json:"workflowId"`
	Operation            string          `json:"operation"` // APPLY, REAPPLY
	Revision             int64           `json:"revision"`
	Attempt              int64           `json:"attempt"`
	Rotate               bool            `json:"rotate"`
	Zone                 string          `json:"zone"`
	TrustDomain          string          `json:"trustDomain"`
	SVIDRegex            string          `json:"svidRegex"`
	DerivedPrincipalName string          `json:"derivedPrincipalName"`
	Source               string          `json:"source"`
	SourceRevision       int64           `json:"sourceRevision"`
	TargetID             string          `json:"targetId"`
	Target               string          `json:"target"`
	TargetRevision       int64           `json:"targetRevision"`
	AccessLevel          string          `json:"accessLevel"`
	RequestedSpec        json.RawMessage `json:"requestedSpec"`
	Wiring               Wiring          `json:"wiring"`
}

// Start starts the workflow of a PROVISIONING or DELETING binding under its
// workflow_id; starting a started workflow returns it again (EXT-02).
func (e *Engine) Start(ctx context.Context, bindingID uuid.UUID) (dbos.WorkflowHandle[string], error) {
	in := ApplyInput{BindingID: bindingID.String()}
	var phase string
	var targetID uuid.UUID
	err := e.DB.QueryRow(ctx, `SELECT b.name, b.workflow_id, b.operation, b.revision, b.attempt, b.rotate_static_secrets, b.zone,
		b.source_trust_domain, b.source_svid_regex, b.derived_principal_name, s.name, b.source_revision, b.target_id, t.name,
		b.target_revision, b.access_level, b.requested_spec, b.identity_provider_type, b.identity_provider_instance, b.platform_type,
		b.platform, b.secret_store_type, b.secret_store_instance, b.secret_storage_strategy, b.phase
		FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id WHERE b.id = $1`, bindingID).
		Scan(&in.BindingName, &in.WorkflowID, &in.Operation, &in.Revision, &in.Attempt, &in.Rotate, &in.Zone, &in.TrustDomain,
			&in.SVIDRegex, &in.DerivedPrincipalName, &in.Source, &in.SourceRevision, &targetID, &in.Target, &in.TargetRevision,
			&in.AccessLevel, &in.RequestedSpec, &in.Wiring.IdentityType, &in.Wiring.IdentityInstance, &in.Wiring.PlatformType,
			&in.Wiring.Platform, &in.Wiring.StoreType, &in.Wiring.StoreInstance, &in.Wiring.Strategy, &phase)
	if err != nil {
		return nil, fmt.Errorf("workflows: binding %s: %w", bindingID, err)
	}
	in.TargetID = targetID.String()
	switch {
	case phase == "PROVISIONING" && in.Operation != "DELETE":
		return dbos.RunWorkflow(e.DBOS, e.apply, in, dbos.WithWorkflowID(in.WorkflowID))
	case phase == "DELETING" && in.Operation == "DELETE":
		return dbos.RunWorkflow(e.DBOS, e.delete, in, dbos.WithWorkflowID(in.WorkflowID))
	}
	return nil, fmt.Errorf("workflows: binding %s is %s (%s): no workflow to run", bindingID, phase, in.Operation)
}

// Retry starts a new attempt of a FAILED binding, with rotation, or of a
// DELETE_FAILED one, which resumes its cleanup (§3.11, §6.5): same revision
// and operation, a new workflow ID (INV-09).
func (e *Engine) Retry(ctx context.Context, bindingID uuid.UUID, actor string) (dbos.WorkflowHandle[string], error) {
	err := pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		var name, op string
		var revision, attempt int64
		err := tx.QueryRow(ctx, `UPDATE bindings SET attempt = attempt + 1, current_step = 'INIT', status_message = '',
			phase = CASE phase WHEN 'FAILED' THEN 'PROVISIONING'::binding_phase ELSE 'DELETING'::binding_phase END,
			rotate_static_secrets = (phase = 'FAILED') OR rotate_static_secrets,
			last_transition_at = now(), updated_at = now(), updated_by = $2,
			workflow_id = format('ligo:%s:%s:r%s:a%s', lower(operation::text), id, revision, attempt + 1)
			WHERE id = $1 AND phase IN ('FAILED', 'DELETE_FAILED') RETURNING name, operation, revision, attempt`, bindingID, actor).Scan(&name, &op, &revision, &attempt)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("workflows: binding %s is neither FAILED nor DELETE_FAILED", bindingID)
		}
		if err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &bindingID, ResourceName: name,
			Action: op + "_STARTED", Actor: actor, Revision: &revision, Attempt: &attempt})
		return err
	})
	if err != nil {
		return nil, err
	}
	return e.Start(ctx, bindingID)
}

// fence is what every write of a workflow is fenced on (ADR-08).
type fence struct {
	bindingID  uuid.UUID
	workflowID string
}

// markFailed records a terminal error of the attempt: FAILED for an apply,
// DELETE_FAILED for a delete (§6.4 failure path, §6.5).
func (e *Engine) markFailed(ctx context.Context, f fence, step string, cause *StepError, in ApplyInput) error {
	from, to, action := "PROVISIONING", "FAILED", "PROVISION_FAILURE"
	if in.Operation == "DELETE" {
		from, to, action = "DELETING", "DELETE_FAILED", "DELETE_FAILURE"
	}
	return pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE bindings SET phase = $5, current_step = $3, status_message = left($4, 2048),
			last_transition_at = now(), updated_at = now() WHERE id = $1 AND workflow_id = $2 AND phase = $6`,
			f.bindingID, f.workflowID, step, cause.Error(), to, from)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrFenced
		}
		snap, _ := json.Marshal(map[string]string{"step": step, "code": cause.Code, "message": cause.Message})
		_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &f.bindingID, ResourceName: in.BindingName,
			Action: action, Actor: "system:workflow", Revision: &in.Revision, Attempt: &in.Attempt, WorkflowID: f.workflowID, Snapshot: snap})
		return err
	})
}
