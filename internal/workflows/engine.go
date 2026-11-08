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
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/metrics"
	"github.com/dihedron/ligo/internal/outputvalidation"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/tracing"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
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

func (e *StepError) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

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
	Realm                string          `json:"realm"`
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
	TraceParent          string          `json:"traceParent,omitempty"` // the starting request's trace (§10.1), journaled for a recovery
}

// Start starts the workflow of a PROVISIONING or DELETING binding under its
// workflow_id; starting a started workflow returns it again (EXT-02).
func (e *Engine) Start(ctx context.Context, bindingID uuid.UUID) (dbos.WorkflowHandle[string], error) {
	in, phase, err := e.input(ctx, bindingID)
	if err != nil {
		return nil, err
	}
	in.TraceParent = traceParent(ctx)
	switch {
	case phase == "PROVISIONING" && in.Operation != "DELETE":
		return dbos.RunWorkflow(e.DBOS, e.apply, in, dbos.WithWorkflowID(in.WorkflowID))
	case phase == "DELETING" && in.Operation == "DELETE":
		return dbos.RunWorkflow(e.DBOS, e.delete, in, dbos.WithWorkflowID(in.WorkflowID))
	}
	return nil, fmt.Errorf("workflows: binding %s is %s (%s): no workflow to run", bindingID, phase, in.Operation)
}

// input reads the input of a binding's current attempt, and its phase.
func (e *Engine) input(ctx context.Context, bindingID uuid.UUID) (ApplyInput, string, error) {
	in := ApplyInput{BindingID: bindingID.String()}
	var phase string
	var targetID uuid.UUID
	err := e.DB.QueryRow(ctx, `SELECT b.name, b.workflow_id, b.operation, b.revision, b.attempt, b.rotate_static_secrets, b.realm,
		b.source_trust_domain, b.source_svid_regex, b.derived_principal_name, s.name, b.source_revision, b.target_id, t.name,
		b.target_revision, b.access_level, b.requested_spec, b.identity_provider_type, b.identity_provider_instance, b.platform_type,
		b.platform, b.secret_store_type, b.secret_store_instance, b.secret_storage_strategy, b.phase
		FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id WHERE b.id = $1`, bindingID).
		Scan(&in.BindingName, &in.WorkflowID, &in.Operation, &in.Revision, &in.Attempt, &in.Rotate, &in.Realm, &in.TrustDomain,
			&in.SVIDRegex, &in.DerivedPrincipalName, &in.Source, &in.SourceRevision, &targetID, &in.Target, &in.TargetRevision,
			&in.AccessLevel, &in.RequestedSpec, &in.Wiring.IdentityType, &in.Wiring.IdentityInstance, &in.Wiring.PlatformType,
			&in.Wiring.Platform, &in.Wiring.StoreType, &in.Wiring.StoreInstance, &in.Wiring.Strategy, &phase)
	if err != nil {
		return in, "", fmt.Errorf("workflows: binding %s: %w", bindingID, err)
	}
	in.TargetID = targetID.String()
	return in, phase, nil
}

// Retry starts a new attempt of a FAILED binding, with rotation, or of a
// DELETE_FAILED one, which resumes its cleanup (§3.11, §6.5): same revision
// and operation, a new workflow ID (INV-09).
func (e *Engine) Retry(ctx context.Context, bindingID uuid.UUID, actor string) (dbos.WorkflowHandle[string], error) {
	err := pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		if err := changerequests.Maintenance(ctx, tx); err != nil { // §10.3: no retry in maintenance
			return err
		}
		var name, op string
		var revision, attempt int64
		err := tx.QueryRow(ctx, `UPDATE bindings SET attempt = attempt + 1, current_step = 'INIT', status_message = '',
			phase = CASE phase WHEN 'FAILED' THEN 'PROVISIONING'::binding_phase ELSE 'DELETING'::binding_phase END,
			rotate_static_secrets = (phase = 'FAILED') OR rotate_static_secrets,
			last_transition_at = now(), updated_at = now(), updated_by = $2,
			workflow_id = format('ligo:%s:%s:r%s:a%s', lower(operation::text), id, revision, attempt + 1)
			WHERE id = $1 AND phase IN ('FAILED', 'DELETE_FAILED') RETURNING name, operation, revision, attempt`, bindingID, actor).Scan(&name, &op, &revision, &attempt)
		if errors.Is(err, pgx.ErrNoRows) {
			return &changerequests.Error{Status: 409, Slug: "invalid-transition", Detail: fmt.Sprintf("binding %s is neither FAILED nor DELETE_FAILED", bindingID)}
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

// stepSpan starts a step's span and returns the function that ends it and
// observes its duration (ligo_step_duration_seconds); it runs inside the
// step, so DBOS's replays of completed steps count nothing. A failed span
// gets an error status, never the error's text (§10.1: no secrets in spans).
func stepSpan(ctx context.Context, stage, providerType string) (context.Context, func(error)) {
	start := time.Now()
	ctx, span := tracing.Tracer().Start(ctx, "step "+stage, trace.WithAttributes(attribute.String("ligo.stage", stage),
		attribute.String("ligo.provider_type", providerType)))
	return ctx, func(err error) {
		result := "success"
		if err != nil {
			result = "failure"
			span.SetStatus(otelcodes.Error, "")
		}
		span.End()
		metrics.StepDuration.WithLabelValues(stage, providerType, result).Observe(time.Since(start).Seconds())
	}
}

// workflowSpan starts the span of a workflow run, and puts it in the DBOS
// context its steps inherit; a replay after a recovery starts a new one.
func workflowSpan(ctx dbos.Context, in ApplyInput) (dbos.Context, trace.Span) {
	c, span := startWorkflowSpan(ctx, in)
	return dbos.From(ctx, c), span
}

// startWorkflowSpan starts the span in the trace of the request that started
// the workflow, if any: DBOS runs it on its own context, which has none.
func startWorkflowSpan(ctx context.Context, in ApplyInput) (context.Context, trace.Span) {
	ctx = propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{"traceparent": in.TraceParent})
	return tracing.Tracer().Start(ctx, "workflow "+in.Operation, trace.WithAttributes(attribute.String("ligo.binding_id", in.BindingID),
		attribute.String("ligo.binding", in.BindingName), attribute.String("ligo.workflow_id", in.WorkflowID),
		attribute.Int64("ligo.revision", in.Revision), attribute.Int64("ligo.attempt", in.Attempt)))
}

// traceParent is ctx's trace context as a W3C traceparent, empty without one.
func traceParent(ctx context.Context) string {
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	return carrier.Get("traceparent")
}

// attemptStarted is the time the attempt's phase was entered, read in its
// closing transaction, for ligo_workflow_duration_seconds.
func attemptStarted(ctx context.Context, tx pgx.Tx, f fence) (time.Time, error) {
	var t time.Time
	err := tx.QueryRow(ctx, "SELECT last_transition_at FROM bindings WHERE id = $1 AND workflow_id = $2", f.bindingID, f.workflowID).Scan(&t)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, store.ErrFenced
	}
	return t, err
}

// finished observes an attempt's duration once its closing transaction
// commits.
func finished(op, result string, start time.Time) {
	if !start.IsZero() {
		metrics.WorkflowDuration.WithLabelValues(op, result).Observe(time.Since(start).Seconds())
	}
}

// reverted is a break-glass revert's outcome, counted once its transaction
// commits (ligo_break_glass_total).
type reverted struct{ realm, operation, outcome string }

func (r *reverted) count() {
	if r != nil {
		metrics.BreakGlass.WithLabelValues(r.realm, r.operation, r.outcome).Inc()
	}
}

// revertOutcome audits BREAK_GLASS_REVERTED or BREAK_GLASS_REVERT_FAILED
// when the attempt's revision was started by a SYSTEM_REVERT, retries
// included (§6.3); it returns the outcome, or nil for no revert.
func revertOutcome(ctx context.Context, tx pgx.Tx, f fence, in ApplyInput, ok bool) (*reverted, error) {
	started, action := "APPLY_STARTED", "BREAK_GLASS_REVERTED"
	if in.Operation == "DELETE" {
		started = "DELETE_STARTED"
	}
	if !ok {
		action = "BREAK_GLASS_REVERT_FAILED"
	}
	var cr uuid.UUID
	r := &reverted{outcome: "reverted"}
	if !ok {
		r.outcome = "revert_failed"
	}
	err := tx.QueryRow(ctx, `SELECT a.change_request_id, coalesce(bg.realm, ''), bg.operation::text FROM audit_log a
		JOIN change_requests c ON c.id = a.change_request_id JOIN change_requests bg ON bg.id = c.reverts_cr_id
		WHERE a.resource_type = 'BINDING' AND a.resource_name = $1 AND a.resource_id = $2 AND a.revision = $3 AND a.action = $4
		AND c.kind = 'SYSTEM_REVERT' ORDER BY a.id DESC LIMIT 1`, in.BindingName, f.bindingID, in.Revision, started).Scan(&cr, &r.realm, &r.operation)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &f.bindingID, ResourceName: in.BindingName,
		ChangeRequestID: &cr, Action: action, Actor: "system:workflow", Revision: &in.Revision, Attempt: &in.Attempt, WorkflowID: f.workflowID})
	return r, err
}

// markFailed records a terminal error of the attempt: FAILED for an apply,
// DELETE_FAILED for a delete (§6.4 failure path, §6.5).
func (e *Engine) markFailed(ctx context.Context, f fence, step string, cause *StepError, in ApplyInput) error {
	from, to, action := "PROVISIONING", "FAILED", "PROVISION_FAILURE"
	if in.Operation == "DELETE" {
		from, to, action = "DELETING", "DELETE_FAILED", "DELETE_FAILURE"
	}
	var rv *reverted
	var propagated string // the cause of the propagation that started this revision, if any
	var start time.Time
	if err := pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		var err error
		if start, err = attemptStarted(ctx, tx, f); err != nil {
			return err
		}
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
		if _, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &f.bindingID, ResourceName: in.BindingName,
			Action: action, Actor: "system:workflow", Revision: &in.Revision, Attempt: &in.Attempt, WorkflowID: f.workflowID, Snapshot: snap}); err != nil {
			return err
		}
		// a revision the propagator started: ligo_propagation_failed_total, by its cause
		if err := tx.QueryRow(ctx, `SELECT coalesce((SELECT snapshot->>'cause' FROM audit_log WHERE action = 'PROPAGATION_STARTED'
			AND resource_type = 'BINDING' AND resource_id = $1 AND revision = $2 ORDER BY id DESC LIMIT 1), '')`,
			f.bindingID, in.Revision).Scan(&propagated); err != nil {
			return err
		}
		rv, err = revertOutcome(ctx, tx, f, in, false)
		return err
	}); err != nil {
		return err
	}
	rv.count()
	finished(in.Operation, "failure", start)
	if propagated != "" && in.Operation != "DELETE" {
		metrics.PropagationFailed.WithLabelValues(propagated).Inc()
	}
	return nil
}
