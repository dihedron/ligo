package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/outputvalidation"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Stage outputs: JSON DTOs (EXT-07); Protobuf values travel as protojson
// and secrets only sealed (§6.1 rule 6, ADR-07).
type identityOutput struct {
	Artifact json.RawMessage   `json:"artifact"` // IdentityArtifact without static_secret
	Sealed   *sealing.Envelope `json:"sealed,omitempty"`
}

type targetOutput struct {
	FinalizedClientSpec json.RawMessage   `json:"finalizedClientSpec"`
	DeclaredEndpoints   json.RawMessage   `json:"declaredEndpoints"`
	Payload             json.RawMessage   `json:"payload"` // SecretProvisioningPayload without static_secret
	Sealed              *sealing.Envelope `json:"sealed,omitempty"`
}

type storeOutput struct {
	FinalizedClientAuth json.RawMessage `json:"finalizedClientAuth"`
	DeclaredEndpoints   json.RawMessage `json:"declaredEndpoints"`
}

var marshal = protojson.MarshalOptions{UseProtoNames: true}

func endpoints(eps []*pluginv1.Endpoint) json.RawMessage {
	list := make([]json.RawMessage, 0, len(eps))
	for _, e := range eps {
		data, _ := marshal.Marshal(e)
		list = append(list, data)
	}
	data, _ := json.Marshal(list)
	return data
}

// bindingContext is the BindingContext of an attempt (§5.9).
func (in ApplyInput) bindingContext() *pluginv1.BindingContext {
	op := pluginv1.Operation(pluginv1.Operation_value["OPERATION_"+in.Operation])
	return &pluginv1.BindingContext{BindingId: in.BindingID, BindingName: in.BindingName, Revision: in.Revision, Attempt: in.Attempt,
		Operation: op, Zone: in.Zone, SourceTrustDomain: in.TrustDomain, SourceSvidRegex: in.SVIDRegex, RotateStaticSecrets: in.Rotate,
		DerivedPrincipalName: in.DerivedPrincipalName, SourceName: in.Source, TargetId: in.TargetID, TargetName: in.Target,
		AccessLevel: in.AccessLevel, SourceRevision: in.SourceRevision, TargetRevision: in.TargetRevision}
}

func (in ApplyInput) sealContext(stage string) sealing.Context {
	id, _ := uuid.Parse(in.BindingID)
	return sealing.Context{BindingID: id, Revision: in.Revision, Attempt: in.Attempt, Stage: stage}
}

// apply is ApplyBindingWorkflow (§6.4): S1 to S10, or markFailed on a
// terminal error; a superseded workflow stops without side effects.
func (e *Engine) apply(ctx dbos.Context, in ApplyInput) (string, error) {
	id, err := uuid.Parse(in.BindingID)
	if err != nil {
		return "", err
	}
	f := fence{bindingID: id, workflowID: in.WorkflowID}
	w := in.Wiring
	step := func(name string, fn func(context.Context) error) error {
		_, err := dbos.RunAsStep(ctx, func(c context.Context) (struct{}, error) { return struct{}{}, fn(c) }, dbos.WithStepName(name))
		return err
	}
	fail := func(name string, err error) (string, error) {
		if errors.Is(err, store.ErrFenced) || err != nil && err.Error() == store.ErrFenced.Error() {
			return "", err // superseded: no further side effects (§6.1 rule 7)
		}
		se := sanitize(err)
		if se.Code == "PLUGIN_ERROR" && !errors.As(err, new(*StepError)) { // replayed: keep the recorded text
			se = &StepError{Code: "WORKFLOW_ERROR", Message: err.Error()}
		}
		if ferr := step("markFailed", func(c context.Context) error { return e.markFailed(c, f, name, se, in) }); ferr != nil {
			return "", ferr
		}
		return "FAILED", se
	}

	// Stage 1
	if err := step("markStage:IDENTITY:STARTED", func(c context.Context) error {
		return e.markStage(c, f, "IDENTITY", w.IdentityType, w.IdentityInstance, in.Revision, "ensureIdentity", "STARTED", nil)
	}); err != nil {
		return fail("markStage:IDENTITY:STARTED", err)
	}
	idOut, err := dbos.RunAsStep(ctx, func(c context.Context) (identityOutput, error) { return e.ensureIdentity(c, in) },
		dbos.WithStepName("ensureIdentity"))
	if err != nil {
		return fail("ensureIdentity", err)
	}
	if err := step("markStage:IDENTITY:ENSURED", func(c context.Context) error {
		return e.markStage(c, f, "IDENTITY", w.IdentityType, w.IdentityInstance, in.Revision, "markStage:TARGET:STARTED", "ENSURED", idOut.Artifact)
	}); err != nil {
		return fail("markStage:IDENTITY:ENSURED", err)
	}

	// Stage 2
	if err := step("markStage:TARGET:STARTED", func(c context.Context) error {
		return e.markStage(c, f, "TARGET", w.PlatformType, w.Platform, in.Revision, "ensureTarget", "STARTED", nil)
	}); err != nil {
		return fail("markStage:TARGET:STARTED", err)
	}
	tgtOut, err := dbos.RunAsStep(ctx, func(c context.Context) (targetOutput, error) { return e.ensureTarget(c, in, idOut) },
		dbos.WithStepName("ensureTarget"))
	if err != nil {
		return fail("ensureTarget", err)
	}
	if err := step("markStage:TARGET:ENSURED", func(c context.Context) error {
		artifact, _ := json.Marshal(map[string]json.RawMessage{"finalizedClientSpec": tgtOut.FinalizedClientSpec, "declaredEndpoints": tgtOut.DeclaredEndpoints})
		return e.markStage(c, f, "TARGET", w.PlatformType, w.Platform, in.Revision, "markStage:SECRET_STORE:STARTED", "ENSURED", artifact)
	}); err != nil {
		return fail("markStage:TARGET:ENSURED", err)
	}

	// Stage 3
	if err := step("markStage:SECRET_STORE:STARTED", func(c context.Context) error {
		return e.markStage(c, f, "SECRET_STORE", w.StoreType, w.StoreInstance, in.Revision, "ensureSecretStore", "STARTED", nil)
	}); err != nil {
		return fail("markStage:SECRET_STORE:STARTED", err)
	}
	stOut, err := dbos.RunAsStep(ctx, func(c context.Context) (storeOutput, error) { return e.ensureSecretStore(c, in, idOut, tgtOut) },
		dbos.WithStepName("ensureSecretStore"))
	if err != nil {
		return fail("ensureSecretStore", err)
	}
	if err := step("markStage:SECRET_STORE:ENSURED", func(c context.Context) error {
		artifact, _ := json.Marshal(map[string]json.RawMessage{"finalizedClientAuth": stOut.FinalizedClientAuth, "declaredEndpoints": stOut.DeclaredEndpoints})
		return e.markStage(c, f, "SECRET_STORE", w.StoreType, w.StoreInstance, in.Revision, "finalizeActive", "ENSURED", artifact)
	}); err != nil {
		return fail("markStage:SECRET_STORE:ENSURED", err)
	}

	if err := step("finalizeActive", func(c context.Context) error {
		return e.finalize(c, f, in, idOut, tgtOut, stOut)
	}); err != nil {
		return fail("finalizeActive", err)
	}
	return "ACTIVE", nil
}

// markStage records a stage's status with its wiring, fenced on the
// binding's workflow; STARTED keeps the previous artifact (§6.4 S1, INV-05).
func (e *Engine) markStage(ctx context.Context, f fence, stage, providerType, providerInstance string, revision int64, next, status string, artifact json.RawMessage) error {
	return pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		if err := store.MarkStep(ctx, tx, f.bindingID, f.workflowID, next, ""); err != nil {
			return err
		}
		var art any
		if artifact != nil {
			art = string(artifact)
		}
		_, err := tx.Exec(ctx, `INSERT INTO binding_stage_state (binding_id, stage, provider_type, provider_instance, status, revision, workflow_id, artifact)
			VALUES ($1, $2, $3, $4, $5, $6, $7, coalesce($8::jsonb, '{}'::jsonb))
			ON CONFLICT (binding_id, stage) DO UPDATE SET provider_type = EXCLUDED.provider_type, provider_instance = EXCLUDED.provider_instance,
				status = EXCLUDED.status, revision = EXCLUDED.revision, workflow_id = EXCLUDED.workflow_id,
				artifact = coalesce($8::jsonb, binding_stage_state.artifact), updated_at = now()`,
			f.bindingID, stage, providerType, providerInstance, status, revision, f.workflowID, art)
		return err
	})
}

// previous is the stage's artifact as last ENSURED (§6.4, previous outputs).
func (e *Engine) previous(ctx context.Context, in ApplyInput, stage string) (json.RawMessage, error) {
	var artifact json.RawMessage
	err := e.DB.QueryRow(ctx, "SELECT artifact FROM binding_stage_state WHERE binding_id = $1 AND stage = $2", in.BindingID, stage).Scan(&artifact)
	if errors.Is(err, pgx.ErrNoRows) || string(artifact) == "{}" {
		return nil, nil
	}
	return artifact, err
}

func (e *Engine) ensureIdentity(ctx context.Context, in ApplyInput) (identityOutput, error) {
	w := in.Wiring
	if err := e.call(ctx, func(c context.Context) error {
		return e.Plugins.Health(c, pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, w.IdentityInstance)
	}); err != nil {
		return identityOutput{}, err
	}
	prevJSON, err := e.previous(ctx, in, "IDENTITY")
	if err != nil {
		return identityOutput{}, err
	}
	prev := &pluginv1.IdentityArtifact{}
	if prevJSON != nil {
		if err := protojson.Unmarshal(prevJSON, prev); err != nil {
			return identityOutput{}, err
		}
	}
	var resp *pluginv1.EnsureIdentityResponse
	if err := e.call(ctx, func(c context.Context) (err error) {
		resp, err = e.Plugins.EnsureIdentity(c, &pluginv1.EnsureIdentityRequest{Instance: w.IdentityInstance, Binding: in.bindingContext(), PreviousArtifact: prev})
		return err
	}); err != nil {
		return identityOutput{}, err
	}
	art := proto.Clone(resp.GetArtifact()).(*pluginv1.IdentityArtifact)
	var out identityOutput
	if s := art.GetStaticSecret(); s != nil { // stripped, and sealed (ADR-07)
		if out.Sealed, err = e.seal(ctx, in, sealing.StageIdentity, s); err != nil {
			return identityOutput{}, err
		}
		art.StaticSecret = nil
	}
	out.Artifact, err = marshal.Marshal(art)
	return out, err
}

func (e *Engine) ensureTarget(ctx context.Context, in ApplyInput, id identityOutput) (targetOutput, error) {
	w := in.Wiring
	if err := e.call(ctx, func(c context.Context) error {
		return e.Plugins.Health(c, pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, w.Platform)
	}); err != nil {
		return targetOutput{}, err
	}
	identity := &pluginv1.IdentityArtifact{}
	if err := protojson.Unmarshal(id.Artifact, identity); err != nil {
		return targetOutput{}, err
	}
	var prevSpec []byte
	if prev, err := e.previous(ctx, in, "TARGET"); err != nil {
		return targetOutput{}, err
	} else if prev != nil {
		var p struct {
			FinalizedClientSpec json.RawMessage `json:"finalizedClientSpec"`
		}
		_ = json.Unmarshal(prev, &p)
		prevSpec = p.FinalizedClientSpec
	}
	var resp *pluginv1.EnsureTargetResponse
	if err := e.call(ctx, func(c context.Context) (err error) {
		resp, err = e.Plugins.EnsureTarget(c, &pluginv1.EnsureTargetRequest{Instance: w.Platform, Binding: in.bindingContext(), Identity: identity,
			RequestedSpecJson: in.RequestedSpec, PreviousFinalizedClientSpecJson: prevSpec})
		return err
	}); err != nil {
		return targetOutput{}, err
	}
	if err := e.validate(pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, w.Platform, resp.GetFinalizedClientSpecJson(), resp.GetDeclaredEndpoints()); err != nil {
		return targetOutput{}, err
	}
	out := targetOutput{FinalizedClientSpec: resp.GetFinalizedClientSpecJson(), DeclaredEndpoints: endpoints(resp.GetDeclaredEndpoints())}
	payload := proto.Clone(resp.GetSecretPayload()).(*pluginv1.SecretProvisioningPayload)
	if s := payload.GetStaticSecret(); s != nil {
		var err error
		if out.Sealed, err = e.seal(ctx, in, sealing.StageTarget, s); err != nil {
			return targetOutput{}, err
		}
		payload.Payload = nil
	}
	var err error
	out.Payload, err = marshal.Marshal(payload)
	return out, err
}

// ensureSecretStore composes the Stage 3 payload (§5.6), unsealing the
// static secret in memory only, and calls the store.
func (e *Engine) ensureSecretStore(ctx context.Context, in ApplyInput, id identityOutput, tgt targetOutput) (storeOutput, error) {
	w := in.Wiring
	if err := e.call(ctx, func(c context.Context) error {
		return e.Plugins.Health(c, pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, w.StoreInstance)
	}); err != nil {
		return storeOutput{}, err
	}
	identity, payload := &pluginv1.IdentityArtifact{}, &pluginv1.SecretProvisioningPayload{}
	if err := protojson.Unmarshal(id.Artifact, identity); err != nil {
		return storeOutput{}, err
	}
	if err := protojson.Unmarshal(tgt.Payload, payload); err != nil {
		return storeOutput{}, err
	}
	payload.Mode = identity.GetMode()
	switch identity.GetMode() {
	case pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR: // Stage 1's secret, forwarded by the engine
		payload.SecretUnchanged = identity.GetSecretUnchanged()
		if id.Sealed != nil && !payload.SecretUnchanged {
			s, err := e.unseal(ctx, in, sealing.StageIdentity, id.Sealed)
			if err != nil {
				return storeOutput{}, err
			}
			payload.Payload = &pluginv1.SecretProvisioningPayload_StaticSecret{StaticSecret: s}
		}
	case pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL:
		if tgt.Sealed != nil && !payload.GetSecretUnchanged() {
			s, err := e.unseal(ctx, in, sealing.StageTarget, tgt.Sealed)
			if err != nil {
				return storeOutput{}, err
			}
			payload.Payload = &pluginv1.SecretProvisioningPayload_StaticSecret{StaticSecret: s}
		}
	}
	var prevAuth []byte
	if prev, err := e.previous(ctx, in, "SECRET_STORE"); err != nil {
		return storeOutput{}, err
	} else if prev != nil {
		var p struct {
			FinalizedClientAuth json.RawMessage `json:"finalizedClientAuth"`
		}
		_ = json.Unmarshal(prev, &p)
		prevAuth = p.FinalizedClientAuth
	}
	var resp *pluginv1.EnsureSecretStoreResponse
	if err := e.call(ctx, func(c context.Context) (err error) {
		resp, err = e.Plugins.EnsureSecretStore(c, &pluginv1.EnsureSecretStoreRequest{Instance: w.StoreInstance, Binding: in.bindingContext(),
			SecretPayload: payload, Identity: identity, PreviousFinalizedClientAuthJson: prevAuth, SecretStorageStrategy: w.Strategy})
		return err
	}); err != nil {
		return storeOutput{}, err
	}
	if err := e.validate(pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, w.StoreInstance, resp.GetFinalizedClientAuthJson(), resp.GetDeclaredEndpoints()); err != nil {
		return storeOutput{}, err
	}
	return storeOutput{FinalizedClientAuth: resp.GetFinalizedClientAuthJson(), DeclaredEndpoints: endpoints(resp.GetDeclaredEndpoints())}, nil
}

// validate checks a plugin's output before it is persisted (§5.7, INV-13).
func (e *Engine) validate(kind pluginv1.PluginKind, instance string, output []byte, declared []*pluginv1.Endpoint) error {
	v := e.Plugins.OutputValidator(kind, instance)
	if v == nil {
		return &StepError{Code: "OUTPUT_VALIDATION_FAILED", Message: "no output validator for instance " + instance}
	}
	if err := v.Validate(output, declared); err != nil {
		return &StepError{Code: "OUTPUT_VALIDATION_FAILED", Message: strings.TrimPrefix(err.Error(), outputvalidation.ErrFailed.Error()+": ")}
	}
	return nil
}

func (e *Engine) seal(ctx context.Context, in ApplyInput, stage string, s *pluginv1.StaticSecret) (*sealing.Envelope, error) {
	plain, err := proto.Marshal(s)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	env, err := e.Sealer.Seal(ctx, in.sealContext(stage), plain)
	if err != nil {
		return nil, &StepError{Code: "SEALED_SECRET_UNAVAILABLE", Message: "cannot seal the secret", Retryable: true}
	}
	return &env, nil
}

func (e *Engine) unseal(ctx context.Context, in ApplyInput, stage string, env *sealing.Envelope) (*pluginv1.StaticSecret, error) {
	plain, err := e.Sealer.Unseal(ctx, in.sealContext(stage), *env)
	if err != nil { // terminal: a retry starts a new attempt with rotation (ADR-07)
		return nil, &StepError{Code: "SEALED_SECRET_UNAVAILABLE", Message: "cannot unseal the secret of this attempt"}
	}
	defer clear(plain)
	s := &pluginv1.StaticSecret{}
	return s, proto.Unmarshal(plain, s)
}

// finalize promotes the attempt to the active snapshot in one fenced
// transaction (§6.4 S10, INV-02).
func (e *Engine) finalize(ctx context.Context, f fence, in ApplyInput, id identityOutput, tgt targetOutput, st storeOutput) error {
	identity := &pluginv1.IdentityArtifact{}
	if err := protojson.Unmarshal(id.Artifact, identity); err != nil {
		return err
	}
	auth, err := json.Marshal(map[string]any{"secretStorageStrategy": in.Wiring.Strategy, "secretStoreType": in.Wiring.StoreType,
		"secretStoreInstance": in.Wiring.StoreInstance, "config": st.FinalizedClientAuth})
	if err != nil {
		return err
	}
	mode := identity.GetMode()
	rotated := in.Rotate && (mode == pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR || mode == pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL)
	return pgx.BeginFunc(ctx, e.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE bindings SET phase = 'ACTIVE', current_step = 'COMPLETED', status_message = '',
			active_revision = revision, active_source_svid_regex = source_svid_regex, active_auth_config = $3::jsonb, active_spec = $4::jsonb,
			active_since = now(), rotate_static_secrets = false, last_rotated_at = CASE WHEN $5 THEN now() ELSE last_rotated_at END,
			last_transition_at = now(), updated_at = now()
			WHERE id = $1 AND workflow_id = $2 AND phase = 'PROVISIONING'`, f.bindingID, f.workflowID, string(auth), string(tgt.FinalizedClientSpec), rotated)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return store.ErrFenced
		}
		snap, _ := json.Marshal(map[string]any{"mode": mode.String(), "rotated": rotated})
		_, err = audit.Append(ctx, tx, audit.Entry{ResourceType: "BINDING", ResourceID: &f.bindingID, ResourceName: in.BindingName,
			Action: "PROVISION_SUCCESS", Actor: "system:workflow", Revision: &in.Revision, Attempt: &in.Attempt, WorkflowID: f.workflowID, Snapshot: snap})
		return err
	})
}
