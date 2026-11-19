// SPDX-License-Identifier: MIT

package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
	"github.com/google/uuid"
)

// The operations of containment, charter, maintenance, audit and executors.
// None of them is a human decision (T-A4). The writes among them (retry,
// rotate, revoke, withdraw, maintenance, the audit export record, the
// executor recovery) are made once, never repeated by the client (T-A6).

// TestSourceRegex runs the regex tester of Appendix A; nothing is stored.
func (c *Client) TestSourceRegex(ctx context.Context, req SourceTestRequest) (SourceTestResult, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return SourceTestResult{}, fmt.Errorf("adminclient: encoding the request: %w", err)
	}
	return fetch[SourceTestResult](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.TestSourceRegexWithBody(ctx, contentJSON, bytes.NewReader(b), e...)
	})
}

// RevokeTargetBindings files, for containment, one DELETE change request per
// binding of a source (or of the sources of a jurisdiction) on a target. The
// request's Comment is required. The answer holds the requests filed and,
// apart, the bindings that could not be revoked: a call that filed some and
// failed others is not an error.
func (c *Client) RevokeTargetBindings(ctx context.Context, target string, req RevokeRequest, o Options) (Revocation, error) {
	switch {
	case target == "":
		return Revocation{}, errors.New("adminclient: RevokeTargetBindings: a target is required")
	case req.Comment == "":
		return Revocation{}, errors.New("adminclient: RevokeTargetBindings: a comment is required")
	case (deref(req.Source) == "") == (deref(req.SourceJurisdiction) == ""):
		return Revocation{}, errors.New("adminclient: RevokeTargetBindings: give either a source or a source jurisdiction")
	}
	if o.ApprovalReference != "" {
		req.ApprovalReference = &o.ApprovalReference
	}
	b, err := json.Marshal(req)
	if err != nil {
		return Revocation{}, fmt.Errorf("adminclient: encoding the request: %w", err)
	}
	return fetch[Revocation](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RevokeTargetBindingsWithBody(ctx, target, contentJSON, bytes.NewReader(b), e...)
	})
}

// RetryBinding starts again a FAILED or DELETE_FAILED binding and returns it.
func (c *Client) RetryBinding(ctx context.Context, name string) (Binding, error) {
	return c.operate(ctx, name, c.gen.RetryBinding)
}

// RotateBinding applies an ACTIVE binding again, with rotation, and returns it.
func (c *Client) RotateBinding(ctx context.Context, name string) (Binding, error) {
	return c.operate(ctx, name, c.gen.RotateBinding)
}

func (c *Client) operate(ctx context.Context, name string, op func(context.Context, string, ...gen.RequestEditorFn) (*http.Response, error)) (Binding, error) {
	if name == "" {
		return Binding{}, errors.New("adminclient: a binding name is required")
	}
	var out struct {
		Binding Binding `json:"binding"`
	}
	err := c.exec(ctx, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return op(ctx, name, e...)
	}, &out)
	return out.Binding, err
}

// WithdrawChangeRequest withdraws a PENDING change request of the caller's
// own; the comment, optional, is kept in the audit log.
func (c *Client) WithdrawChangeRequest(ctx context.Context, id, comment string) (ChangeRequest, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return ChangeRequest{}, fmt.Errorf("adminclient: change request ID %q: %w", id, err)
	}
	b, err := json.Marshal(gen.WithdrawRequest{Comment: &comment})
	if err != nil {
		return ChangeRequest{}, fmt.Errorf("adminclient: encoding the request: %w", err)
	}
	return c.filing(ctx, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.WithdrawChangeRequestWithBody(ctx, u, contentJSON, bytes.NewReader(b), e...)
	})
}

// GetCharter is the charter in force and the SHA-256 of its canonical form.
func (c *Client) GetCharter(ctx context.Context) (Charter, error) {
	return fetch[Charter](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetCharter(ctx, e...)
	})
}

// EvaluateCharter is the dry run of a planned creation: what the charter
// would ask for. planned is a binding (with "resourceType": "BINDING") or a
// source or a target (with its "kind"), as it would be filed; nothing is
// stored and no plugin is called.
func (c *Client) EvaluateCharter(ctx context.Context, planned any) (Evaluation, error) {
	b, err := json.Marshal(planned)
	if err != nil {
		return Evaluation{}, fmt.Errorf("adminclient: encoding the request: %w", err)
	}
	return fetch[Evaluation](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.EvaluateCharterWithBody(ctx, contentJSON, bytes.NewReader(b), e...)
	})
}

// ListBreakGlassPage is one page of the open and recent break-glass changes.
func (c *Client) ListBreakGlassPage(ctx context.Context, pageSize int, pageToken string) (Page[ChangeRequest], error) {
	r, err := fetch[gen.ChangeRequestPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListBreakGlass(ctx, &gen.ListBreakGlassParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[ChangeRequest]{r.Items, deref(r.NextPageToken)}, err
}

// ListBreakGlass iterates over the open and recent break-glass changes.
func (c *Client) ListBreakGlass(ctx context.Context, pageSize int) iter.Seq2[ChangeRequest, error] {
	return pages(func(t string) (Page[ChangeRequest], error) { return c.ListBreakGlassPage(ctx, pageSize, t) })
}

// GetMaintenance is the maintenance setting and what the drain waits for.
func (c *Client) GetMaintenance(ctx context.Context) (Maintenance, error) {
	return fetch[Maintenance](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetMaintenance(ctx, e...)
	})
}

// PutMaintenance turns maintenance mode on or off (admin.full_access) and
// returns the setting; a reason is required to turn it on.
func (c *Client) PutMaintenance(ctx context.Context, enabled bool, reason string) (Maintenance, error) {
	if enabled && reason == "" {
		return Maintenance{}, errors.New("adminclient: PutMaintenance: a reason is required to enable maintenance mode")
	}
	b, err := json.Marshal(gen.MaintenanceRequest{Enabled: enabled, Reason: &reason})
	if err != nil {
		return Maintenance{}, fmt.Errorf("adminclient: encoding the request: %w", err)
	}
	return fetch[Maintenance](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.PutMaintenanceWithBody(ctx, contentJSON, bytes.NewReader(b), e...)
	})
}

// VerifyAudit verifies the hash chain of the audit log and its signed
// checkpoints; with full, every entry and not only those after the newest
// checkpoint. A chain that does not verify is a result (Valid false), not an
// error; ErrUnavailable when the signing key cannot be reached.
func (c *Client) VerifyAudit(ctx context.Context, full bool) (AuditVerification, error) {
	return fetch[AuditVerification](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.VerifyAudit(ctx, &gen.VerifyAuditParams{Full: optBool(&full)}, e...)
	})
}

// ExportAudit writes the audit log through a signed checkpoint, as JSON
// Lines, to w (admin.full_access); through is the checkpoint's audit entry ID,
// 0 for the newest. The export is verified offline (ligo audit verify
// --file), and it is not repeated by the client: a cut stream is an error
// and the file is to be discarded.
func (c *Client) ExportAudit(ctx context.Context, through int64, w io.Writer) error {
	if through < 0 {
		return errors.New("adminclient: ExportAudit: through is a positive audit entry ID, or 0")
	}
	p := &gen.ExportAuditParams{}
	if through > 0 {
		p.Through = &through
	}
	return c.exec(ctx, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ExportAudit(ctx, p, e...)
	}, w)
}

// RecordAuditExport records an export taken and verified, so that pruning
// never passes it (admin.full_access); ErrState when this or a later
// export is recorded already.
func (c *Client) RecordAuditExport(ctx context.Context, through int64, sha256 string) error {
	if through <= 0 || sha256 == "" {
		return errors.New("adminclient: RecordAuditExport: through and sha256 are required")
	}
	b, err := json.Marshal(gen.AuditExportRecord{Through: through, Sha256: sha256})
	if err != nil {
		return fmt.Errorf("adminclient: encoding the request: %w", err)
	}
	return c.exec(ctx, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RecordAuditExportWithBody(ctx, contentJSON, bytes.NewReader(b), e...)
	}, nil)
}

// ListExecutors shows the pending workflows and live database sessions of
// each executor.
func (c *Client) ListExecutors(ctx context.Context) ([]Executor, error) {
	r, err := fetch[gen.ExecutorList](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListExecutors(ctx, e...)
	})
	return r.Items, err
}

// RecoverExecutor re-enqueues the pending workflows of a replica gone for
// good (admin.full_access); ErrState while that replica is alive or when
// it is the one answering.
func (c *Client) RecoverExecutor(ctx context.Context, id string) (ExecutorRecovery, error) {
	if id == "" {
		return ExecutorRecovery{}, errors.New("adminclient: RecoverExecutor: an executor is required")
	}
	return fetch[ExecutorRecovery](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RecoverExecutor(ctx, id, e...)
	})
}
