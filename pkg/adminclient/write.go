package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
)

// The writes of the admin API. Every one but RegisterAccount and
// RetireAccount files a change request and returns the ChangeRequest the
// server answered with, never the resource as if it had changed: the change
// is in force when the request is APPLIED (WaitChangeRequest), and the
// caller then reads the resource. A mutation is never repeated by the client
// (T-A6), and an update or a state change without the revision it is based
// on fails before any call (T-A5): a stale one is ErrConflict.
//
// The package has no method to approve, decline, ratify or revert a change
// request, or to break glass: those are decisions of people (T-A4).

// Options go with every filing; the zero value is fine.
type Options struct {
	ApprovalReference string         // the external ticket or decision; delegated approval (ADR-11) needs it
	AutomationContext map[string]any // who runs the automation, passed through to the server
}

const contentJSON = "application/json"

// encode is the body of a filing: spec (nil for none) with the revision it is
// based on (0 for none) and the options added to it.
func encode(spec any, revision int64, o Options) (io.Reader, error) {
	fields := map[string]json.RawMessage{}
	if spec != nil {
		raw, err := json.Marshal(spec)
		if err != nil {
			return nil, fmt.Errorf("adminclient: encoding the request: %w", err)
		}
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			return nil, errors.New("adminclient: the request is not a JSON object")
		}
	}
	set := func(key string, v any) error {
		raw, err := json.Marshal(v)
		fields[key] = raw
		return err
	}
	if revision != 0 {
		if err := set("expectedRevision", revision); err != nil {
			return nil, err
		}
	}
	if o.ApprovalReference != "" {
		if err := set("approvalReference", o.ApprovalReference); err != nil {
			return nil, err
		}
	}
	if len(o.AutomationContext) > 0 {
		if err := set("automationContext", o.AutomationContext); err != nil {
			return nil, fmt.Errorf("adminclient: AutomationContext: %w", err)
		}
	}
	raw, err := json.Marshal(fields)
	return bytes.NewReader(raw), err
}

// require refuses what would be a request the server rejects, or worse
// accepts: an empty name, a missing revision.
func require(what, name string, revision int64) error {
	switch {
	case name == "":
		return fmt.Errorf("adminclient: %s: a name is required", what)
	case revision <= 0:
		return fmt.Errorf("adminclient: %s %q: the revision it is based on (expectedRevision) is required", what, name)
	}
	return nil
}

// filing runs a generated write and decodes the change request of its answer.
func (c *Client) filing(ctx context.Context, f call) (ChangeRequest, error) {
	var out struct {
		ChangeRequest ChangeRequest `json:"changeRequest"`
	}
	err := c.exec(ctx, f, &out)
	return out.ChangeRequest, err
}

// file is the common shape of a filing: encode, then call.
func (c *Client) file(ctx context.Context, spec any, revision int64, o Options, op func(context.Context, io.Reader, ...gen.RequestEditorFn) (*http.Response, error)) (ChangeRequest, error) {
	b, err := encode(spec, revision, o)
	if err != nil {
		return ChangeRequest{}, err
	}
	return c.filing(ctx, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) { return op(ctx, b, e...) })
}

// ---- sources

// CreateSource files the registration of a source.
func (c *Client) CreateSource(ctx context.Context, spec SourceSpec, o Options) (ChangeRequest, error) {
	return c.file(ctx, spec, 0, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.CreateSourceWithBody(ctx, contentJSON, b, e...)
	})
}

// UpdateSource files a change of a source based on revision; a regex change must narrow.
func (c *Client) UpdateSource(ctx context.Context, name string, spec SourceSpec, revision int64, o Options) (ChangeRequest, error) {
	if err := require("UpdateSource", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, spec, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.UpdateSourceWithBody(ctx, name, contentJSON, b, e...)
	})
}

// DeprecateSource files the deprecation of a source (no new bindings).
func (c *Client) DeprecateSource(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	return c.stateChange(ctx, "DeprecateSource", name, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.DeprecateSourceWithBody(ctx, name, contentJSON, b, e...)
	})
}

// ReactivateSource files the reactivation of a deprecated source.
func (c *Client) ReactivateSource(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	return c.stateChange(ctx, "ReactivateSource", name, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ReactivateSourceWithBody(ctx, name, contentJSON, b, e...)
	})
}

// RetireSource files the retirement of a source; ErrState while bindings exist.
func (c *Client) RetireSource(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	return c.stateChange(ctx, "RetireSource", name, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RetireSourceWithBody(ctx, name, contentJSON, b, e...)
	})
}

func (c *Client) stateChange(ctx context.Context, what, name string, revision int64, o Options, op func(context.Context, io.Reader, ...gen.RequestEditorFn) (*http.Response, error)) (ChangeRequest, error) {
	if err := require(what, name, revision); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, nil, revision, o, op)
}

// ---- targets

// CreateTarget files the publication of a target.
func (c *Client) CreateTarget(ctx context.Context, spec TargetSpec, o Options) (ChangeRequest, error) {
	return c.file(ctx, spec, 0, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.CreateTargetWithBody(ctx, contentJSON, b, e...)
	})
}

// UpdateTarget files a change of a target based on revision; a grants change must narrow.
func (c *Client) UpdateTarget(ctx context.Context, name string, spec TargetSpec, revision int64, o Options) (ChangeRequest, error) {
	if err := require("UpdateTarget", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, spec, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.UpdateTargetWithBody(ctx, name, contentJSON, b, e...)
	})
}

// DeprecateTarget files the deprecation of a target.
func (c *Client) DeprecateTarget(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	return c.stateChange(ctx, "DeprecateTarget", name, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.DeprecateTargetWithBody(ctx, name, contentJSON, b, e...)
	})
}

// ReactivateTarget files the reactivation of a deprecated target.
func (c *Client) ReactivateTarget(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	return c.stateChange(ctx, "ReactivateTarget", name, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ReactivateTargetWithBody(ctx, name, contentJSON, b, e...)
	})
}

// RetireTarget files the retirement of a target; ErrState while bindings exist.
func (c *Client) RetireTarget(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	return c.stateChange(ctx, "RetireTarget", name, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RetireTargetWithBody(ctx, name, contentJSON, b, e...)
	})
}

// DeprecateAccessLevel files the deprecation of one access level of a target.
func (c *Client) DeprecateAccessLevel(ctx context.Context, target, level string, revision int64, o Options) (ChangeRequest, error) {
	return c.levelChange(ctx, "DeprecateAccessLevel", target, level, revision, o, c.gen.DeprecateAccessLevelWithBody)
}

// ReactivateAccessLevel files the reactivation of one access level of a target.
func (c *Client) ReactivateAccessLevel(ctx context.Context, target, level string, revision int64, o Options) (ChangeRequest, error) {
	return c.levelChange(ctx, "ReactivateAccessLevel", target, level, revision, o, c.gen.ReactivateAccessLevelWithBody)
}

// RetireAccessLevel files the retirement of one access level; ErrState while bindings use it.
func (c *Client) RetireAccessLevel(ctx context.Context, target, level string, revision int64, o Options) (ChangeRequest, error) {
	return c.levelChange(ctx, "RetireAccessLevel", target, level, revision, o, c.gen.RetireAccessLevelWithBody)
}

func (c *Client) levelChange(ctx context.Context, what, target, level string, revision int64, o Options,
	op func(context.Context, string, string, string, io.Reader, ...gen.RequestEditorFn) (*http.Response, error)) (ChangeRequest, error) {
	if level == "" {
		return ChangeRequest{}, fmt.Errorf("adminclient: %s: an access level is required", what)
	}
	return c.stateChange(ctx, what, target, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return op(ctx, target, level, contentJSON, b, e...)
	})
}

// ---- bindings

// CreateBinding files a binding, with an optional spec.InlineSource registered
// with it. With wait, the server waits up to 10 s for an applied binding to
// settle before it answers.
func (c *Client) CreateBinding(ctx context.Context, spec BindingSpec, wait bool, o Options) (ChangeRequest, error) {
	var p *gen.CreateBindingParams
	if wait {
		p = &gen.CreateBindingParams{Wait: &wait}
	}
	return c.file(ctx, spec, 0, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.CreateBindingWithBody(ctx, p, contentJSON, b, e...)
	})
}

// UpdateBinding files a change of a binding based on revision.
func (c *Client) UpdateBinding(ctx context.Context, name string, spec BindingSpec, revision int64, o Options) (ChangeRequest, error) {
	if err := require("UpdateBinding", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, spec, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.UpdateBindingWithBody(ctx, name, contentJSON, b, e...)
	})
}

// DeleteBinding files the revocation of a binding based on revision.
func (c *Client) DeleteBinding(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	if err := require("DeleteBinding", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	b, err := encode(nil, 0, o) // the revision is a query parameter here
	if err != nil {
		return ChangeRequest{}, err
	}
	return c.filing(ctx, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.DeleteBindingWithBody(ctx, name, &gen.DeleteBindingParams{ExpectedRevision: revision}, contentJSON, b, e...)
	})
}

// ---- accounts: registered and retired at once, not by a change request

// RegisterAccount registers an account (account_admin).
func (c *Client) RegisterAccount(ctx context.Context, name, displayName string) (Account, error) {
	if name == "" {
		return Account{}, errors.New("adminclient: RegisterAccount: a name is required")
	}
	req := map[string]string{"name": name}
	if displayName != "" {
		req["displayName"] = displayName
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return Account{}, err
	}
	return fetch[Account](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RegisterAccountWithBody(ctx, contentJSON, bytes.NewReader(raw), e...)
	})
}

// RetireAccount retires an account with no active source or target
// (account_admin); its name is never reused.
func (c *Client) RetireAccount(ctx context.Context, name string) (Account, error) {
	if name == "" {
		return Account{}, errors.New("adminclient: RetireAccount: a name is required")
	}
	return fetch[Account](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RetireAccount(ctx, name, e...)
	})
}
