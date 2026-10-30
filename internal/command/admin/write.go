package admin

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dihedron/ligo/internal/client"
)

// waitDelete is how long --wait waits for a revoked binding to be deleted,
// and how often it asks.
var waitDelete, waitPoll = 10 * time.Second, 250 * time.Millisecond

// changed runs fn, which files changes, and reports them.
func (b *Base) changed(what string, fn func(ctx context.Context, c *client.Client) ([]filed, error)) error {
	var answers []filed
	err := b.connected(func(ctx context.Context, c *client.Client) (err error) {
		answers, err = fn(ctx, c)
		return err
	})
	if err != nil && answers == nil {
		return err
	}
	if rerr := b.report(what, answers); rerr != nil {
		return rerr
	}
	return err
}

// post files a change and decodes the answer.
func (b *Base) post(ctx context.Context, c *client.Client, method, p string, query url.Values, body any) (filed, error) {
	var f filed
	return f, c.Do(ctx, method, p, query, body, &f)
}

// Apply submits create or update change requests from a manifest
// (ligo apply -f FILE).
type Apply struct {
	Base
	File              string `short:"f" long:"file" required:"true" description:"Manifest file (YAML or JSON, or '-' for stdin); may hold several documents, applied in order Source, Target, Binding."`
	Wait              bool   `short:"w" long:"wait" description:"If a binding change is applied at creation, block up to 10s until provisioning reaches a terminal phase."`
	ApprovalRef       string `long:"approval-ref" env:"LIGO_APPROVAL_REF" description:"Upstream approval reference (required for delegated approval, ADR-11)."`
	AutomationContext string `long:"automation-context" env:"LIGO_AUTOMATION_CONTEXT" description:"Optional JSON object describing the calling automation (informative only)."`
}

func (cmd *Apply) Execute([]string) error {
	docs, err := readManifest(cmd.File)
	if err != nil {
		return err
	}
	inline, err := inlineSources(docs)
	if err != nil {
		return err
	}
	registered := map[string]bool{} // sources a binding registers inline
	for _, s := range inline {
		registered[s.name] = true
	}
	return cmd.changed("applied", func(ctx context.Context, c *client.Client) ([]filed, error) {
		var answers []filed
		pending := map[string]any{} // targets of this file awaiting approval, by name: their change request
		submit := func(d document) error {
			if err := automation(d.body, cmd.ApprovalRef, cmd.AutomationContext); err != nil {
				return err
			}
			kind := strings.ToLower(d.kind)
			method, p := "POST", path(kind+"s")
			if !d.creates() {
				method, p = "PUT", path(kind+"s", d.name)
			}
			var query url.Values
			if d.kind == "Binding" && cmd.Wait && d.creates() {
				query = url.Values{"wait": {"true"}}
			}
			f, err := cmd.post(ctx, c, method, p, query, d.body)
			if err != nil {
				if d.creates() {
					err = existing(ctx, c, err, kind, d.name)
				}
				return fmt.Errorf("%s %s: %w", kind, d.name, err)
			}
			if d.kind == "Target" && f.ChangeRequest["status"] == "PENDING" {
				pending[d.name] = f.ChangeRequest["id"]
			}
			answers = append(answers, f)
			return nil
		}
		for _, d := range docs {
			if d.kind == "Source" && registered[d.name] {
				continue // filed with its binding
			}
			s, withSource := inline[d.name]
			if d.kind == "Binding" {
				if cr, ok := pending[fmt.Sprint(d.body["target"])]; ok {
					// a target not created yet cannot be bound: its source alone now, the binding later
					_, _ = fmt.Fprintf(os.Stderr, "binding %s not filed: its target %v awaits approval (change request %v); apply it again once the target is applied\n",
						d.name, d.body["target"], cr)
					if withSource {
						if err := submit(s); err != nil {
							return answers, err
						}
					}
					continue
				}
				if withSource {
					d.body["inlineSource"] = s.body
				}
			}
			if err := submit(d); err != nil {
				return answers, err
			}
		}
		return answers, nil
	})
}

// Delete revokes a binding, or retires a source or target (ligo delete).
type Delete struct {
	Base
	ExpectedRevision int64        `short:"r" long:"expected-revision" required:"true" description:"Expected current revision of the resource."`
	ApprovalRef      string       `long:"approval-ref" env:"LIGO_APPROVAL_REF" description:"Upstream approval reference (required for delegated approval, ADR-11)."`
	Wait             bool         `short:"w" long:"wait" description:"If a binding revocation is applied at creation, block up to 10s until deletion completes."`
	Args             ResourceArgs `positional-args:"yes" required:"yes"`
}

func (cmd *Delete) Execute([]string) error {
	kind, name := cmd.Args.Kind, cmd.Args.Name
	return cmd.changed("deleted", func(ctx context.Context, c *client.Client) ([]filed, error) {
		if kind != "binding" {
			f, err := cmd.post(ctx, c, "POST", path(kind+"s", name, "retire"), nil,
				map[string]any{"expectedRevision": cmd.ExpectedRevision, "approvalReference": cmd.ApprovalRef})
			return answers(f, err)
		}
		f, err := cmd.post(ctx, c, "DELETE", path("bindings", name), url.Values{"expectedRevision": {strconv.FormatInt(cmd.ExpectedRevision, 10)}},
			map[string]any{"approvalReference": cmd.ApprovalRef})
		if err != nil || !cmd.Wait || f.ChangeRequest["status"] != "APPLIED" {
			return answers(f, err)
		}
		deadline := time.Now().Add(waitDelete)
		for time.Now().Before(deadline) {
			err := c.Do(ctx, "GET", path("bindings", name), nil, nil, nil)
			var p *client.Problem
			if errors.As(err, &p) && p.Status == 404 {
				f.Resource = nil
				break
			}
			time.Sleep(waitPoll)
		}
		return answers(f, nil)
	})
}

func answers(f filed, err error) ([]filed, error) {
	if err != nil {
		return nil, err
	}
	return []filed{f}, nil
}

// operation is a binding's retry or rotate.
type operation struct {
	Base
	Args struct {
		Name string `positional-arg-name:"name" description:"Binding name."`
	} `positional-args:"yes" required:"yes"`
}

func (cmd *operation) run(op string) error {
	return cmd.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		var v map[string]any
		if err := c.Do(ctx, "POST", path("bindings", cmd.Args.Name, op), nil, nil, &v); err != nil {
			return nil, nil, err
		}
		return v["binding"], columns["binding"], nil
	})
}

// Retry retries a binding in FAILED or DELETE_FAILED (ligo retry NAME).
type Retry struct{ operation }

func (cmd *Retry) Execute([]string) error { return cmd.run("retry") }

// Rotate re-applies an ACTIVE binding with rotation (ligo rotate NAME).
type Rotate struct{ operation }

func (cmd *Rotate) Execute([]string) error { return cmd.run("rotate") }

// Source: ligo source test|deprecate|reactivate.
type Source struct {
	Test       SourceTest       `command:"test" description:"Test a regex: Appendix A, scope, sample IDs, overlaps, and narrowing of an existing source (nothing is stored)."`
	Deprecate  SourceDeprecate  `command:"deprecate" description:"Deprecate a source (no new bindings)."`
	Reactivate SourceReactivate `command:"reactivate" description:"Reactivate a deprecated source."`
}

type SourceTest struct {
	Base
	TrustDomain string   `long:"trust-domain" required:"true" description:"Trust domain."`
	Regex       string   `long:"regex" required:"true" description:"SVID regex."`
	SpiffeIDs   []string `long:"id" description:"SPIFFE ID to test (repeatable)."`
	Current     string   `long:"current" description:"Existing source to check narrowing against."`
}

func (cmd *SourceTest) Execute([]string) error {
	return cmd.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		var v any
		err := c.Do(ctx, "POST", path("sources", "test"), nil, map[string]any{"trustDomain": cmd.TrustDomain, "svidRegex": cmd.Regex,
			"spiffeIds": cmd.SpiffeIDs, "currentSource": cmd.Current}, &v)
		return v, nil, err
	})
}

// StateChange deprecates or reactivates a source or a target.
type StateChange struct {
	Base
	ExpectedRevision int64   `short:"r" long:"expected-revision" required:"true" description:"Expected current revision."`
	Args             NameArg `positional-args:"yes" required:"yes"`
}

func (cmd *StateChange) run(kind, op string) error {
	return cmd.changed(op, func(ctx context.Context, c *client.Client) ([]filed, error) {
		return answers(cmd.post(ctx, c, "POST", path(kind+"s", cmd.Args.Name, op), nil, map[string]any{"expectedRevision": cmd.ExpectedRevision}))
	})
}

type SourceDeprecate struct{ StateChange }

func (cmd *SourceDeprecate) Execute([]string) error { return cmd.run("source", "deprecate") }

type SourceReactivate struct{ StateChange }

func (cmd *SourceReactivate) Execute([]string) error { return cmd.run("source", "reactivate") }

type TargetDeprecate struct{ StateChange }

func (cmd *TargetDeprecate) Execute([]string) error { return cmd.run("target", "deprecate") }

type TargetReactivate struct{ StateChange }

func (cmd *TargetReactivate) Execute([]string) error { return cmd.run("target", "reactivate") }

// Target: ligo target deprecate|reactivate|level|revoke-bindings.
type Target struct {
	Deprecate  TargetDeprecate  `command:"deprecate" description:"Deprecate a target (no new bindings)."`
	Reactivate TargetReactivate `command:"reactivate" description:"Reactivate a deprecated target."`
	Level      TargetLevel      `command:"level" description:"Deprecate, reactivate or retire an access level."`
	Revoke     TargetRevoke     `command:"revoke-bindings" description:"Revoke every binding of a source or source scope on this target (containment)."`
}

type TargetLevel struct {
	Base
	ExpectedRevision int64 `short:"r" long:"expected-revision" required:"true" description:"Expected current revision of the target."`
	Args             struct {
		Action string `positional-arg-name:"action" choice:"deprecate" choice:"reactivate" choice:"retire" description:"State change."`
		Target string `positional-arg-name:"target" description:"Target name."`
		Level  string `positional-arg-name:"level" description:"Access level name."`
	} `positional-args:"yes" required:"yes"`
}

func (cmd *TargetLevel) Execute([]string) error {
	a := cmd.Args
	return cmd.changed(a.Action, func(ctx context.Context, c *client.Client) ([]filed, error) {
		return answers(cmd.post(ctx, c, "POST", path("targets", a.Target, "access-levels", a.Level, a.Action), nil,
			map[string]any{"expectedRevision": cmd.ExpectedRevision}))
	})
}

type TargetRevoke struct {
	Base
	Source      string  `long:"source" description:"Revoke the bindings of this source."`
	SourceScope string  `long:"source-scope" description:"Revoke the bindings of every source in this scope pattern."`
	Comment     string  `short:"m" long:"comment" required:"true" description:"Reason (recorded on every change request)."`
	ApprovalRef string  `long:"approval-ref" env:"LIGO_APPROVAL_REF" description:"Upstream approval reference."`
	Args        NameArg `positional-args:"yes" required:"yes"`
}

func (cmd *TargetRevoke) Execute([]string) error {
	if (cmd.Source == "") == (cmd.SourceScope == "") {
		return errors.New("revoke-bindings: either --source or --source-scope")
	}
	return cmd.changed("revoked", func(ctx context.Context, c *client.Client) ([]filed, error) {
		var v struct {
			ChangeRequests []map[string]any `json:"changeRequests"`
			Errors         []any            `json:"errors"`
		}
		body := map[string]any{"source": cmd.Source, "sourceScope": cmd.SourceScope, "comment": cmd.Comment, "approvalReference": cmd.ApprovalRef}
		if err := c.Do(ctx, "POST", path("targets", cmd.Args.Name, "bindings", "revoke"), nil, body, &v); err != nil {
			return nil, err
		}
		out := []filed{}
		for _, cr := range v.ChangeRequests {
			out = append(out, filed{ChangeRequest: cr})
		}
		if len(v.Errors) > 0 {
			return out, fmt.Errorf("revoke-bindings: %d bindings could not be revoked: %v", len(v.Errors), v.Errors)
		}
		return out, nil
	})
}

// decide approves, declines, withdraws, ratifies or reverts a change
// request.
func (b *Base) decide(id, op string, body map[string]any) error {
	return b.changed(op, func(ctx context.Context, c *client.Client) ([]filed, error) {
		return answers(b.post(ctx, c, "POST", path("change-requests", id, op), nil, body))
	})
}

type crID struct {
	ID string `positional-arg-name:"cr-id" description:"Change request UUID."`
}

type ChangeRequestApprove struct {
	Base
	SHA256  string `long:"sha256" required:"true" description:"Expected 64-char hex payloadSha256 of the change request."`
	Comment string `short:"m" long:"comment" description:"Optional approval comment."`
	Side    string `long:"side" description:"Side to approve (OWNER, PLATFORM, SOURCE, TARGET or PARTY:<name>); required when you may decide several sides and distinct approvers are required."`
	Args    crID   `positional-args:"yes" required:"yes"`
}

func (cmd *ChangeRequestApprove) Execute([]string) error {
	return cmd.decide(cmd.Args.ID, "approve", map[string]any{"payloadSha256": cmd.SHA256, "comment": cmd.Comment, "side": cmd.Side})
}

type ChangeRequestDecline struct {
	Base
	Comment string `short:"m" long:"comment" required:"true" description:"Rejection reason (required)."`
	Side    string `long:"side" description:"Side to decline; default: every side you may decide."`
	Args    crID   `positional-args:"yes" required:"yes"`
}

func (cmd *ChangeRequestDecline) Execute([]string) error {
	return cmd.decide(cmd.Args.ID, "decline", map[string]any{"comment": cmd.Comment, "side": cmd.Side})
}

type ChangeRequestRatify struct {
	Base
	Comment string `short:"m" long:"comment" required:"true" description:"Ratification comment (required)."`
	Side    string `long:"side" description:"Side to ratify; required when you may ratify several sides and distinct approvers are required."`
	Args    crID   `positional-args:"yes" required:"yes"`
}

func (cmd *ChangeRequestRatify) Execute([]string) error {
	return cmd.decide(cmd.Args.ID, "ratify", map[string]any{"comment": cmd.Comment, "side": cmd.Side})
}

type ChangeRequestWithdraw struct {
	Base
	Args crID `positional-args:"yes" required:"yes"`
}

func (cmd *ChangeRequestWithdraw) Execute([]string) error {
	return cmd.decide(cmd.Args.ID, "withdraw", nil)
}

type ChangeRequestRevert struct {
	Base
	Args crID `positional-args:"yes" required:"yes"`
}

func (cmd *ChangeRequestRevert) Execute([]string) error {
	return cmd.decide(cmd.Args.ID, "revert", nil)
}

type MaintenanceOn struct {
	Base
	Reason string `short:"m" long:"reason" required:"true" description:"Why maintenance is being enabled (recorded in the audit log)."`
}

func (cmd *MaintenanceOn) Execute([]string) error { return cmd.maintenance(true, cmd.Reason) }

type MaintenanceOff struct{ Base }

func (cmd *MaintenanceOff) Execute([]string) error { return cmd.maintenance(false, "") }

func (b *Base) maintenance(on bool, reason string) error {
	return b.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		var v any
		return v, maintenanceColumns, c.Do(ctx, "PUT", path("maintenance"), nil, map[string]any{"enabled": on, "reason": reason}, &v)
	})
}

// BGOptions are the controls of a break-glass change (ADR-12).
type BGOptions struct {
	Justification string `short:"j" long:"justification" required:"true" description:"Why the emergency change is needed."`
	Incident      string `short:"i" long:"incident" required:"true" description:"Incident reference (e.g. INC0012345)."`
	TTL           string `long:"ttl" description:"Time until automatic revert unless ratified (default: the most restrictive default_ttl of the sides' policies)."`
}

func (o BGOptions) body(op string) map[string]any {
	return map[string]any{"operation": op, "justification": o.Justification, "incidentReference": o.Incident, "ttl": o.TTL}
}

// BreakGlassApply is an emergency create or update of one binding, with an
// optional source created inline.
type BreakGlassApply struct {
	Base
	BGOptions
	File string `short:"f" long:"file" required:"true" description:"Binding manifest (YAML or JSON, or '-' for stdin); may also contain one Source document, created inline."`
}

func (cmd *BreakGlassApply) Execute([]string) error {
	docs, err := readManifest(cmd.File)
	if err != nil {
		return err
	}
	body := cmd.body("CREATE")
	var bindings, srcs int
	for _, d := range docs {
		switch d.kind {
		case "Binding":
			bindings++
			if !d.creates() {
				body["operation"] = "UPDATE"
			}
			body["binding"] = d.body
		case "Source":
			srcs++
			body["inlineSource"] = d.body
		default:
			return errors.New("break-glass apply: a Binding and at most one Source")
		}
	}
	if bindings != 1 || srcs > 1 {
		return errors.New("break-glass apply: exactly one Binding and at most one Source")
	}
	return cmd.changed("break-glass", func(ctx context.Context, c *client.Client) ([]filed, error) {
		return answers(cmd.post(ctx, c, "POST", path("break-glass"), nil, body))
	})
}

// BreakGlassDelete is an emergency revocation.
type BreakGlassDelete struct {
	Base
	BGOptions
	ExpectedRevision int64 `short:"r" long:"expected-revision" required:"true" description:"Expected current revision of the binding."`
	Args             struct {
		Name string `positional-arg-name:"name" description:"Binding name."`
	} `positional-args:"yes" required:"yes"`
}

func (cmd *BreakGlassDelete) Execute([]string) error {
	body := cmd.body("DELETE")
	body["name"], body["expectedRevision"] = cmd.Args.Name, cmd.ExpectedRevision
	return cmd.changed("break-glass", func(ctx context.Context, c *client.Client) ([]filed, error) {
		return answers(cmd.post(ctx, c, "POST", path("break-glass"), nil, body))
	})
}

// GovernanceCheck evaluates the manifest's documents without filing them
// (ligo governance check -f FILE).
type GovernanceCheck struct {
	Base
	File string `short:"f" long:"file" required:"true" description:"Manifest to evaluate (YAML or JSON, or '-' for stdin)."`
}

func (cmd *GovernanceCheck) Execute([]string) error {
	docs, err := readManifest(cmd.File)
	if err != nil {
		return err
	}
	created := map[string]map[string]any{}
	for _, d := range docs {
		if d.kind == "Source" {
			created[d.name] = d.body
		}
	}
	return cmd.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		items := []any{}
		for _, d := range docs {
			body := d.body
			if d.kind == "Binding" {
				source := body["source"]
				if s, ok := created[fmt.Sprint(source)]; ok { // a source of the file: by its identity
					source = map[string]any{"trustDomain": client.Lookup(s, "identity.trustDomain"), "svidRegex": client.Lookup(s, "identity.svidRegex")}
				}
				body = map[string]any{"resourceType": "BINDING", "name": d.name, "source": source, "target": body["target"], "accessLevel": body["accessLevel"]}
			} else {
				body = map[string]any{"kind": d.kind, "metadata": body["metadata"], "identity": body["identity"]}
			}
			var v any
			if err := c.Do(ctx, "POST", path("governance", "evaluate"), nil, body, &v); err != nil {
				return nil, nil, fmt.Errorf("%s %s: %w", strings.ToLower(d.kind), d.name, err)
			}
			items = append(items, v)
		}
		return map[string]any{"items": items}, []client.Column{col("TYPE", "resourceType"), col("NAME", "name"), col("SCOPES", "scopes"),
			col("PREFIX OK", "namePrefix.valid"), col("CONSENT", "consent"), col("INTERCONNECT", "interconnect"), col("SIDES", "sides")}, nil
	})
}
