package admin

import (
	"context"
	"strings"
	"time"

	"github.com/dihedron/ligo/internal/client"
)

// Get displays a source, target or binding (ligo get KIND NAME).
type Get struct {
	Base
	Args ResourceArgs `positional-args:"yes" required:"yes"`
}

func (cmd *Get) Execute([]string) error {
	return cmd.get(path(cmd.Args.Kind+"s", cmd.Args.Name), nil, columns[cmd.Args.Kind]...)
}

// List lists sources, targets or bindings (ligo list KIND).
type List struct {
	Base
	Page
	Zone           string `short:"z" long:"zone" description:"Filter by zone (targets, bindings)."`
	Scope          string `long:"scope" description:"Filter by governance scope pattern (any scope of the resource)."`
	Source         string `long:"source" description:"Bindings of this source."`
	Target         string `long:"target" description:"Bindings of this target."`
	Platform       string `long:"platform" description:"Filter by platform (targets, bindings)."`
	Type           string `short:"t" long:"type" description:"Filter by platform type (targets, bindings)."`
	State          string `long:"state" choice:"ACTIVE" choice:"DEPRECATED" choice:"RETIRED" description:"Filter by state (sources, targets)."`
	Phase          string `long:"phase" choice:"PROVISIONING" choice:"ACTIVE" choice:"FAILED" choice:"DELETING" choice:"DELETE_FAILED" description:"Filter by lifecycle phase (bindings)."`
	TrustDomain    string `long:"trust-domain" description:"Filter by source trust domain."`
	ExpiringBefore string `long:"expiring-before" description:"Bindings expiring before this RFC 3339 time."`
	Args           struct {
		Kind string `positional-arg-name:"kind" choice:"sources" choice:"targets" choice:"bindings" description:"Resource kind."`
	} `positional-args:"yes" required:"yes"`
}

func (cmd *List) Execute([]string) error {
	q := cmd.query("zone", cmd.Zone, "scope", cmd.Scope, "source", cmd.Source, "target", cmd.Target, "platform", cmd.Platform,
		"platformType", cmd.Type, "state", cmd.State, "phase", cmd.Phase, "trustDomain", cmd.TrustDomain, "expiringBefore", cmd.ExpiringBefore)
	return cmd.get(path(cmd.Args.Kind), q, columns[strings.TrimSuffix(cmd.Args.Kind, "s")]...)
}

// Flows prints the effective network flows of a binding (ligo flows NAME).
type Flows struct {
	Base
	Args struct {
		Binding string `positional-arg-name:"binding" description:"Binding name."`
	} `positional-args:"yes" required:"yes"`
}

func (cmd *Flows) Execute([]string) error {
	return cmd.flows(path("bindings", cmd.Args.Binding, "flows"))
}

// flows prints networkFlows as the table's items.
func (b *Base) flows(p string) error {
	return b.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		var v map[string]any
		if err := c.Do(ctx, "GET", p, nil, nil, &v); err != nil {
			return nil, nil, err
		}
		if b.format() == "table" {
			return map[string]any{"items": v["networkFlows"]}, columns["flow"], nil
		}
		return v, nil, nil
	})
}

// Platform: ligo platform list|show|schema.
type Platform struct {
	List   PlatformList   `command:"list" alias:"ls" description:"List configured platforms and their health."`
	Show   PlatformShow   `command:"show" description:"Show a platform, including its flows and privilege bounds."`
	Schema PlatformSchema `command:"schema" description:"Fetch the UI forms (target definition, access-level grants, binding parameters) of a platform."`
}

type PlatformList struct{ Base }

func (cmd *PlatformList) Execute([]string) error {
	return cmd.get(path("platforms"), nil, columns["platform"]...)
}

type PlatformShow struct {
	Base
	Args NameArg `positional-args:"yes" required:"yes"`
}

func (cmd *PlatformShow) Execute([]string) error {
	return cmd.get(path("platforms", cmd.Args.Name), nil)
}

type PlatformSchema struct {
	Base
	Args NameArg `positional-args:"yes" required:"yes"`
}

func (cmd *PlatformSchema) Execute([]string) error {
	return cmd.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		var v map[string]any
		if err := c.Do(ctx, "GET", path("platforms", cmd.Args.Name), nil, nil, &v); err != nil {
			return nil, nil, err
		}
		return v["uiSchemas"], nil, nil
	})
}

// Catalog: ligo catalog search|show|flows.
type Catalog struct {
	Search CatalogSearch `command:"search" description:"Search targets visible to you that the interconnection policy allows."`
	Show   CatalogShow   `command:"show" description:"Show a target's catalog card and the governance outcome for your sources."`
	Flows  CatalogFlows  `command:"flows" description:"Print a target's flows (JSON, for the verification tool) before any binding exists."`
}

type CatalogSearch struct {
	Base
	Page
	Query     string   `short:"q" long:"query" description:"Text to match in name, display name, description and labels."`
	Platform  string   `long:"platform" description:"Filter by platform."`
	Type      string   `short:"t" long:"type" description:"Filter by platform type."`
	Scope     string   `long:"scope" description:"Filter by target scope pattern."`
	Label     []string `long:"label" description:"Filter by label key=value (repeatable)."`
	ForSource string   `long:"for-source" description:"Only targets allowed for this source, marking those already bound."`
}

func (cmd *CatalogSearch) Execute([]string) error {
	q := cmd.query("q", cmd.Query, "platform", cmd.Platform, "platformType", cmd.Type, "scope", cmd.Scope, "forSource", cmd.ForSource)
	for _, l := range cmd.Label {
		q.Add("label", l) // shortcut: the server applies the first label only; filter the rest client-side when several are needed
	}
	return cmd.get(path("catalog", "targets"), q, columns["catalog"]...)
}

type CatalogShow struct {
	Base
	Args NameArg `positional-args:"yes" required:"yes"`
}

func (cmd *CatalogShow) Execute([]string) error {
	return cmd.get(path("catalog", "targets", cmd.Args.Name), nil)
}

type CatalogFlows struct {
	Base
	Args NameArg `positional-args:"yes" required:"yes"`
}

func (cmd *CatalogFlows) Execute([]string) error {
	return cmd.flows(path("catalog", "targets", cmd.Args.Name, "flows"))
}

// Audit: ligo audit list|verify.
type Audit struct {
	List   AuditList   `command:"list" alias:"ls" description:"List audit entries for a source, target or binding."`
	Verify AuditVerify `command:"verify" description:"Verify the cryptographic hash chain of the audit log."`
}

type AuditList struct {
	Base
	Page
	Args ResourceArgs `positional-args:"yes" required:"yes"`
}

func (cmd *AuditList) Execute([]string) error {
	return cmd.get(path(cmd.Args.Kind+"s", cmd.Args.Name, "audit"), cmd.query(), columns["audit"]...)
}

type AuditVerify struct{ Base }

func (cmd *AuditVerify) Execute([]string) error {
	return cmd.get(path("audit", "verify"), nil, client.Column{Header: "VALID", Path: "valid"}, client.Column{Header: "ENTRIES", Path: "entries"},
		client.Column{Header: "FIRST BROKEN", Path: "firstBroken"})
}

// Maintenance: ligo maintenance status (on and off come with the write
// commands).
type Maintenance struct {
	Status MaintenanceStatus `command:"status" description:"Show maintenance mode and the number of in-flight bindings."`
}

type MaintenanceStatus struct {
	Base
	WaitDrained bool `long:"wait-drained" description:"Block until no binding is PROVISIONING or DELETING."`
}

var maintenanceColumns = []client.Column{col("MAINTENANCE", "maintenanceMode"), col("REASON", "reason"), col("CHANGED BY", "changedBy"),
	col("CHANGED AT", "changedAt"), col("IN FLIGHT", "inFlight"), col("PROPAGATION QUEUED", "propagationQueued")}

// drainPoll is how often --wait-drained asks again.
var drainPoll = 2 * time.Second

func (cmd *MaintenanceStatus) Execute([]string) error {
	return cmd.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		for {
			var v map[string]any
			if err := c.Do(ctx, "GET", path("maintenance"), nil, nil, &v); err != nil {
				return nil, nil, err
			}
			if n, _ := v["inFlight"].(float64); !cmd.WaitDrained || n == 0 {
				return v, maintenanceColumns, nil
			}
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(drainPoll):
			}
		}
	})
}

// Governance: ligo governance show (check comes with the write commands).
type Governance struct {
	Show GovernanceShow `command:"show" description:"Show the governance policy in force and its SHA-256."`
}

type GovernanceShow struct{ Base }

func (cmd *GovernanceShow) Execute([]string) error { return cmd.get(path("governance"), nil) }

// ChangeRequest: ligo cr list|get (the decisions come with the write
// commands).
type ChangeRequest struct {
	List ChangeRequestList `command:"list" alias:"ls" description:"List change requests."`
	Get  ChangeRequestGet  `command:"get" description:"Inspect a change request, its diff, and its payloadSha256."`
}

type ChangeRequestList struct {
	Base
	Page
	Status     string `long:"status" choice:"PENDING" choice:"APPLIED" choice:"REJECTED" choice:"WITHDRAWN" choice:"EXPIRED" choice:"FAILED_TO_APPLY" description:"Filter by status."`
	Zone       string `short:"z" long:"zone" description:"Filter by zone."`
	Scope      string `long:"scope" description:"Filter by governance scope pattern (any scope of the request)."`
	AwaitingMe bool   `long:"awaiting-me" description:"Only requests with a pending side the caller may decide."`
	Kind       string `short:"k" long:"kind" choice:"source" choice:"target" choice:"binding" description:"Filter by resource kind."`
	Name       string `short:"n" long:"name" description:"Filter by resource name."`
}

func (cmd *ChangeRequestList) Execute([]string) error {
	awaiting := ""
	if cmd.AwaitingMe {
		awaiting = "true"
	}
	q := cmd.query("status", cmd.Status, "zone", cmd.Zone, "scope", cmd.Scope, "awaitingMe", awaiting,
		"resourceType", strings.ToUpper(cmd.Kind), "resourceName", cmd.Name)
	return cmd.get(path("change-requests"), q, columns["request"]...)
}

type ChangeRequestGet struct {
	Base
	Args struct {
		ID string `positional-arg-name:"cr-id" description:"Change request UUID."`
	} `positional-args:"yes" required:"yes"`
}

func (cmd *ChangeRequestGet) Execute([]string) error {
	return cmd.get(path("change-requests", cmd.Args.ID), nil)
}

// BreakGlass: ligo break-glass list (apply and delete come with the write
// commands).
type BreakGlass struct {
	List BreakGlassList `command:"list" alias:"ls" description:"List open and recent break-glass changes."`
}

type BreakGlassList struct {
	Base
	Open bool `long:"open" description:"Only open (unratified, unexpired) changes."`
}

func (cmd *BreakGlassList) Execute([]string) error {
	return cmd.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		var v map[string]any
		if err := c.Do(ctx, "GET", path("break-glass"), nil, nil, &v); err != nil {
			return nil, nil, err
		}
		if cmd.Open {
			items, _ := v["items"].([]any)
			open := []any{}
			for _, it := range items {
				if isOpen(it.(map[string]any), time.Now()) {
					open = append(open, it)
				}
			}
			v["items"] = open
		}
		return v, append(columns["request"], client.Column{Header: "EXPIRES", Path: "breakGlass.expiresAt"}), nil
	})
}

// isOpen: an applied break-glass change not yet expired with a side not
// yet ratified.
func isOpen(cr map[string]any, now time.Time) bool {
	bg, _ := cr["breakGlass"].(map[string]any)
	expires, err := time.Parse(time.RFC3339, func() string { s, _ := bg["expiresAt"].(string); return s }())
	if cr["status"] != "APPLIED" || err != nil || !expires.After(now) {
		return false
	}
	sides, _ := cr["sides"].([]any)
	for _, s := range sides {
		if sd, _ := s.(map[string]any); sd["basis"] == "BREAK_GLASS" && sd["ratifiedBy"] == nil {
			return true
		}
	}
	return false
}
