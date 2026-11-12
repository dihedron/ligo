package admin

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/client"
	"github.com/dihedron/ligo/internal/sealing"
)

// Get displays a source, target, binding or instance (ligo get KIND NAME).
type Get struct {
	Base
	Args ResourceArgs `positional-args:"yes" required:"yes"`
}

func (cmd *Get) Execute([]string) error {
	return cmd.get(path(cmd.Args.Kind+"s", cmd.Args.Name), nil, columns[cmd.Args.Kind]...)
}

// List lists sources, targets, bindings or instances (ligo list KIND).
type List struct {
	Base
	Page
	Realm          string `long:"realm" description:"Filter by realm (targets, bindings)."`
	Jurisdiction   string `long:"jurisdiction" description:"Filter by jurisdiction pattern (any jurisdiction of the resource)."`
	Source         string `long:"source" description:"Bindings of this source."`
	Target         string `long:"target" description:"Bindings of this target."`
	Platform       string `long:"platform" description:"Filter by platform (targets, bindings)."`
	Type           string `short:"t" long:"type" description:"Filter by platform type (targets, bindings)."`
	State          string `long:"state" choice:"ACTIVE" choice:"DEPRECATED" choice:"RETIRED" description:"Filter by state (sources, targets)."`
	Phase          string `long:"phase" choice:"PROVISIONING" choice:"ACTIVE" choice:"FAILED" choice:"DELETING" choice:"DELETE_FAILED" description:"Filter by lifecycle phase (bindings)."`
	TrustDomain    string `long:"trust-domain" description:"Filter by source trust domain."`
	ExpiringBefore string `long:"expiring-before" description:"Bindings expiring before this RFC 3339 time."`
	Args           struct {
		Kind string `positional-arg-name:"kind" choice:"sources" choice:"targets" choice:"bindings" choice:"platforms" choice:"identity-providers" choice:"secret-stores" description:"Resource kind."`
	} `positional-args:"yes" required:"yes"`
}

func (cmd *List) Execute([]string) error {
	q := cmd.query("realm", cmd.Realm, "jurisdiction", cmd.Jurisdiction, "source", cmd.Source, "target", cmd.Target, "platform", cmd.Platform,
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
	Show   CatalogShow   `command:"show" description:"Show a target's catalog card and the charter outcome for your sources."`
	Flows  CatalogFlows  `command:"flows" description:"Print a target's flows (JSON, for the verification tool) before any binding exists."`
}

type CatalogSearch struct {
	Base
	Page
	Query        string   `short:"q" long:"query" description:"Text to match in name, display name, description and labels."`
	Platform     string   `long:"platform" description:"Filter by platform."`
	Type         string   `short:"t" long:"type" description:"Filter by platform type."`
	Jurisdiction string   `long:"jurisdiction" description:"Filter by target jurisdiction pattern."`
	Label        []string `long:"label" description:"Filter by label key=value (repeatable)."`
	ForSource    string   `long:"for-source" description:"Only targets allowed for this source, marking those already bound."`
}

func (cmd *CatalogSearch) Execute([]string) error {
	q := cmd.query("q", cmd.Query, "platform", cmd.Platform, "platformType", cmd.Type, "jurisdiction", cmd.Jurisdiction, "forSource", cmd.ForSource)
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

// Audit: ligo audit list|verify|export.
type Audit struct {
	List   AuditList   `command:"list" alias:"ls" description:"List audit entries for a source, target or binding."`
	Verify AuditVerify `command:"verify" description:"Verify the cryptographic hash chain of the audit log, or of an exported file."`
	Export AuditExport `command:"export" description:"Export the audit log through a signed checkpoint, verify the file and record the export (requires admin.full_access)."`
}

type AuditList struct {
	Base
	Page
	Args ResourceArgs `positional-args:"yes" required:"yes"`
}

func (cmd *AuditList) Execute([]string) error {
	return cmd.get(path(cmd.Args.Kind+"s", cmd.Args.Name, "audit"), cmd.query(), columns["audit"]...)
}

type AuditVerify struct {
	Base
	Full       bool     `long:"full" description:"Re-hash every entry, not only those after the newest signed checkpoint."`
	File       string   `long:"file" description:"Verify an exported file offline, without the server."`
	PublicKeys []string `long:"public-key" value-name:"KEYID/VERSION=BASE64" description:"With --file: a public key to verify the checkpoints with, instead of the file's own (repeatable)."`
}

var fileColumns = []client.Column{col("VALID", "valid"), col("FROM", "from"), col("THROUGH", "through"), col("ENTRIES", "entries"),
	col("CHECKPOINTS", "checkpoints"), col("CHANGE REQUESTS", "changeRequests"), col("KEYS FROM FILE", "keysFromFile"), col("FIRST BROKEN", "firstBroken"), col("REASON", "reason")}

func (cmd *AuditVerify) Execute([]string) error {
	if cmd.File != "" {
		return cmd.verifyFile()
	}
	var query url.Values
	if cmd.Full {
		query = url.Values{"full": {"true"}}
	}
	return cmd.get(path("audit", "verify"), query, client.Column{Header: "VALID", Path: "valid"}, client.Column{Header: "ENTRIES", Path: "entries"},
		client.Column{Header: "CHECKPOINTS", Path: "checkpoints"}, client.Column{Header: "FULL", Path: "full"}, client.Column{Header: "FIRST BROKEN", Path: "firstBroken"})
}

// Maintenance: ligo maintenance on|off|status.
type Maintenance struct {
	On     MaintenanceOn     `command:"on" description:"Enable maintenance mode on all replicas (requires admin.full_access)."`
	Off    MaintenanceOff    `command:"off" description:"Disable maintenance mode (requires admin.full_access)."`
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

// Executors: ligo executors list|recover.
type Executors struct {
	List    ExecutorsList    `command:"list" description:"Show the pending workflows and live database sessions of each executor."`
	Recover ExecutorsRecover `command:"recover" description:"Re-enqueue the pending workflows of a replica gone for good (requires admin.full_access)."`
}

type ExecutorsList struct{ Base }

func (cmd *ExecutorsList) Execute([]string) error {
	return cmd.get(path("executors"), nil, col("EXECUTOR", "executor"), col("VERSION", "applicationVersion"), col("PENDING", "pending"),
		col("OLDEST PENDING", "oldestPending"), col("LIVE SESSIONS", "liveSessions"), col("SELF", "self"))
}

// Charter: ligo charter show|check.
type Charter struct {
	Show  CharterShow  `command:"show" description:"Show the charter in force and its SHA-256."`
	Check CharterCheck `command:"check" description:"Evaluate a planned change: jurisdictions, name prefix, consent rule, interconnection rule and sides (nothing is stored)."`
}

type CharterShow struct{ Base }

func (cmd *CharterShow) Execute([]string) error { return cmd.get(path("charter"), nil) }

// ChangeRequest: ligo cr list|get|approve|decline|withdraw|ratify|revert|review.
type ChangeRequest struct {
	List     ChangeRequestList     `command:"list" alias:"ls" description:"List change requests."`
	Get      ChangeRequestGet      `command:"get" description:"Inspect a change request, its diff, and its payloadSha256."`
	Approve  ChangeRequestApprove  `command:"approve" description:"Approve one or more sides of a PENDING change request; applies it when every required side is approved (four-eyes)."`
	Decline  ChangeRequestDecline  `command:"decline" description:"Decline one or more sides of a PENDING change request."`
	Withdraw ChangeRequestWithdraw `command:"withdraw" description:"Withdraw own PENDING change request."`
	Ratify   ChangeRequestRatify   `command:"ratify" description:"Ratify one side of a break-glass change (approver, not the requester)."`
	Revert   ChangeRequestRevert   `command:"revert" description:"Revert an open break-glass change now."`
	Review   Review                `command:"review" description:"Interactive queue of the change requests awaiting you: read them and approve or decline several at once (needs a terminal)."`
}

type ChangeRequestList struct {
	Base
	Page
	Status       string `long:"status" choice:"PENDING" choice:"APPLIED" choice:"REJECTED" choice:"WITHDRAWN" choice:"EXPIRED" choice:"FAILED_TO_APPLY" description:"Filter by status."`
	Realm        string `long:"realm" description:"Filter by realm."`
	Jurisdiction string `long:"jurisdiction" description:"Filter by jurisdiction pattern (any jurisdiction of the request)."`
	AwaitingMe   bool   `long:"awaiting-me" description:"Only requests with a pending side the caller may decide."`
	Kind         string `short:"k" long:"kind" choice:"source" choice:"target" choice:"binding" description:"Filter by resource kind."`
	Name         string `short:"n" long:"name" description:"Filter by resource name."`
}

func (cmd *ChangeRequestList) Execute([]string) error {
	awaiting := ""
	if cmd.AwaitingMe {
		awaiting = "true"
	}
	q := cmd.query("status", cmd.Status, "realm", cmd.Realm, "jurisdiction", cmd.Jurisdiction, "awaitingMe", awaiting,
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

// BreakGlass: ligo break-glass apply|delete|list (Basic credentials only,
// §7.2.3).
type BreakGlass struct {
	Apply  BreakGlassApply  `command:"apply" description:"Emergency create or update from a manifest."`
	Delete BreakGlassDelete `command:"delete" description:"Emergency revocation (not reverted on expiry)."`
	List   BreakGlassList   `command:"list" alias:"ls" description:"List open and recent break-glass changes."`
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

// verifyFile checks an export offline (.specs/ligo-pruning.md §3.3); a file
// that does not verify is an error, after its result is printed.
func (cmd *AuditVerify) verifyFile() error {
	var keys sealing.KeySet
	for _, k := range cmd.PublicKeys {
		id, b64, ok := strings.Cut(k, "=")
		slash := strings.LastIndex(id, "/")
		pub, err := base64.StdEncoding.DecodeString(b64)
		if !ok || slash < 1 || err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("--public-key %q: want KEYID/VERSION=BASE64 of an ed25519 public key", k)
		}
		if keys == nil {
			keys = sealing.KeySet{}
		}
		if keys[id[:slash]] == nil {
			keys[id[:slash]] = map[string]ed25519.PublicKey{}
		}
		keys[id[:slash]][id[slash+1:]] = pub
	}
	res, err := verifyExport(cmd.File, keys)
	if err != nil {
		return err
	}
	if err := client.Print(cmd.writer(), cmd.format(), asMap(res), fileColumns...); err != nil {
		return err
	}
	if !res.Valid {
		return fmt.Errorf("%s does not verify: %s", cmd.File, res.Reason)
	}
	return nil
}

func verifyExport(file string, keys sealing.KeySet) (audit.FileResult, error) {
	f, err := os.Open(file) //nolint:gosec // the path is the operator's --file or --out
	if err != nil {
		return audit.FileResult{}, err
	}
	defer func() { _ = f.Close() }()
	return audit.VerifyFile(bufio.NewReader(f), keys)
}

// asMap gives v the shape client.Print's columns read.
func asMap(v any) map[string]any {
	b, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

type AuditExport struct {
	Base
	Through int64  `long:"through" description:"The checkpoint to export through (an audit entry id); the newest checkpoint by default."`
	Out     string `long:"out" required:"yes" description:"The file to write; it must not exist."`
}

// Execute downloads the export, verifies it with the keys it carries, and
// records it with its SHA-256 only if it verifies (.specs/ligo-pruning.md
// §3.2): pruning never passes an export that is not recorded.
func (cmd *AuditExport) Execute([]string) error {
	return cmd.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		f, err := os.OpenFile(cmd.Out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, nil, err
		}
		var query url.Values
		if cmd.Through > 0 {
			query = url.Values{"through": {strconv.FormatInt(cmd.Through, 10)}}
		}
		h := sha256.New()
		err = c.Do(ctx, "GET", path("audit", "export"), query, nil, io.MultiWriter(f, h))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(cmd.Out)
			return nil, nil, err
		}
		res, err := verifyExport(cmd.Out, nil)
		if err != nil {
			return nil, nil, err
		}
		if !res.Valid {
			return nil, nil, fmt.Errorf("%s does not verify (%s): the export is not recorded", cmd.Out, res.Reason)
		}
		sum := hex.EncodeToString(h.Sum(nil))
		if err := c.Do(ctx, "POST", path("audit", "exports"), nil, map[string]any{"through": res.Through, "sha256": sum}, nil); err != nil {
			return nil, nil, fmt.Errorf("%s verifies but was not recorded: %w", cmd.Out, err)
		}
		out := asMap(res)
		out["file"], out["sha256"] = cmd.Out, sum
		return out, []client.Column{col("FILE", "file"), col("FROM", "from"), col("THROUGH", "through"), col("ENTRIES", "entries"),
			col("CHECKPOINTS", "checkpoints"), col("SHA256", "sha256")}, nil
	})
}
