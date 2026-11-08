//go:build lab

package serve

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The webhook e2e of ligo serve, run by lab.sh serve test-webhook, which stops
// and starts the receiver and the replicas between the tests
// (.specs/ligo-test-environment.md, "The webhook receiver hooks").

// breakGlass has livia apply a break-glass CREATE (AC-31), checks it active,
// and has dora revert it so that repeated runs stay under max_open.
func breakGlass(t *testing.T, source, target, name string) {
	t.Helper()
	livia, dora := newAdmin(t, "livia"), newAdmin(t, "dora")
	code, filed := livia.do("POST", "/v1/admin/break-glass", map[string]any{"operation": "CREATE",
		"binding":       map[string]any{"name": name, "source": source, "target": target, "accessLevel": "read"},
		"justification": "the on-call rotation needs the ledger now", "incidentReference": "INC0012345", "ttl": "1h"})
	if code/100 != 2 {
		t.Fatalf("break-glass: %d %v", code, filed)
	}
	phase(t, dora, name, "ACTIVE")
	cr, _ := filed["changeRequest"].(map[string]any)
	if cr == nil {
		t.Fatalf("break-glass: no change request: %v", filed)
	}
	if code, body := dora.do("POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/revert", map[string]any{"comment": "webhook e2e"}); code/100 != 2 {
		t.Fatalf("revert: %d %v", code, body)
	}
	phase(t, dora, name, "")
}

// TestServeWebhookEvents: a binding filed, approved and revoked, a break-glass
// change, and maintenance on and off, for TestServeWebhookFile to find.
func TestServeWebhookEvents(t *testing.T) {
	olga, dora := newAdmin(t, "olga"), newAdmin(t, "dora")
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	source, target := haFixture(t, olga, dora, "hk")

	code, filed := olga.do("POST", "/v1/admin/bindings", map[string]any{"name": "hook-rv-" + x, "source": source, "target": target, "accessLevel": "read"})
	filedCR(t, "binding", code, filed)
	approveAll(t, dora, filed)
	b := phase(t, olga, "hook-rv-"+x, "ACTIVE")
	revision := int64(b["metadata"].(map[string]any)["revision"].(float64))
	code, filed = olga.do("DELETE", fmt.Sprintf("/v1/admin/bindings/hook-rv-%s?expectedRevision=%d", x, revision), nil)
	filedCR(t, "revoke", code, filed)
	approveAll(t, dora, filed)
	phase(t, olga, "hook-rv-"+x, "")

	breakGlass(t, source, target, "hook-bg-"+x)
	TestServeWebhookMaintenance(t)
}

// TestServeWebhookDown (AC-37): with the receiver down, a break-glass change
// still applies.
func TestServeWebhookDown(t *testing.T) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	source, target := haFixture(t, newAdmin(t, "olga"), newAdmin(t, "dora"), "hd")
	start := time.Now()
	breakGlass(t, source, target, "hook-down-"+x)
	t.Logf("applied and reverted in %s with the receiver down", time.Since(start).Round(time.Second))
}

// TestServeWebhookMaintenance turns maintenance on and off through
// LIGO_E2E_ADMIN: two system events per webhook.
func TestServeWebhookMaintenance(t *testing.T) {
	ada := newAdmin(t, "ada")
	for _, on := range []bool{true, false} {
		if code, body := ada.do("PUT", "/v1/admin/maintenance", map[string]any{"enabled": on, "reason": "webhook e2e"}); code != http.StatusOK {
			t.Fatalf("maintenance %v: %d %v", on, code, body)
		}
	}
}

// hookEvent is one recorded request with its payload decoded.
type hookEvent struct {
	Hook, Verdict string
	raw           string
	Event         string `json:"event"`
	EventID       string `json:"eventId"`
	OccurredAt    string `json:"occurredAt"`
	Actor         string `json:"actor"`
	Realm         string `json:"realm"`
	SideScope     string `json:"sideScope"`
	SourceScope   string `json:"sourceScope"`
	TargetScope   string `json:"targetScope"`
	PlatformScope string `json:"platformScope"`
	Justification string `json:"justification"`
	Incident      string `json:"incidentReference"`
	ExpiresAt     string `json:"expiresAt"`
	Resource      struct {
		Type     string `json:"type"`
		Name     string `json:"name"`
		Source   string `json:"source"`
		Target   string `json:"target"`
		Platform string `json:"platform"`
	} `json:"resource"`
}

// TestServeWebhookFile reads what the receiver recorded: every request valid
// and every eventId once (§7.5); the fields of a BREAK_GLASS_USED (AC-31);
// scope filters; no secret anywhere.
func TestServeWebhookFile(t *testing.T) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	data, err := os.ReadFile(filepath.Join(e2eEnv(t, "LIGO_E2E_DIR"), "hooks.jsonl")) //nolint:gosec // written by lab.sh
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{e2eEnv(t, "LIGO_TEST_LDAP_LIVIA_PASS"), e2eEnv(t, "LIGO_TEST_LDAP_OLIVIA_PASS"), "Basic ", "password"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("the requests hold %q", secret)
		}
	}
	uuid7 := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	var events []hookEvent
	lines := bufio.NewScanner(strings.NewReader(string(data)))
	lines.Buffer(nil, 4<<20)
	for lines.Scan() {
		var rec struct{ Hook, Verdict, Body string }
		if err := json.Unmarshal(lines.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		e := hookEvent{Hook: rec.Hook, Verdict: rec.Verdict, raw: rec.Body}
		if err := json.Unmarshal([]byte(rec.Body), &e); err != nil {
			t.Fatalf("%s: %v", rec.Body, err)
		}
		if e.Verdict != "ok" {
			t.Errorf("verdict %s: %s", e.Verdict, e.raw)
		}
		if !uuid7.MatchString(e.EventID) || seen[e.EventID] {
			t.Errorf("eventId not a new UUIDv7: %s", e.raw)
		}
		seen[e.EventID] = true
		if _, err := time.Parse(time.RFC3339, e.OccurredAt); err != nil {
			t.Errorf("occurredAt: %s", e.raw)
		}
		events = append(events, e)
	}
	find := func(hook, event, name string) []hookEvent {
		var out []hookEvent
		for _, e := range events {
			if e.Hook == hook && e.Event == event && (name == "" || e.Resource.Name == name) {
				out = append(out, e)
			}
		}
		return out
	}

	// AC-31: the event says who, why, for which incident, until when
	used := find("oncall", "BREAK_GLASS_USED", "hook-bg-"+x)
	if len(used) != 1 {
		t.Fatalf("BREAK_GLASS_USED of hook-bg-%s at oncall: %d", x, len(used))
	}
	u := used[0]
	if u.Actor != "livia" || u.Justification == "" || u.Incident != "INC0012345" || u.Realm != "prod" ||
		u.SourceScope != "dc/corp-prod" || u.TargetScope != "dc/corp-prod/ledger" || u.PlatformScope != "dc/corp-prod" ||
		u.Resource.Type != "BINDING" || u.Resource.Source == "" || u.Resource.Target == "" || u.Resource.Platform != "pg-ledger" {
		t.Errorf("BREAK_GLASS_USED: %s", u.raw)
	}
	occurred, _ := time.Parse(time.RFC3339, u.OccurredAt)
	if at, err := time.Parse(time.RFC3339, u.ExpiresAt); err != nil || at.Sub(occurred).Round(time.Minute) != time.Hour {
		t.Errorf("BREAK_GLASS_USED expiresAt, 1h after: %s", u.raw)
	}
	if got := find("dba", "BREAK_GLASS_USED", "hook-bg-"+x); len(got) != 1 {
		t.Errorf("BREAK_GLASS_USED at dba, whose filter matches its target scope: %d", len(got))
	}

	// BINDING_REVOKED (AC-70): dora decided for dc/corp-prod, so the ledger's
	// scope hears of it; a break-glass revert, which every side decided, has
	// nobody to tell
	for _, hook := range []string{"oncall", "dba"} {
		if got := find(hook, "BINDING_REVOKED", "hook-rv-"+x); len(got) != 1 {
			t.Errorf("BINDING_REVOKED of hook-rv-%s at %s: %d", x, hook, len(got))
		}
	}
	if got := find("oncall", "BINDING_REVOKED", "hook-bg-"+x); len(got) != 0 {
		t.Errorf("a break-glass revert announced as BINDING_REVOKED: %s", got[0].raw)
	}

	// CR_AWAITING_APPROVAL, one per side: dba only of its own scope
	binding := "hook-rv-" + x
	var scopes []string
	for _, e := range find("oncall", "CR_AWAITING_APPROVAL", binding) {
		scopes = append(scopes, e.SideScope)
	}
	if !slices.Contains(scopes, "dc/corp-prod/ledger") || !slices.Contains(scopes, "dc/corp-prod") {
		t.Errorf("CR_AWAITING_APPROVAL at oncall: sides %v", scopes)
	}
	dba := find("dba", "CR_AWAITING_APPROVAL", binding)
	if len(dba) == 0 {
		t.Error("CR_AWAITING_APPROVAL at dba: none")
	}
	for _, e := range dba {
		if e.SideScope != "dc/corp-prod/ledger" {
			t.Errorf("dba received another scope's side: %s", e.raw)
		}
	}

	// elsewhere's filter matches nothing here: system events only, and those always
	for _, e := range events {
		if e.Hook == "elsewhere" && !strings.HasPrefix(e.Event, "SYSTEM_") {
			t.Errorf("elsewhere received %s", e.raw)
		}
	}
	for _, hook := range []string{"oncall", "dba", "elsewhere"} {
		if len(find(hook, "SYSTEM_MAINTENANCE_ENABLED", "")) == 0 || len(find(hook, "SYSTEM_MAINTENANCE_DISABLED", "")) == 0 {
			t.Errorf("%s misses a maintenance event", hook)
		}
	}
	t.Logf("%d requests, all valid", len(events))
}
