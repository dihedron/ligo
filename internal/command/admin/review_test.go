package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/dihedron/ligo/internal/client"
)

// memAPI answers by "METHOD path" with handlers, and records calls.
type memAPI struct {
	mu       sync.Mutex
	handlers map[string]func(q url.Values, body map[string]any) (string, error)
	calls    []string
}

func (a *memAPI) Do(_ context.Context, method, p string, q url.Values, body, out any) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	b, _ := json.Marshal(body)
	var in map[string]any
	_ = json.Unmarshal(b, &in)
	a.calls = append(a.calls, method+" "+p+" "+string(b))
	h, ok := a.handlers[method+" "+p]
	if !ok {
		return &client.Problem{Status: 404, Type: "urn:ligo:problem:not-found", Detail: p}
	}
	answer, err := h(q, in)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(answer), out)
}

func key(s string) tea.KeyPressMsg {
	switch s {
	case "space":
		return tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "backspace":
		return tea.KeyPressMsg{Code: tea.KeyBackspace}
	case "ctrl+c":
		return tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl}
	}
	return tea.KeyPressMsg{Code: []rune(s)[0], Text: s}
}

// drive sends msg, then runs each command the model returns, feeding its
// message back, until none is left; it reports whether the program quit.
func drive(m *review, msg tea.Msg) bool {
	for msg != nil {
		_, cmd := m.Update(msg)
		if cmd == nil {
			return false
		}
		if msg = cmd(); msg == nil {
			return false
		}
		if _, ok := msg.(tea.QuitMsg); ok {
			return true
		}
	}
	return false
}

func view(m *review) string { return m.View().Content }

const queuePage1 = `{"items":[{"id":"cr-newer-0000","resourceType":"BINDING","operation":"CREATE","resourceName":"b2","awaitingApproval":["TARGET"],"payloadSha256":"bbbb","requestedBy":"olga"}],"nextPageToken":"t1"}`
const queuePage2 = `{"items":[{"id":"cr-older-0000","resourceType":"TARGET","operation":"CREATE","resourceName":"t1","awaitingApproval":["OWNER","PLATFORM"],"payloadSha256":"aaaa","requestedBy":"olga"}],"nextPageToken":null}`

// TestReview: the queue loads every page oldest first; requests are
// selected and approved side by side with the hash that was shown, a side
// of another approver is skipped, failures are reported per request, and
// the queue reloads.
func TestReview(t *testing.T) {
	reloaded := false
	a := &memAPI{handlers: map[string]func(url.Values, map[string]any) (string, error){
		"GET /v1/admin/change-requests": func(q url.Values, _ map[string]any) (string, error) {
			if q.Get("awaitingMe") != "true" {
				return "", fmt.Errorf("not awaitingMe")
			}
			if reloaded {
				return `{"items":[],"nextPageToken":null}`, nil
			}
			if q.Get("pageToken") == "t1" {
				return queuePage2, nil
			}
			return queuePage1, nil
		},
		"POST /v1/admin/change-requests/cr-older-0000/approve": func(_ url.Values, b map[string]any) (string, error) {
			if b["payloadSha256"] != "aaaa" || b["comment"] != "ok" {
				return "", fmt.Errorf("body %v", b)
			}
			if b["side"] == "OWNER" {
				return "", &client.Problem{Status: 403, Type: "urn:ligo:problem:forbidden", Detail: "not yours"}
			}
			reloaded = true
			return `{"changeRequest":{"status":"APPLIED"}}`, nil
		},
		"POST /v1/admin/change-requests/cr-newer-0000/approve": func(url.Values, map[string]any) (string, error) {
			return "", &client.Problem{Status: 409, Type: "urn:ligo:problem:payload-mismatch", Detail: "changed"}
		},
	}}
	m := newReview(context.Background(), a, url.Values{"awaitingMe": {"true"}})
	drive(m, m.Init()())
	if len(m.items) != 2 || id(m.items[0]) != "cr-older-0000" || !strings.Contains(view(m), "> [ ] cr-older") {
		t.Fatalf("queue:\n%s", view(m))
	}
	for _, k := range []string{"space", "down", "space"} {
		drive(m, key(k))
	}
	if len(m.targets()) != 2 || !strings.Contains(view(m), "[x] cr-newer") {
		t.Fatalf("selection:\n%s", view(m))
	}
	drive(m, key("a"))
	if m.mode != confirmMode || !strings.Contains(view(m), "sha256 aaaa") || !strings.Contains(view(m), "Approve these") {
		t.Fatalf("confirm:\n%s", view(m))
	}
	for _, k := range []string{"o", "k", "x", "backspace"} {
		drive(m, key(k))
	}
	drive(m, key("enter"))
	results := strings.Join(m.results, "\n")
	if m.mode != resultsMode || !strings.Contains(results, "cr-older TARGET t1: APPLIED") || !strings.Contains(results, "payload-mismatch") {
		t.Fatalf("results:\n%s\n%v", view(m), a.calls)
	}
	if len(m.items) != 0 || len(m.selected) != 0 {
		t.Errorf("not reloaded: %v %v", m.items, m.selected)
	}
	drive(m, key("x"))
	if m.mode != queueMode || !strings.Contains(view(m), "nothing awaits you") {
		t.Errorf("back to the queue:\n%s", view(m))
	}
	if !drive(m, key("q")) {
		t.Error("q does not quit")
	}
}

// TestReviewDecline: a decline needs its reason; it declines every side
// the caller may decide; a request only for other approvers is reported.
func TestReviewDecline(t *testing.T) {
	a := &memAPI{handlers: map[string]func(url.Values, map[string]any) (string, error){
		"GET /v1/admin/change-requests": func(url.Values, map[string]any) (string, error) { return queuePage2, nil },
		"POST /v1/admin/change-requests/cr-older-0000/decline": func(_ url.Values, b map[string]any) (string, error) {
			if b["comment"] != "no" || b["side"] != nil {
				return "", fmt.Errorf("body %v", b)
			}
			return `{"changeRequest":{"status":"REJECTED"}}`, nil
		},
		"POST /v1/admin/change-requests/cr-older-0000/approve": func(url.Values, map[string]any) (string, error) {
			return "", &client.Problem{Status: 403, Type: "urn:ligo:problem:forbidden", Detail: "not yours"}
		},
	}}
	m := newReview(context.Background(), a, url.Values{"awaitingMe": {"true"}})
	drive(m, m.Init()())
	drive(m, key("d"))
	drive(m, key("enter"))
	if m.mode != confirmMode || !strings.Contains(view(m), "(required)") {
		t.Fatalf("a decline without a reason was sent:\n%s", view(m))
	}
	drive(m, key("n"))
	drive(m, key("o"))
	drive(m, key("enter"))
	if !strings.Contains(strings.Join(m.results, ""), "REJECTED") {
		t.Errorf("decline: %v %v", m.results, a.calls)
	}
	drive(m, key("x"))
	drive(m, key("a"))
	drive(m, key("enter"))
	if r := strings.Join(m.results, ""); !strings.Contains(r, "no side you may decide (OWNER, PLATFORM)") {
		t.Errorf("only other approvers' sides: %s", r)
	}
	drive(m, key("x"))
	drive(m, key("d"))
	drive(m, key("esc"))
	if m.mode != queueMode {
		t.Errorf("esc does not cancel")
	}
	if !drive(m, key("ctrl+c")) {
		t.Error("ctrl+c does not quit")
	}
}

// TestReviewDetail: enter shows the request with its sides, hash and
// diff; esc goes back; a failing load or detail shows the error.
func TestReviewDetail(t *testing.T) {
	a := &memAPI{handlers: map[string]func(url.Values, map[string]any) (string, error){
		"GET /v1/admin/change-requests": func(url.Values, map[string]any) (string, error) { return queuePage2, nil },
		"GET /v1/admin/change-requests/cr-older-0000": func(url.Values, map[string]any) (string, error) {
			return `{"id":"cr-older-0000","resourceType":"TARGET","operation":"UPDATE","resourceName":"t1","kind":"STANDARD","consent":"ALL",
				"ownerScope":"dc/x/ledger","payloadSha256":"aaaa","sides":[{"side":"OWNER","scope":"dc/x/ledger","basis":"HUMAN","decision":null}],
				"diff":{"changes":[{"field":"description","old":"a","new":"b"}]}}`, nil
		},
	}}
	m := newReview(context.Background(), a, url.Values{})
	drive(m, m.Init()())
	drive(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	drive(m, key("enter"))
	if v := view(m); m.mode != detailMode || !strings.Contains(v, "payloadSha256: aaaa") || !strings.Contains(v, `"field": "description"`) ||
		!strings.Contains(v, "OWNER") || !strings.Contains(v, "ownerScope: dc/x/ledger") {
		t.Fatalf("detail:\n%s", v)
	}
	drive(m, key("down"))
	drive(m, key("esc"))
	if m.mode != queueMode {
		t.Error("esc does not go back")
	}
	delete(a.handlers, "GET /v1/admin/change-requests/cr-older-0000")
	drive(m, key("enter"))
	if m.mode != queueMode || !strings.Contains(view(m), "error: ") {
		t.Errorf("a failing detail:\n%s", view(m))
	}
	delete(a.handlers, "GET /v1/admin/change-requests")
	drive(m, key("r"))
	if !strings.Contains(view(m), "error: 404") {
		t.Errorf("a failing load:\n%s", view(m))
	}
}

// TestReviewNeedsTerminal: without a terminal, review points to the
// scriptable commands.
func TestReviewNeedsTerminal(t *testing.T) {
	if err := (&Review{}).Execute(nil); err == nil || !strings.Contains(err.Error(), "needs a terminal") {
		t.Errorf("no terminal: %v", err)
	}
}
