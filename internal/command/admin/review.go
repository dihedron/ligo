package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"github.com/dihedron/ligo/internal/client"
)

// Review is ligo cr review: an interactive queue of the change requests
// awaiting the caller, to read and decide several at once. It needs a
// terminal; cr list and cr approve are its scriptable equivalents (§8.4
// "Output").
type Review struct {
	Base
	Scope string `long:"scope" description:"Only requests with a scope matching this pattern."`
	Kind  string `short:"k" long:"kind" choice:"source" choice:"target" choice:"binding" description:"Only requests of this resource kind."`
	Zone  string `short:"z" long:"zone" description:"Only requests of this zone."`
}

func (cmd *Review) Execute([]string) error {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		if info, err := f.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
			return errors.New("cr review needs a terminal: use ligo cr list --awaiting-me and ligo cr approve")
		}
	}
	return cmd.connected(func(ctx context.Context, c *client.Client) error {
		q := url.Values{"awaitingMe": {"true"}}
		for k, v := range map[string]string{"scope": cmd.Scope, "resourceType": strings.ToUpper(cmd.Kind), "zone": cmd.Zone} {
			if v != "" {
				q.Set(k, v)
			}
		}
		_, err := tea.NewProgram(newReview(ctx, c, q)).Run()
		return err
	})
}

// api is what the review calls: *client.Client.
type api interface {
	Do(ctx context.Context, method, path string, query url.Values, body, out any) error
}

type mode int

const (
	queueMode mode = iota
	detailMode
	confirmMode // the comment, and what will be sent
	resultsMode
)

// review is the model of ligo cr review.
type review struct {
	ctx      context.Context
	api      api
	query    url.Values
	items    []map[string]any
	selected map[string]bool // by change request id
	cursor   int
	mode     mode
	action   string // approve or decline
	comment  string
	detail   viewport.Model
	results  []string
	err      error
	height   int
}

func newReview(ctx context.Context, a api, q url.Values) *review {
	return &review{ctx: ctx, api: a, query: q, selected: map[string]bool{}, detail: viewport.New(viewport.WithHeight(20)), height: 24}
}

type loadedMsg struct {
	items []map[string]any
	err   error
}

type detailMsg struct {
	text string
	err  error
}

type doneMsg struct{ results []string }

// load reads every page of the queue, oldest first.
func (m *review) load() tea.Cmd {
	return func() tea.Msg {
		var all []map[string]any
		q := url.Values{}
		for k, v := range m.query {
			q[k] = v
		}
		for {
			var page struct {
				Items         []map[string]any `json:"items"`
				NextPageToken *string          `json:"nextPageToken"`
			}
			if err := m.api.Do(m.ctx, "GET", path("change-requests"), q, nil, &page); err != nil {
				return loadedMsg{err: err}
			}
			all = append(all, page.Items...)
			if page.NextPageToken == nil {
				break
			}
			q.Set("pageToken", *page.NextPageToken)
		}
		slices.Reverse(all) // the API lists newest first
		return loadedMsg{items: all}
	}
}

func (m *review) Init() tea.Cmd { return m.load() }

func id(cr map[string]any) string { s, _ := cr["id"].(string); return s }

// targets are the selected requests, or the one under the cursor.
func (m *review) targets() []map[string]any {
	var out []map[string]any
	for _, cr := range m.items {
		if m.selected[id(cr)] {
			out = append(out, cr)
		}
	}
	if len(out) == 0 && m.cursor < len(m.items) {
		out = append(out, m.items[m.cursor])
	}
	return out
}

func (m *review) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.detail.SetWidth(msg.Width)
		m.detail.SetHeight(max(msg.Height-4, 3))
		return m, nil
	case loadedMsg:
		m.items, m.err = msg.items, msg.err
		m.cursor = min(m.cursor, max(len(m.items)-1, 0))
		for k := range m.selected {
			if !slices.ContainsFunc(m.items, func(cr map[string]any) bool { return id(cr) == k }) {
				delete(m.selected, k)
			}
		}
		return m, nil
	case detailMsg:
		if msg.err != nil {
			m.err, m.mode = msg.err, queueMode
			return m, nil
		}
		m.detail.SetContent(msg.text)
		return m, nil
	case doneMsg:
		m.results, m.mode, m.selected = msg.results, resultsMode, map[string]bool{}
		return m, m.load()
	case tea.KeyPressMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *review) key(k tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if k.String() == "ctrl+c" {
		return m, tea.Quit
	}
	switch m.mode {
	case detailMode:
		if s := k.String(); s == "esc" || s == "q" {
			m.mode = queueMode
			return m, nil
		}
		var cmd tea.Cmd
		m.detail, cmd = m.detail.Update(k)
		return m, cmd
	case confirmMode:
		switch k.String() {
		case "esc":
			m.mode = queueMode
		case "enter":
			if m.action == "decline" && strings.TrimSpace(m.comment) == "" {
				return m, nil // a decline needs its reason
			}
			return m, m.submit(m.targets(), m.action, m.comment)
		case "backspace":
			if r := []rune(m.comment); len(r) > 0 {
				m.comment = string(r[:len(r)-1])
			}
		default:
			m.comment += k.Text
		}
		return m, nil
	case resultsMode:
		m.mode = queueMode
		return m, nil
	}
	switch k.String() {
	case "q":
		return m, tea.Quit
	case "up", "k":
		m.cursor = max(m.cursor-1, 0)
	case "down", "j":
		m.cursor = min(m.cursor+1, max(len(m.items)-1, 0))
	case "space":
		if m.cursor < len(m.items) {
			i := id(m.items[m.cursor])
			m.selected[i] = !m.selected[i]
			if !m.selected[i] {
				delete(m.selected, i)
			}
		}
	case "r":
		m.err = nil
		return m, m.load()
	case "enter":
		if m.cursor < len(m.items) {
			m.mode = detailMode
			m.detail.SetContent("loading…")
			return m, m.show(id(m.items[m.cursor]))
		}
	case "a", "d":
		if len(m.items) > 0 {
			m.action, m.comment, m.mode = map[string]string{"a": "approve", "d": "decline"}[k.String()], "", confirmMode
		}
	}
	return m, nil
}

// show reads a request with its diff for the detail view.
func (m *review) show(crID string) tea.Cmd {
	return func() tea.Msg {
		var cr map[string]any
		if err := m.api.Do(m.ctx, "GET", path("change-requests", crID), nil, nil, &cr); err != nil {
			return detailMsg{err: err}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%v %v %v (%v, consent %v)\n", cr["resourceType"], cr["operation"], cr["resourceName"], cr["kind"], cr["consent"])
		fmt.Fprintf(&b, "requested by %v at %v; expires %v\n", cr["requestedBy"], cr["requestedAt"], cr["expiresAt"])
		for _, k := range []string{"ownerScope", "sourceScope", "targetScope", "platformScope", "interconnectRule", "dependsOn"} {
			if v := cr[k]; v != nil && v != "" {
				fmt.Fprintf(&b, "%s: %v\n", k, v)
			}
		}
		fmt.Fprintf(&b, "payloadSha256: %v\n\nsides:\n", cr["payloadSha256"])
		for _, s := range cr["sides"].([]any) {
			sd := s.(map[string]any)
			fmt.Fprintf(&b, "  %-16v %-28v %-9v %v\n", sd["side"], sd["scope"], sd["basis"], cell(sd["decision"], "pending"))
		}
		for _, k := range []string{"diff", "payload"} {
			if v, ok := cr[k]; ok && v != nil {
				out, _ := json.MarshalIndent(v, "", "  ")
				fmt.Fprintf(&b, "\n%s:\n%s\n", k, out)
			}
		}
		return detailMsg{text: b.String()}
	}
}

func cell(v any, empty string) string {
	if v == nil {
		return empty
	}
	return fmt.Sprint(v)
}

// submit decides each request: approve takes its awaiting sides one by
// one, with the payloadSha256 that was shown, until it is no longer
// pending; decline declines every side the caller may decide.
func (m *review) submit(crs []map[string]any, action, comment string) tea.Cmd {
	return func() tea.Msg {
		var results []string
		for _, cr := range crs {
			label := fmt.Sprintf("%.8s %v %v", id(cr), cr["resourceType"], cr["resourceName"])
			status, err := m.decide(cr, action, comment)
			if err != nil {
				results = append(results, label+": "+err.Error())
				continue
			}
			results = append(results, label+": "+status)
		}
		return doneMsg{results: results}
	}
}

func (m *review) decide(cr map[string]any, action, comment string) (string, error) {
	p := path("change-requests", id(cr), action)
	var out struct {
		ChangeRequest map[string]any `json:"changeRequest"`
	}
	if action == "decline" {
		if err := m.api.Do(m.ctx, "POST", p, nil, map[string]any{"comment": comment}, &out); err != nil {
			return "", err
		}
		return fmt.Sprint(out.ChangeRequest["status"]), nil
	}
	status, decided := "PENDING", 0
	var others []string
	sides, _ := cr["awaitingApproval"].([]any)
	for _, side := range sides {
		body := map[string]any{"payloadSha256": cr["payloadSha256"], "side": side, "comment": comment}
		err := m.api.Do(m.ctx, "POST", p, nil, body, &out)
		var problem *client.Problem
		if errors.As(err, &problem) && problem.Status == 403 { // a side for another approver
			others = append(others, fmt.Sprint(side))
			continue
		}
		if err != nil {
			return "", fmt.Errorf("side %v: %w", side, err)
		}
		decided++
		if status = fmt.Sprint(out.ChangeRequest["status"]); status != "PENDING" {
			break
		}
	}
	if decided == 0 {
		return "", fmt.Errorf("no side you may decide (%s)", strings.Join(others, ", "))
	}
	if len(others) > 0 && status == "PENDING" {
		status += ", awaiting others for " + strings.Join(others, ", ")
	}
	return status, nil
}

func (m *review) View() tea.View {
	var b strings.Builder
	switch m.mode {
	case detailMode:
		b.WriteString(m.detail.View() + "\n\n↑/↓ scroll · esc back")
	case confirmMode:
		fmt.Fprintf(&b, "%s these change requests:\n\n", strings.ToUpper(m.action[:1])+m.action[1:])
		for _, cr := range m.targets() {
			fmt.Fprintf(&b, "  %.8s %v %v %v  sides %v  sha256 %.12v…\n", id(cr), cr["resourceType"], cr["operation"], cr["resourceName"],
				cr["awaitingApproval"], cr["payloadSha256"])
		}
		need := "optional"
		if m.action == "decline" {
			need = "required"
		}
		fmt.Fprintf(&b, "\nComment (%s): %s█\n\nenter submit · esc cancel", need, m.comment)
	case resultsMode:
		b.WriteString("Results:\n\n")
		for _, r := range m.results {
			b.WriteString("  " + r + "\n")
		}
		b.WriteString("\nany key: back to the queue")
	default:
		b.WriteString("Change requests awaiting your decision\n\n")
		if m.err != nil {
			b.WriteString("error: " + m.err.Error() + "\n\n")
		}
		if len(m.items) == 0 {
			b.WriteString("  nothing awaits you\n")
		}
		for i, cr := range m.items {
			cursor, mark := " ", "[ ]"
			if i == m.cursor {
				cursor = ">"
			}
			if m.selected[id(cr)] {
				mark = "[x]"
			}
			fmt.Fprintf(&b, "%s %s %.8s  %-7v %-6v %-32v awaiting %v  by %v\n", cursor, mark, id(cr), cr["resourceType"], cr["operation"],
				cr["resourceName"], cr["awaitingApproval"], cr["requestedBy"])
		}
		b.WriteString("\nspace select · enter details · a approve · d decline · r refresh · q quit")
	}
	v := tea.NewView(b.String())
	v.AltScreen = true
	return v
}
