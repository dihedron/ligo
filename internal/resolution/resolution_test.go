package resolution

import (
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/regexpolicy"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const p = `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/`

var now = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func row(name, target, active, current string) Row {
	return Row{ID: uuid.NewV7(), Name: name, TargetName: target, SourceName: "src", TrustDomain: "cloud.internal",
		ActiveRevision: 1, ActiveRegex: active, SourceRegex: current, AuthConfig: []byte(`{}`), Spec: []byte(`{}`)}
}

func cache(t *testing.T, rows ...Row) *Cache {
	t.Helper()
	c := New(nil, Options{MaxStaleness: 5 * time.Minute, Policy: regexpolicy.DefaultPolicy()})
	c.now = func() time.Time { return now }
	c.replace(rows, now)
	return c
}

func names(bs []Binding) []string {
	var out []string
	for _, b := range bs {
		out = append(out, b.Name)
	}
	return out
}

func id(t *testing.T, s string) spiffeid.ID {
	t.Helper()
	return spiffeid.RequireFromString(s)
}

// TestINV01 checks that a binding is served only when both its active regex
// and its source's current regex match (a narrowed source takes effect at
// once), in the caller's trust domain.
func TestINV01(t *testing.T) {
	c := cache(t,
		row("b-ledger", "ledger", p+`ledger-[0-9]+$`, p+`ledger-[0-9]+$`),
		row("a-narrowed", "ledger2", p+`ledger-[0-9]+$`, p+`ledger-[0-9]$`),
		row("c-other", "orders", p+`orders$`, p+`orders$`),
	)
	got, err := c.Resolve(id(t, "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/ledger-12"), "")
	if err != nil || len(got) != 1 || got[0].Name != "b-ledger" {
		t.Errorf("ledger-12: %v %v, want only b-ledger (a-narrowed's source no longer matches)", names(got), err)
	}
	got, _ = c.Resolve(id(t, "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/ledger-1"), "")
	if want := []string{"a-narrowed", "b-ledger"}; len(got) != 2 || got[0].Name != want[0] || got[1].Name != want[1] {
		t.Errorf("ledger-1: %v, want %v sorted by name", names(got), want)
	}
	got, _ = c.Resolve(id(t, "spiffe://prod.internal/acct/fin-01/tenant/payments/sa/ledger-1"), "")
	if len(got) != 0 {
		t.Errorf("other trust domain: %v", names(got))
	}
	got, _ = c.Resolve(id(t, "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/ledger-1"), "ledger2")
	if len(got) != 1 || got[0].Name != "a-narrowed" {
		t.Errorf("?target=ledger2: %v", names(got))
	}
}

// TestINV15 checks that rows whose regexes fail the Appendix A validator are
// never served (fail closed).
func TestINV15(t *testing.T) {
	c := cache(t,
		row("bad-active", "t1", `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/.*$`, p+`x$`),
		row("bad-current", "t2", p+`x$`, `^spiffe://cloud\.internal/x|.*$`),
		row("good", "t3", p+`x$`, p+`x$`),
	)
	got, _ := c.Resolve(id(t, "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/x"), "")
	if len(got) != 1 || got[0].Name != "good" || c.InvalidRegexes() != 2 {
		t.Errorf("got %v, %d invalid; want only good, 2 invalid", names(got), c.InvalidRegexes())
	}
}

// TestINV25 checks that an expired binding is not served, before the
// sweeper revokes it.
func TestINV25(t *testing.T) {
	expired, later := now.Add(-time.Second), now.Add(time.Hour)
	a, b := row("expired", "t1", p+`x$`, p+`x$`), row("valid", "t2", p+`x$`, p+`x$`)
	a.ExpiresAt, b.ExpiresAt = &expired, &later
	got, _ := cache(t, a, b).Resolve(id(t, "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/x"), "")
	if len(got) != 1 || got[0].Name != "valid" {
		t.Errorf("got %v, want only valid", names(got))
	}
}

// TestStale checks that the cache refuses to answer once it has not been
// refreshed for max_staleness (§4.5 rule 4, 503).
func TestStale(t *testing.T) {
	c := cache(t, row("b", "t", p+`x$`, p+`x$`))
	c.now = func() time.Time { return now.Add(5*time.Minute + time.Second) }
	if _, err := c.Resolve(id(t, "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/x"), ""); !errors.Is(err, ErrStale) {
		t.Errorf("stale cache: %v, want ErrStale", err)
	}
	empty := New(nil, Options{MaxStaleness: time.Minute})
	if _, err := empty.Resolve(id(t, "spiffe://cloud.internal/x"), ""); !errors.Is(err, ErrStale) {
		t.Errorf("never loaded: %v, want ErrStale", err)
	}
}

// TestUpsertEvict covers the single-row refresh after a notification.
func TestUpsertEvict(t *testing.T) {
	r := row("b", "t", p+`x$`, p+`x$`)
	c := cache(t, r)
	caller := id(t, "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/x")
	r.TargetName = "t2"
	c.upsert(r)
	if got, _ := c.Resolve(caller, "t2"); len(got) != 1 {
		t.Errorf("after upsert: %v", names(got))
	}
	c.evict(r.ID)
	if got, _ := c.Resolve(caller, ""); len(got) != 0 {
		t.Errorf("after evict: %v", names(got))
	}
}
