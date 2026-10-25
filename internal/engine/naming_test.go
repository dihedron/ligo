package engine

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/governance"
)

// TestAppendixB checks the derived principal name against values computed
// independently (Python hashlib and base64); the first is the binding of the
// §3.5 example, whose Vault role is bnd_ty7bsxjkraerelw2.
func TestAppendixB(t *testing.T) {
	for id, want := range map[string]string{
		"019286f8-7c80-7b2e-9f1a-4b5a6c7d8e9f": "bnd_ty7bsxjkraerelw2",
		"00000000-0000-0000-0000-000000000000": "bnd_g5dqr77xogo5lf46",
	} {
		got, err := DerivedPrincipalName(uuid.MustParse(id), "")
		if err != nil || got != want {
			t.Errorf("DerivedPrincipalName(%s) = (%q, %v), want %q", id, got, err, want)
		}
	}
	shape := regexp.MustCompile(`^bnd_[a-z2-7]{16}$`)
	for range 100 {
		if got, _ := DerivedPrincipalName(uuid.NewV7(), ""); !shape.MatchString(got) {
			t.Fatalf("%q is not bnd_ plus 16 base32 characters", got)
		}
	}
}

func TestAppendixBPrefix(t *testing.T) {
	id := uuid.MustParse("019286f8-7c80-7b2e-9f1a-4b5a6c7d8e9f")
	for prefix, want := range map[string]string{
		"svc_": "svc_ty7bsxjkraerelw2",
		"a":    "aty7bsxjkraerelw2",
		"Ab9_": "Ab9_ty7bsxjkraerelw2",
		"":     "bnd_ty7bsxjkraerelw2",
	} {
		if got, err := DerivedPrincipalName(id, prefix); err != nil || got != want {
			t.Errorf("prefix %q: (%q, %v), want %q", prefix, got, err, want)
		}
	}
	for _, prefix := range []string{"svc_x", "_svc", "9ab", "a-b", "äb"} {
		if _, err := DerivedPrincipalName(id, prefix); err == nil {
			t.Errorf("prefix %q accepted", prefix)
		}
	}
}

func TestValidName(t *testing.T) {
	for name, want := range map[string]bool{
		"payments-ledger-workers": true, "a": true, "0": true, strings.Repeat("a", 63): true,
		"": false, "-a": false, "a-": false, "A": false, "a_b": false, strings.Repeat("a", 64): false,
	} {
		if got := ValidName(name); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", name, got, want)
		}
	}
}

var prefixes = []governance.NamePrefix{
	{Scopes: []string{"cloud/*"}, Prefix: "{2}-{3}-"},
	{Scopes: []string{"dc/corp-prod/*"}, Prefix: "prod-", Resources: []string{string(KindTarget)}},
}

// TestAC56 is acceptance scenario AC-56.
func TestAC56(t *testing.T) {
	for _, v := range []struct {
		kind  Kind
		name  string
		scope string
		ok    bool
	}{
		{KindSource, "orders-workers", "cloud/fin-01/payments", false},
		{KindSource, "fin-01-hr-orders", "cloud/fin-01/payments", false},
		{KindSource, "fin-01-payments-orders-workers", "cloud/fin-01/payments", true},
		{KindBinding, "orders-db", "cloud/fin-01/payments", false},
		{KindBinding, "fin-01-payments-orders-db", "cloud/fin-01/payments", true},
	} {
		checkName(t, v.kind, v.name, v.scope, v.ok)
	}
}

func TestNamePrefixes(t *testing.T) {
	for _, v := range []struct {
		kind  Kind
		name  string
		scope string
		ok    bool
	}{
		{KindTarget, "prod-ledger", "dc/corp-prod/ledger", true},
		{KindTarget, "ledger", "dc/corp-prod/ledger", false},
		{KindTarget, "prod-", "dc/corp-prod/ledger", false}, // must be longer than the prefix
		{KindSource, "ledger", "dc/corp-prod/ledger", true}, // the entry is for targets only
		{KindSource, "anything", "k8s/team", true},          // no entry matches
		{KindSource, "x-y", "cloud/fin-01", false},          // {3} beyond the scope's segments
		{KindSource, "Bad", "k8s/team", false},
	} {
		checkName(t, v.kind, v.name, v.scope, v.ok)
	}
}

func checkName(t *testing.T, kind Kind, name, scope string, ok bool) {
	t.Helper()
	err := CheckName(kind, name, scope, prefixes)
	if ok && err != nil {
		t.Errorf("%s %q in %s: %v", kind, name, scope, err)
	}
	if !ok && !errors.Is(err, ErrInvalidName) {
		t.Errorf("%s %q in %s: got %v, want ErrInvalidName", kind, name, scope, err)
	}
}

// TestNarrowingPrivileges covers the privilege rows of §3.10, including
// AC-65 (write narrowed to LEDGER_RO_ROLE, read widened).
func TestNarrowingPrivileges(t *testing.T) {
	ro, rw := "role:LEDGER_RO_ROLE", "role:LEDGER_RW_ROLE"
	for _, v := range []struct {
		current, proposed []string
		want              bool
	}{
		{[]string{ro, rw}, []string{ro}, true},  // AC-65: narrowing write
		{[]string{ro}, []string{ro, rw}, false}, // AC-65: widening read
		{[]string{ro, rw}, []string{rw, ro}, true},
		{[]string{ro}, []string{}, true},
		{[]string{ro}, []string{"role:OTHER"}, false},
	} {
		if got := PrivilegesNarrower(v.current, v.proposed); got != v.want {
			t.Errorf("PrivilegesNarrower(%v, %v) = %v, want %v", v.current, v.proposed, got, v.want)
		}
	}
}

func TestNarrowingExpiry(t *testing.T) {
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	later := now.Add(time.Hour)
	for _, v := range []struct {
		current, proposed *time.Time
		want              bool
	}{
		{nil, &now, true},
		{&later, &now, true},
		{&now, &later, false},
		{&now, &now, false},
		{&now, nil, false},
		{nil, nil, false},
	} {
		if got := ExpiryNarrower(v.current, v.proposed); got != v.want {
			t.Errorf("ExpiryNarrower(%v, %v) = %v, want %v", v.current, v.proposed, got, v.want)
		}
	}
}
