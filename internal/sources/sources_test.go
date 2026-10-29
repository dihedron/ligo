package sources

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
)

const (
	regex   = `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/ledger-[0-9]+$`
	sample1 = "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/ledger-1"
	sample2 = "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/ledger-2"
)

// example returns the §8.1 reference configuration.
func example(t *testing.T) *config.Config {
	t.Helper()
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func rules(t *testing.T) *Rules {
	t.Helper()
	r, err := NewRules(example(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func source() Source {
	return Source{
		Metadata: Metadata{Name: "fin-01-payments-ledger-workers"},
		Identity: Identity{TrustDomain: "cloud.internal", SVIDRegex: regex, SampleSPIFFEIDs: []string{sample1, sample2}},
	}
}

func slug(err error) string {
	var e *changerequests.Error
	if errors.As(err, &e) {
		return e.Slug
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

// TestValidate runs the source pipeline's own checks (§7.2.3 steps 1 to 7,
// §3.7) on a new source and on an update of the stored one.
func TestValidate(t *testing.T) {
	r := rules(t)
	stored := source()
	stored.Metadata.Scope, stored.Metadata.State = "cloud/fin-01/payments", "ACTIVE"
	for name, tc := range map[string]struct {
		edit   func(*Source)
		update bool
		want   string
	}{
		"valid":                {func(*Source) {}, false, ""},
		"name grammar":         {func(s *Source) { s.Metadata.Name = "Ledger_Workers" }, false, "validation-failed"},
		"name prefix":          {func(s *Source) { s.Metadata.Name = "ledger-workers" }, false, "validation-failed"},
		"unknown trust domain": {func(s *Source) { s.Identity.TrustDomain = "other.internal" }, false, "validation-failed"},
		"regex (Appendix A)":   {func(s *Source) { s.Identity.SVIDRegex = `^spiffe://cloud\.internal/.*$` }, false, "validation-failed"},
		"scope unresolvable": {func(s *Source) {
			s.Identity.SVIDRegex = `^spiffe://cloud\.internal/team/fin-01/sa/ledger-[0-9]+$`
			s.Identity.SampleSPIFFEIDs = nil
		}, false, "scope-unresolvable"},
		"sample not matched (AC-60)": {func(s *Source) {
			s.Identity.SampleSPIFFEIDs = []string{sample1, "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/other"}
		}, false, "sample-not-matched"},
		"sample of another domain": {func(s *Source) { s.Identity.SampleSPIFFEIDs = []string{"spiffe://prod.internal/x/y"} }, false, "sample-not-matched"},
		"scope on create":          {func(s *Source) { s.Metadata.Scope = "cloud/fin-01/payments" }, false, "validation-failed"},
		"listed without visibleTo": {func(s *Source) { s.Visibility.Mode = "LISTED" }, false, "validation-failed"},
		"display name too long":    {func(s *Source) { s.DisplayName = strings.Repeat("x", 129) }, false, "validation-failed"},
		"narrowing": {func(s *Source) {
			s.Identity.SVIDRegex = `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/ledger-1$`
			s.Identity.SampleSPIFFEIDs = []string{sample1}
		}, true, ""},
		"narrowing keeps a dropped sample": {func(s *Source) {
			s.Identity.SVIDRegex = `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/ledger-1$`
		}, true, "sample-not-matched"},
		"widening": {func(s *Source) {
			s.Identity.SVIDRegex = `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/[a-z]+-[0-9]+$`
		}, true, "widening-not-allowed"},
		"trust domain changed": {func(s *Source) { s.Identity.TrustDomain = "prod.internal" }, true, "immutable-field"},
	} {
		t.Run(name, func(t *testing.T) {
			s := source()
			var cur *Source
			if tc.update {
				s.Metadata.Scope, s.Metadata.State = stored.Metadata.Scope, "ACTIVE"
				cur = &stored
			}
			tc.edit(&s)
			_, err := r.validate(&s, cur)
			if slug(err) != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if err == nil && (s.Metadata.Scope != "cloud/fin-01/payments" || s.Metadata.State != "ACTIVE" || s.Visibility.Mode != "PRIVATE" || s.Kind != "Source") {
				t.Errorf("not normalized: %+v", s)
			}
		})
	}
}

// TestWideningWitness: a widening names an identity the new regex adds
// (§3.10 rule 2).
func TestWideningWitness(t *testing.T) {
	stored := source()
	stored.Metadata.Scope, stored.Metadata.State = "cloud/fin-01/payments", "ACTIVE"
	s := stored
	s.Identity.SVIDRegex = `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/[a-z]+-[0-9]+$`
	_, err := rules(t).validate(&s, &stored)
	if !strings.Contains(err.Error(), "spiffe://cloud.internal/acct/fin-01/tenant/payments/sa/") {
		t.Errorf("no witness: %v", err)
	}
}

func TestTransition(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		ok       bool
	}{
		{"ACTIVE", "DEPRECATED", true},
		{"DEPRECATED", "ACTIVE", true},
		{"ACTIVE", "RETIRED", true},
		{"DEPRECATED", "RETIRED", true},
		{"ACTIVE", "ACTIVE", true}, // no change of state
		{"DEPRECATED", "DEPRECATED", true},
		{"RETIRED", "ACTIVE", false},
		{"ACTIVE", "BOGUS", false},
	} {
		if err := Transition(tc.from, tc.to); (err == nil) != tc.ok {
			t.Errorf("%s -> %s: %v", tc.from, tc.to, err)
		}
	}
}

// TestVisibility: LISTED needs scope patterns; visibleTo is only for
// LISTED; the mode defaults to PRIVATE (§3.2).
func TestVisibility(t *testing.T) {
	for _, tc := range []struct {
		v  Visibility
		ok bool
	}{
		{Visibility{}, true},
		{Visibility{Mode: "PUBLIC"}, true},
		{Visibility{Mode: "LISTED", VisibleTo: []string{"cloud/*"}}, true},
		{Visibility{Mode: "LISTED", VisibleTo: []string{"Cloud!"}}, false},
		{Visibility{Mode: "PRIVATE", VisibleTo: []string{"cloud/*"}}, false},
		{Visibility{Mode: "SECRET"}, false},
	} {
		v := tc.v
		if err := v.Normalize(); (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc.v, err)
		} else if err == nil && v.Mode == "" {
			t.Errorf("%+v: mode not defaulted", tc.v)
		}
	}
}
