//go:build integration

package bindings

import (
	"context"
	"testing"
)

// inline is the inlineSource of a dc/corp-prod source called name.
func inline(name, suffix string) string {
	return `"inlineSource":{"kind":"Source","metadata":{"name":"` + name + `"},"identity":{"trustDomain":"prod.internal",` +
		`"svidRegex":"^spiffe://prod\\.internal/ns/inline/sa/` + suffix + `$","sampleSpiffeIds":["spiffe://prod.internal/ns/inline/sa/` + suffix + `"]},` +
		`"visibility":{"mode":"PRIVATE"}}`
}

// TestInlineSource: a binding CREATE with inlineSource files the source's
// CREATE first and depends on it: the binding cannot be approved before the
// source is applied (409 dependency-pending), then applies on its own
// approval; when both are complete at creation they apply together
// (§7.2.4 "Inline source").
func TestInlineSource(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	src, name := "dc-inl-src-"+w.suffix, "dc-inl-"+w.suffix
	r, err := s.Create(ctx, dcOp, body(name, src, w.dcShared, "read", inline(src, w.suffix)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "PENDING" || r.DependsOn == nil || status(t, o, *r.DependsOn) != "PENDING" {
		t.Fatalf("filed: %s, depends on %v", r.Status, r.DependsOn)
	}
	if _, err := s.Requests.Approve(ctx, dcApp, r.ID, r.PayloadSHA256, "", "early"); slug(err) != "dependency-pending" {
		t.Fatalf("binding approved before its source: %v", err)
	}
	source, err := s.Requests.Read(ctx, *r.DependsOn)
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, source, dcApp)
	if status(t, o, source.ID) != "APPLIED" || status(t, o, r.ID) != "PENDING" {
		t.Fatalf("source %s, binding %s", status(t, o, source.ID), status(t, o, r.ID))
	}
	approve(t, s, r, dcApp)
	if phase, _, _, _, _ := bindingRow(t, o, name); phase != "PROVISIONING" || status(t, o, r.ID) != "APPLIED" {
		t.Fatalf("binding %s, request %s", phase, status(t, o, r.ID))
	}

	// both complete at creation: the source first, then the binding, at once
	s.Requests.Policy.RequiredScopes = nil
	src2, name2 := "dc-inl2-src-"+w.suffix, "dc-inl2-"+w.suffix
	r, err = s.Create(ctx, dcOp, body(name2, src2, w.dcShared, "read", inline(src2, w.suffix+"b")))
	if err != nil || r.Status != "APPLIED" || status(t, o, *r.DependsOn) != "APPLIED" {
		t.Fatalf("at creation: %v %v", r, err)
	}
	if phase, _, _, _, _ := bindingRow(t, o, name2); phase != "PROVISIONING" {
		t.Errorf("binding at creation: %s", phase)
	}
}

// TestInlineSourceRefusals: the inline source must be the binding's, the
// requester must be able to register it, it is only for a CREATE, and a
// binding refused by its pipeline registers nothing.
func TestInlineSourceRefusals(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	src := "dc-inl-src-" + w.suffix
	for what, tc := range map[string]struct {
		by   string
		body []byte
		slug string
	}{
		"another source":   {"dino", body("dc-x-"+w.suffix, w.dcSrc, w.dcShared, "read", inline(src, w.suffix)), "validation-failed"},
		"not its operator": {"lea", body("dc-x-"+w.suffix, src, w.ledger, "read", inline(src, w.suffix)), "forbidden"},
		"an invalid level": {"dino", body("dc-x-"+w.suffix, src, w.dcShared, "nope", inline(src, w.suffix)), "validation-failed"},
		"a broken source":  {"dino", body("dc-x-"+w.suffix, src, w.dcShared, "read", `"inlineSource":{"metadata":{}}`), "validation-failed"},
	} {
		c := dcOp
		if tc.by == "lea" {
			c = ledgerOp
		}
		if _, err := s.Create(ctx, c, tc.body); slug(err) != tc.slug {
			t.Errorf("%s: %v, want %s", what, err, tc.slug)
		}
	}
	var n int
	if err := o.QueryRow(ctx, "select count(*) from change_requests where resource_name = $1", src).Scan(&n); err != nil || n != 0 {
		t.Errorf("a refused binding filed its source (%d, %v)", n, err)
	}
	if _, err := s.Update(ctx, dcOp, "dc-x-"+w.suffix, body("dc-x-"+w.suffix, src, w.dcShared, "read", `"expectedRevision":1`, inline(src, w.suffix))); slug(err) != "validation-failed" {
		t.Errorf("inline source on an update: %v", err)
	}
}
