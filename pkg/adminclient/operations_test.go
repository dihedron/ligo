package adminclient

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// TestOperations: each method calls the verb and the path of its operation,
// sends what it was given and decodes what the contract says.
func TestOperations(t *testing.T) {
	ctx := context.Background()
	var got struct{ method, path, query, body string }
	reply := func(code int, body string) (*Client, *recorder) {
		rec := &recorder{body: func(*http.Request) (int, string) { return code, body }}
		return newClient(t, rec), rec
	}
	seen := func(rec *recorder) {
		r := rec.last()
		got.method, got.path, got.query = r.Method, r.URL.Path, r.URL.RawQuery
	}
	check := func(t *testing.T, method, path, query string) {
		t.Helper()
		if got.method != method || got.path != path || got.query != query {
			t.Errorf("called %s %s?%s, want %s %s?%s", got.method, got.path, got.query, method, path, query)
		}
	}
	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	t.Run("TestSourceRegex", func(t *testing.T) {
		c, rec := reply(200, `{"valid":true,"jurisdiction":"it/rm","matches":{"spiffe://x/a":true},"overlaps":[{"source":"s1","undecided":true}]}`)
		r, err := c.TestSourceRegex(ctx, SourceTestRequest{TrustDomain: "x", SvidRegex: "^a$"})
		seen(rec)
		check(t, "POST", "/v1/admin/sources/test", "")
		if err != nil || !r.Valid || !r.Matches["spiffe://x/a"] || len(r.Overlaps) != 1 {
			t.Errorf("%+v, %v", r, err)
		}
	})
	t.Run("RevokeTargetBindings", func(t *testing.T) {
		cr := strings.TrimSuffix(strings.TrimPrefix(filedBody, `{"changeRequest":`), `,"resource":null}`)
		c, rec := reply(202, `{"changeRequests":[`+cr+`],"errors":[{"binding":"b2","type":"urn:ligo:problem:internal","detail":"internal error"}]}`)
		src := "s"
		r, err := c.RevokeTargetBindings(ctx, "t", RevokeRequest{Source: &src, Comment: "contain"}, Options{ApprovalReference: "INC-1"})
		seen(rec)
		check(t, "POST", "/v1/admin/targets/t/bindings/revoke", "")
		if err != nil || len(r.ChangeRequests) != 1 || len(r.Errors) != 1 || r.Errors[0].Binding != "b2" {
			t.Errorf("a partial success is an answer, not an error: %+v, %v", r, err)
		}
		if b := rec.last().Header.Get("Content-Type"); b != "application/json" {
			t.Errorf("content type %q", b)
		}
	})
	t.Run("RetryBinding and RotateBinding", func(t *testing.T) {
		c, rec := reply(202, `{"binding":{"apiVersion":"v1alpha1","kind":"Binding","metadata":{"name":"b"}}}`)
		if _, err := c.RetryBinding(ctx, "b"); err != nil {
			t.Fatal(err)
		}
		seen(rec)
		check(t, "POST", "/v1/admin/bindings/b/retry", "")
		if _, err := c.RotateBinding(ctx, "b"); err != nil {
			t.Fatal(err)
		}
		seen(rec)
		check(t, "POST", "/v1/admin/bindings/b/rotate", "")
	})
	t.Run("WithdrawChangeRequest", func(t *testing.T) {
		c, rec := reply(200, filedBody)
		cr, err := c.WithdrawChangeRequest(ctx, someID, "mistake")
		seen(rec)
		check(t, "POST", "/v1/admin/change-requests/"+someID+"/withdraw", "")
		if err != nil || cr.Id.String() != someID {
			t.Errorf("%+v, %v", cr, err)
		}
		if _, err := c.WithdrawChangeRequest(ctx, "not-a-uuid", ""); err == nil {
			t.Error("a malformed ID was sent")
		}
	})
	t.Run("GetCharter", func(t *testing.T) {
		c, rec := reply(200, `{"policy":{"a":1},"sha256":"`+hash+`"}`)
		r, err := c.GetCharter(ctx)
		seen(rec)
		check(t, "GET", "/v1/admin/charter", "")
		if err != nil || r.Sha256 != hash {
			t.Errorf("%+v, %v", r, err)
		}
	})
	t.Run("EvaluateCharter", func(t *testing.T) {
		c, rec := reply(200, `{"resourceType":"BINDING","name":"b","jurisdictions":{},"namePrefix":{"valid":true},"consent":"ALL","interconnect":null,"sides":[]}`)
		r, err := c.EvaluateCharter(ctx, map[string]any{"resourceType": "BINDING", "source": "s", "target": "t", "accessLevel": "read"})
		seen(rec)
		check(t, "POST", "/v1/admin/charter/evaluate", "")
		if err != nil || r.Consent != "ALL" || r.Interconnect != nil {
			t.Errorf("%+v, %v", r, err)
		}
	})
	t.Run("ListBreakGlass", func(t *testing.T) {
		c, rec := reply(200, `{"items":[`+strings.TrimSuffix(strings.TrimPrefix(filedBody, `{"changeRequest":`), `,"resource":null}`)+`]}`)
		var n int
		for _, err := range c.ListBreakGlass(ctx, 10) {
			if err != nil {
				t.Fatal(err)
			}
			n++
		}
		seen(rec)
		check(t, "GET", "/v1/admin/break-glass", "pageSize=10")
		if n != 1 {
			t.Errorf("%d items", n)
		}
	})
	t.Run("maintenance", func(t *testing.T) {
		c, rec := reply(200, `{"maintenanceMode":true,"reason":"r","changedBy":"ada","changedAt":null,"inFlight":1,"propagationQueued":2}`)
		m, err := c.GetMaintenance(ctx)
		seen(rec)
		check(t, "GET", "/v1/admin/maintenance", "")
		if err != nil || !m.MaintenanceMode || m.InFlight != 1 {
			t.Errorf("%+v, %v", m, err)
		}
		if _, err = c.PutMaintenance(ctx, true, "upgrade"); err != nil {
			t.Fatal(err)
		}
		seen(rec)
		check(t, "PUT", "/v1/admin/maintenance", "")
		before := len(rec.reqs)
		if _, err = c.PutMaintenance(ctx, true, ""); err == nil || len(rec.reqs) != before {
			t.Errorf("enabling without a reason: %v, %d requests sent", err, len(rec.reqs)-before)
		}
	})
	t.Run("VerifyAudit", func(t *testing.T) {
		c, rec := reply(200, `{"valid":false,"entries":3,"checkpoints":1,"full":true,"firstBroken":2}`)
		r, err := c.VerifyAudit(ctx, true)
		seen(rec)
		check(t, "GET", "/v1/admin/audit/verify", "full=true")
		if err != nil || r.Valid || r.FirstBroken == nil || *r.FirstBroken != 2 {
			t.Errorf("a broken chain is a result: %+v, %v", r, err)
		}
	})
	t.Run("ExportAudit", func(t *testing.T) {
		c, rec := reply(200, "{\"a\":1}\n{\"b\":2}\n")
		var out bytes.Buffer
		if err := c.ExportAudit(ctx, 9, &out); err != nil {
			t.Fatal(err)
		}
		seen(rec)
		check(t, "GET", "/v1/admin/audit/export", "through=9")
		if out.String() != "{\"a\":1}\n{\"b\":2}\n" {
			t.Errorf("the export: %q", out.String())
		}
		if err := c.ExportAudit(ctx, -1, &out); err == nil {
			t.Error("a negative checkpoint was sent")
		}
	})
	t.Run("RecordAuditExport", func(t *testing.T) {
		c, rec := reply(201, `{"through":9,"sha256":"`+hash+`"}`)
		if err := c.RecordAuditExport(ctx, 9, hash); err != nil {
			t.Fatal(err)
		}
		seen(rec)
		check(t, "POST", "/v1/admin/audit/exports", "")
		c, _ = reply(409, `{"type":"urn:ligo:problem:audit-export-recorded","title":"x","status":409}`)
		if err := c.RecordAuditExport(ctx, 9, hash); !errors.Is(err, ErrState) {
			t.Errorf("a recorded export: %v", err)
		}
	})
	t.Run("executors", func(t *testing.T) {
		c, rec := reply(200, `{"items":[{"executor":"e1","pending":2,"liveSessions":0,"self":false}]}`)
		es, err := c.ListExecutors(ctx)
		seen(rec)
		check(t, "GET", "/v1/admin/executors", "")
		if err != nil || len(es) != 1 || es[0].Pending != 2 {
			t.Errorf("%+v, %v", es, err)
		}
		c, rec = reply(200, `{"executor":"e1","recovered":2,"otherVersions":0}`)
		r, err := c.RecoverExecutor(ctx, "e1")
		seen(rec)
		check(t, "POST", "/v1/admin/executors/e1/recover", "")
		if err != nil || r.Recovered != 2 {
			t.Errorf("%+v, %v", r, err)
		}
	})
}

// TestOperationsRefuseBeforeTheCall: what the server would refuse, or worse
// accept, is not sent.
func TestOperationsRefuseBeforeTheCall(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{}
	c := newClient(t, rec)
	s := "s"
	for name, err := range map[string]error{
		"no target":      second(c.RevokeTargetBindings(ctx, "", RevokeRequest{Source: &s, Comment: "c"}, Options{})),
		"no comment":     second(c.RevokeTargetBindings(ctx, "t", RevokeRequest{Source: &s}, Options{})),
		"no selector":    second(c.RevokeTargetBindings(ctx, "t", RevokeRequest{Comment: "c"}, Options{})),
		"both selectors": second(c.RevokeTargetBindings(ctx, "t", RevokeRequest{Source: &s, SourceJurisdiction: &s, Comment: "c"}, Options{})),
		"no binding":     second(c.RetryBinding(ctx, "")),
		"no executor":    second(c.RecoverExecutor(ctx, "")),
		"no export":      c.RecordAuditExport(ctx, 0, ""),
	} {
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if len(rec.reqs) != 0 {
		t.Errorf("%d requests sent", len(rec.reqs))
	}
}

func second[T any](_ T, err error) error { return err }

// TestOperationsAreNotRetried: the writes among them are made once (T-A6).
func TestOperationsAreNotRetried(t *testing.T) {
	rec := &recorder{body: func(*http.Request) (int, string) {
		return 503, `{"type":"urn:ligo:problem:unavailable","title":"x","status":503}`
	}}
	c := newClient(t, rec)
	if _, err := c.RotateBinding(context.Background(), "b"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if len(rec.reqs) != 1 {
		t.Errorf("%d requests", len(rec.reqs))
	}
}
