//go:build integration

package bindings

import (
	"context"
	"strings"
	"testing"
)

// BM-2: a violation of the limits is refused at filing, naming the field.
func TestTextRefused(t *testing.T) {
	s, _, w, _ := setup(t)
	ctx := context.Background()
	for name, extra := range map[string]string{
		"description": `"description":"` + strings.Repeat("x", 4097) + `"`,
		"annotations": `"annotations":{"bad key":"v"}`,
	} {
		_, err := s.Create(ctx, dcOp, body("tx-"+name[:3]+"-"+w.suffix, w.dcSrc, w.dcShared, "read", extra))
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// BM-4: a text-only change is a change request needing approval; the old text
// stays until it is applied, then the new text and a new revision.
func TestTextChangeNeedsApproval(t *testing.T) {
	s, o, w, _ := setup(t)
	ctx := context.Background()
	name := "tx-" + w.suffix
	r, err := s.Create(ctx, dcOp, body(name, w.dcSrc, w.dcShared, "read", `"description":"one","annotations":{"a":"1"}`))
	if err != nil {
		t.Fatal(err)
	}
	approve(t, s, r, dcApp)
	if _, err := o.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", name); err != nil {
		t.Fatal(err)
	}
	r, err = s.Update(ctx, dcOp, name, body(name, w.dcSrc, w.dcShared, "read", `"expectedRevision":1`, `"description":"two","annotations":{"a":"2","b":"3"}`))
	if err != nil || r.Status != "PENDING" {
		t.Fatalf("update: %+v, %v", r, err)
	}
	read := func() (d, a string, rev int64) {
		t.Helper()
		if err := o.QueryRow(ctx, "select description, annotations::text, revision from bindings where name = $1", name).Scan(&d, &a, &rev); err != nil {
			t.Fatal(err)
		}
		return
	}
	if d, a, rev := read(); d != "one" || a != `{"a": "1"}` || rev != 1 {
		t.Errorf("before approval: %q %s %d", d, a, rev)
	}
	approve(t, s, r, dcApp)
	if d, a, rev := read(); d != "two" || a != `{"a": "2", "b": "3"}` || rev != 2 {
		t.Errorf("after approval: %q %s %d", d, a, rev)
	}
}

// BM-7: migration 002 keeps what purpose and labels held, under the new names.
func TestColumnsRenamed(t *testing.T) {
	_, o, _, _ := setup(t)
	var n int
	if err := o.QueryRow(context.Background(), `select count(*) from information_schema.columns where table_name = 'bindings'
		and column_name in ('purpose','labels')`).Scan(&n); err != nil || n != 0 {
		t.Errorf("old columns left: %d (%v)", n, err)
	}
	if err := o.QueryRow(context.Background(), `select count(*) from information_schema.columns where table_name = 'v_active_bindings'
		and column_name in ('description','annotations')`).Scan(&n); err != nil || n != 2 {
		t.Errorf("the view lacks the new columns: %d (%v)", n, err)
	}
}
