//go:build integration

package adminhttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/jackc/pgx/v5"
)

// TestAuditExportAPI: full access exports the chain through a checkpoint as
// JSON Lines that verify offline, and records the export once; a viewer can
// do neither (.specs/ligo-pruning.md §3.2).
func TestAuditExportAPI(t *testing.T) {
	v := setup(t, config.AdminListener{})
	ctx := context.Background()
	admin, viewer := v.client(t, adminID), v.client(t, viewerID)
	s := zeroSigner(t)

	newCheckpoint(t, v, s)

	get := func(c *http.Client, query string) (int, string, []byte) {
		t.Helper()
		resp, err := c.Get(v.srv.URL + "/v1/admin/audit/export" + query)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Content-Type"), body
	}
	if code, _, _ := get(viewer, ""); code != 403 {
		t.Errorf("viewer export: %d", code)
	}
	for _, q := range []string{"?through=x", "?through=-1", "?through=" + strconv.Itoa(1<<60)} {
		if code, _, _ := get(admin, q); code != 422 {
			t.Errorf("export %s: %d", q, code)
		}
	}
	code, ctype, file := get(admin, "")
	if code != 200 || ctype != "application/x-ndjson" {
		t.Fatalf("export: %d %s %s", code, ctype, file)
	}
	fr, err := audit.VerifyFile(bytes.NewReader(file), nil)
	if err != nil || !fr.Valid {
		t.Fatalf("verify the export: %+v, %v", fr, err)
	}

	sum := sha256.Sum256(file)
	record := map[string]any{"through": fr.Through, "sha256": hex.EncodeToString(sum[:])}
	if r := v.do(t, viewer, "POST", "/v1/admin/audit/exports", record); r.code != 403 {
		t.Errorf("viewer record: %d", r.code)
	}
	if r := v.do(t, admin, "POST", "/v1/admin/audit/exports", map[string]any{"through": fr.Through, "sha256": "x"}); r.code != 422 {
		t.Errorf("record with a bad sha256: %d", r.code)
	}
	if r := v.do(t, admin, "POST", "/v1/admin/audit/exports", map[string]any{"through": fr.Through + 1, "sha256": record["sha256"]}); r.code != 422 {
		t.Errorf("record through a non-checkpoint: %d", r.code)
	}
	if r := v.do(t, admin, "POST", "/v1/admin/audit/exports", record); r.code != 201 {
		t.Fatalf("record: %d %v", r.code, r.body)
	}
	if r := v.do(t, admin, "POST", "/v1/admin/audit/exports", record); r.code != 409 {
		t.Errorf("record again: %d", r.code)
	}
	var actor string
	if err := v.owner.QueryRow(ctx, "SELECT actor FROM audit_log WHERE action = 'SYSTEM_AUDIT_EXPORTED' ORDER BY id DESC LIMIT 1").Scan(&actor); err != nil || actor != adminID {
		t.Errorf("SYSTEM_AUDIT_EXPORTED by %q (%v)", actor, err)
	}
}

// newCheckpoint commits a new entry and a checkpoint of it, as the audit
// loop would, dated after the newest checkpoint (earlier runs may have dated
// theirs ahead), and returns its entry.
func newCheckpoint(t *testing.T, v *env, s sealing.Signer) int64 {
	t.Helper()
	ctx := context.Background()
	if err := pgx.BeginFunc(ctx, v.owner, func(tx pgx.Tx) error {
		_, err := audit.Append(ctx, tx, audit.Entry{Action: "SYSTEM_EXECUTOR_RECOVERED", Actor: "test"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(ctx, v.owner, s, false)
	if err != nil || !res.Valid {
		t.Fatalf("verify: %+v, %v", res, err)
	}
	at := time.Now()
	if err := v.owner.QueryRow(ctx, "SELECT greatest(now(), coalesce(max(created_at), now())) FROM audit_checkpoints").Scan(&at); err != nil {
		t.Fatal(err)
	}
	if done, err := audit.Checkpoint(ctx, v.owner, s, res, at.Add(2*time.Hour)); err != nil || !done {
		t.Fatalf("checkpoint: %v, %v", done, err)
	}
	var id int64
	if err := v.owner.QueryRow(ctx, "SELECT max(audit_id) FROM audit_checkpoints").Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
