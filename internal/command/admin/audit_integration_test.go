//go:build integration

package admin

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/jackc/pgx/v5"
)

// zeroSigner signs with the all-zero local KEK every integration test uses.
func zeroSigner(t *testing.T) sealing.Signer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	kek, err := sealing.NewLocalKEK(path, true)
	if err != nil {
		t.Fatal(err)
	}
	return sealing.NewLocalSigner(kek)
}

// TestCLIAuditExport: ada exports through the newest checkpoint; the file
// verifies offline, with its own keys or keys given, and not when changed or
// with another key; an export is recorded once; olga, without full access,
// gets no file (.specs/ligo-pruning.md §3.2, §3.3).
func TestCLIAuditExport(t *testing.T) {
	srv, owner := server(t)
	ctx := context.Background()
	s := zeroSigner(t)
	if err := pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		_, err := audit.Append(ctx, tx, audit.Entry{Action: "SYSTEM_EXECUTOR_RECOVERED", Actor: "test"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	res, err := audit.Verify(ctx, owner, s, false)
	if err != nil || !res.Valid {
		t.Fatalf("verify: %+v, %v", res, err)
	}
	at := time.Now()
	if err := owner.QueryRow(ctx, "SELECT greatest(now(), coalesce(max(created_at), now())) FROM audit_checkpoints").Scan(&at); err != nil {
		t.Fatal(err)
	}
	if done, err := audit.Checkpoint(ctx, owner, s, res, at.Add(2*time.Hour)); err != nil || !done {
		t.Fatalf("checkpoint: %v, %v", done, err)
	}

	var out bytes.Buffer
	ada, olga := as(t, srv, "ada", &out), as(t, srv, "olga", &out)
	dir := t.TempDir()
	file := filepath.Join(dir, "audit.jsonl")
	if err := (&AuditExport{Base: olga, Out: filepath.Join(dir, "olga.jsonl")}).Execute(nil); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("olga exports: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "olga.jsonl")); !os.IsNotExist(err) {
		t.Errorf("a refused export left its file: %v", err)
	}
	if err := (&AuditExport{Base: ada, Out: file}).Execute(nil); err != nil || !strings.Contains(out.String(), `"sha256"`) {
		t.Fatalf("ada exports: %v\n%s", err, out.String())
	}
	if err := (&AuditExport{Base: ada, Out: file}).Execute(nil); err == nil {
		t.Error("an export over an existing file")
	}
	if err := (&AuditExport{Base: ada, Out: filepath.Join(dir, "again.jsonl")}).Execute(nil); err == nil || !strings.Contains(err.Error(), "not recorded") {
		t.Errorf("a second export through the same checkpoint: %v", err)
	}

	pubs, _ := s.PublicKeys(ctx)
	good := s.ID() + "/1=" + base64.StdEncoding.EncodeToString(pubs["1"])
	other := s.ID() + "/1=" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	out.Reset()
	if err := (&AuditVerify{Base: ada, File: file}).Execute(nil); err != nil || !strings.Contains(out.String(), `"keysFromFile": true`) {
		t.Errorf("verify the file: %v\n%s", err, out.String())
	}
	out.Reset()
	if err := (&AuditVerify{Base: ada, File: file, PublicKeys: []string{good}}).Execute(nil); err != nil || !strings.Contains(out.String(), `"keysFromFile": false`) {
		t.Errorf("verify with the key given: %v\n%s", err, out.String())
	}
	if err := (&AuditVerify{Base: ada, File: file, PublicKeys: []string{other}}).Execute(nil); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("verify with another key: %v", err)
	}
	for _, bad := range []string{"nope", s.ID() + "=AAAA", s.ID() + "/1=!!"} {
		if err := (&AuditVerify{Base: ada, File: file, PublicKeys: []string{bad}}).Execute(nil); err == nil || !strings.Contains(err.Error(), "--public-key") {
			t.Errorf("--public-key %q: %v", bad, err)
		}
	}
	data, _ := os.ReadFile(file)
	changed := filepath.Join(dir, "changed.jsonl")
	_ = os.WriteFile(changed, bytes.Replace(data, []byte(`"actor":"`), []byte(`"actor":"x`), 1), 0o600)
	if err := (&AuditVerify{Base: ada, File: changed}).Execute(nil); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("verify a changed file: %v", err)
	}
}
