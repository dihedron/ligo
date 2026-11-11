//go:build integration

package audit

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/sealing"
)

// edit replaces, in the n-th line of an export that contains match, old
// with new.
func edit(t *testing.T, file []byte, match, old, new string) []byte {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(string(file), "\n"), "\n")
	for i, l := range lines {
		if strings.Contains(l, match) {
			if !strings.Contains(l, old) {
				t.Fatalf("line %q has no %q", l, old)
			}
			lines[i] = strings.Replace(l, old, new, 1)
			return []byte(strings.Join(lines, "\n") + "\n")
		}
	}
	t.Fatalf("no line with %q", match)
	return nil
}

// TestExportRoundTrip: an export verifies offline with its own keys or with
// keys given; any change to an entry, a checkpoint or the end is caught; an
// export is recorded once per checkpoint, forward only; after a prune, the
// export starts at the oldest entry left, anchored on the checkpoint below.
func TestExportRoundTrip(t *testing.T) {
	app, _ := setup(t)
	ctx := context.Background()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	s := signer(t)
	first := anchorHead(t, ctx, tx, 5, 25*time.Hour)
	second := anchorHead(t, ctx, tx, 3, 25*time.Hour)

	var buf bytes.Buffer
	if _, err := Export(ctx, tx, s, first-1, &buf); !errors.Is(err, ErrNotCheckpoint) || buf.Len() != 0 {
		t.Errorf("export through a non-checkpoint: %v, %d bytes written", err, buf.Len())
	}
	end, err := Export(ctx, tx, s, first, &buf)
	if err != nil || end != first {
		t.Fatalf("export through %d: %d, %v", first, end, err)
	}
	file := bytes.Clone(buf.Bytes())
	res, err := VerifyFile(bytes.NewReader(file), nil)
	if err != nil || !res.Valid || !res.KeysFromFile || res.Through != first || res.Entries < 5 || res.Checkpoints < 1 {
		t.Fatalf("verify the export: %+v, %v", res, err)
	}

	pubs, _ := s.PublicKeys(ctx)
	if res, err := VerifyFile(bytes.NewReader(file), sealing.KeySet{s.ID(): pubs}); err != nil || !res.Valid || res.KeysFromFile {
		t.Errorf("verify with keys given: %+v, %v", res, err)
	}
	other := sealing.NewLocalSigner(mustKEK(t, bytes.Repeat([]byte{1}, 32)))
	otherPubs, _ := other.PublicKeys(ctx)
	if res, _ := VerifyFile(bytes.NewReader(file), sealing.KeySet{s.ID(): otherPubs}); res.Valid || !strings.Contains(res.Reason, "signature") {
		t.Errorf("verify with another key: %+v", res)
	}

	for _, c := range []struct {
		name   string
		file   []byte
		reason string
	}{
		{"an entry changed", edit(t, file, `"kind":"entry"`, `"actor":"`, `"actor":"x`), "entry hash"},
		{"a checkpoint forged", edit(t, file, `"kind":"checkpoint"`, `"signature":"local:v1:`, `"signature":"local:v1:AAAA`), "signature"},
		{"the end cut", file[:bytes.LastIndexByte(file[:len(file)-1], '\n')+1], "does not end"},
	} {
		if res, err := VerifyFile(bytes.NewReader(c.file), nil); err != nil || res.Valid || !strings.Contains(res.Reason, c.reason) {
			t.Errorf("%s: %+v, %v, want %q", c.name, res, err, c.reason)
		}
	}
	if _, err := VerifyFile(strings.NewReader(`{"kind":"entry"}`), nil); err == nil {
		t.Error("a file without its header")
	}

	sha := strings.Repeat("d", 64)
	if err := RecordExport(ctx, tx, second, "nope", "ana", nil); err == nil {
		t.Error("record with a bad sha256")
	}
	if err := RecordExport(ctx, tx, second-1, sha, "ana", nil); !errors.Is(err, ErrNotCheckpoint) {
		t.Errorf("record through a non-checkpoint: %v", err)
	}
	if err := RecordExport(ctx, tx, second, sha, "ana", []string{"cn=admins"}); err != nil {
		t.Fatal(err)
	}
	var action, actor string
	if err := tx.QueryRow(ctx, "SELECT action, actor FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&action, &actor); err != nil ||
		action != "SYSTEM_AUDIT_EXPORTED" || actor != "ana" {
		t.Errorf("audited %q by %q (%v)", action, actor, err)
	}
	for _, through := range []int64{first, second} {
		if err := RecordExport(ctx, tx, through, sha, "ana", nil); !errors.Is(err, ErrExported) {
			t.Errorf("record through %d again: %v, want ErrExported", through, err)
		}
	}

	// prune through first: the export starts after it, anchored on it
	if _, err := tx.Exec(ctx, "SELECT audit_prune($1)", first); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if end, err := Export(ctx, tx, s, 0, &buf); err != nil || end != second {
		t.Fatalf("export after the prune: %d, %v", end, err)
	}
	res, err = VerifyFile(bytes.NewReader(buf.Bytes()), nil)
	if err != nil || !res.Valid || res.From != first+1 || res.Checkpoints < 2 {
		t.Errorf("verify after the prune: %+v, %v", res, err)
	}
	bad := edit(t, buf.Bytes(), `"kind":"header"`, `"prevHash":"`, `"prevHash":"0`)
	if res, _ := VerifyFile(bytes.NewReader(bad), nil); res.Valid {
		t.Error("a header whose prevHash is not the anchor's")
	}
}
