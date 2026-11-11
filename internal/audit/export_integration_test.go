//go:build integration

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/jcs"
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

// TestExportChangeRequests: an export carries each request its entries
// name, with its sides and payload; offline verification checks the payload
// against payloadSha256 and that an entry names the request
// (.specs/ligo-cr-pruning.md §4.5).
func TestExportChangeRequests(t *testing.T) {
	app, _ := setup(t)
	ctx := context.Background()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	s := signer(t)

	cr := uuid.NewV7()
	payload := []byte(`{"metadata":{"name":"q"},"identity":{"trustDomain":"prod.internal","svidRegex":"^x$"},"visibility":"PUBLIC"}`)
	canonical, _ := jcs.Transform(payload)
	sum := sha256.Sum256(canonical)
	if _, err := tx.Exec(ctx, `insert into change_requests (id, resource_type, resource_name, operation, kind, consent, owner_jurisdiction,
		policy_sha256, distinct_approvers_required, payload, payload_sha256, requested_by, expires_at, status, decided_by, decided_at)
		values ($1, 'SOURCE', 'q-export', 'CREATE', 'STANDARD', 'ALL', 'dc/corp-prod/ledger', repeat('a', 64), true, $2, $3, 'carla',
		now() + interval '1 day', 'WITHDRAWN', 'carla', now())`, cr, payload, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `insert into change_request_sides (change_request_id, side, jurisdiction, approval_required, basis, requested_by, cr_kind)
		values ($1, 'OWNER', 'dc/corp-prod/ledger', true, 'HUMAN', 'carla', 'STANDARD')`, cr); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(ctx, tx, Entry{ResourceType: "SOURCE", ResourceName: "q-export", ChangeRequestID: &cr, Action: "CR_WITHDRAWN", Actor: "carla"}); err != nil {
		t.Fatal(err)
	}
	through := anchorHead(t, ctx, tx, 1, 25*time.Hour)

	var buf bytes.Buffer
	if _, err := Export(ctx, tx, s, through, &buf); err != nil {
		t.Fatal(err)
	}
	file := buf.Bytes()
	if !bytes.Contains(file, []byte(`"kind":"change_request","changeRequestId":"`+cr.String()+`"`)) {
		t.Fatalf("the request is not in the export")
	}
	res, err := VerifyFile(bytes.NewReader(file), nil)
	if err != nil || !res.Valid || res.ChangeRequests < 1 {
		t.Fatalf("verify: %+v, %v", res, err)
	}
	for _, c := range []struct {
		name   string
		file   []byte
		reason string
	}{
		{"a payload changed", edit(t, file, `"kind":"change_request","changeRequestId":"`+cr.String(), `"visibility":"PUBLIC"`, `"visibility":"PRIVATE"`), "payload"},
		{"a request no entry names", edit(t, file, `"kind":"change_request","changeRequestId":"`+cr.String(), `"changeRequestId":"`+cr.String(), `"changeRequestId":"`+uuid.NewV7().String()), "names"},
	} {
		if res, err := VerifyFile(bytes.NewReader(c.file), nil); err != nil || res.Valid || !strings.Contains(res.Reason, c.reason) {
			t.Errorf("%s: %+v, %v, want %q", c.name, res, err, c.reason)
		}
	}
}
