package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dihedron/ligo/internal/jcs"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
)

// An export (ligo audit export, .specs/ligo-pruning.md §3.2) is JSON Lines:
// a header, the signed checkpoints that cover it (and the newest one below
// it, which anchors a pruned head), then every entry from the oldest left
// through a checkpoint. Each entry carries its canonical row, so it can be
// re-hashed without ligo.
type line struct {
	Kind string `json:"kind"` // header, checkpoint, entry

	// header
	From       int64                        `json:"from,omitempty"`
	Through    int64                        `json:"through,omitempty"`
	ExportedAt string                       `json:"exportedAt,omitempty"`
	PublicKeys map[string]map[string]string `json:"publicKeys,omitempty"` // key ID, version, base64

	// checkpoint
	AuditID   int64  `json:"auditId,omitempty"`
	CreatedAt string `json:"createdAt,omitempty"`
	KeyID     string `json:"keyId,omitempty"`
	Signature string `json:"signature,omitempty"`

	// entry, and the header's prevHash
	ID        int64           `json:"id,omitempty"`
	PrevHash  string          `json:"prevHash,omitempty"`
	EntryHash string          `json:"entryHash,omitempty"`
	Row       json.RawMessage `json:"row,omitempty"`
}

var (
	// ErrNotCheckpoint: an export or a prune must end on a signed checkpoint.
	ErrNotCheckpoint = errors.New("audit: not a signed checkpoint of an entry still in the log")
	// ErrBadExport: a record without a SHA-256 of 64 hex characters.
	ErrBadExport = errors.New("audit: sha256 must be 64 hex characters")
	// ErrExported: an export through this entry or a later one is recorded.
	ErrExported = errors.New("audit: an export through this entry or a later one is already recorded")
)

// Export writes the chain from its oldest entry through the checkpoint
// through, or the newest checkpoint when through is 0, and returns the
// entry it ended on. Nothing is written when it fails before the first line.
// Entries up to a checkpoint never change, so no snapshot is needed.
func Export(ctx context.Context, q store.Querier, s sealing.Signer, through int64, w io.Writer) (int64, error) {
	var end *int64
	err := q.QueryRow(ctx, `SELECT max(c.audit_id) FROM audit_checkpoints c JOIN audit_log a ON a.id = c.audit_id
		WHERE $1::bigint = 0 OR c.audit_id = $1::bigint`, through).Scan(&end)
	if err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}
	if end == nil {
		return 0, ErrNotCheckpoint
	}
	head := line{Kind: "header", Through: *end, ExportedAt: time.Now().UTC().Format(timeLayout), PublicKeys: map[string]map[string]string{}}
	if err := q.QueryRow(ctx, "SELECT id, prev_hash FROM audit_log ORDER BY id LIMIT 1").Scan(&head.From, &head.PrevHash); err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}
	pubs, err := s.PublicKeys(ctx)
	if err != nil {
		return 0, fmt.Errorf("audit export: %w", err)
	}
	head.PublicKeys[s.ID()] = map[string]string{}
	for v, pub := range pubs {
		head.PublicKeys[s.ID()][v] = base64.StdEncoding.EncodeToString(pub)
	}
	cps, err := q.Query(ctx, `SELECT audit_id, entry_hash, created_at, key_id, signature FROM audit_checkpoints
		WHERE audit_id <= $2 AND audit_id >= coalesce((SELECT max(audit_id) FROM audit_checkpoints WHERE audit_id < $1), $1)
		ORDER BY audit_id`, head.From, head.Through)
	if err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}
	var lines []line
	for cps.Next() {
		l := line{Kind: "checkpoint"}
		var at time.Time
		if err := cps.Scan(&l.AuditID, &l.EntryHash, &at, &l.KeyID, &l.Signature); err != nil {
			cps.Close()
			return 0, fmt.Errorf("audit: %w", err)
		}
		l.CreatedAt = at.UTC().Truncate(time.Microsecond).Format(timeLayout)
		lines = append(lines, l)
	}
	cps.Close()
	if err := cps.Err(); err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}

	enc := json.NewEncoder(w)
	for _, l := range append([]line{head}, lines...) {
		if err := enc.Encode(l); err != nil {
			return 0, err
		}
	}
	for after := head.From - 1; after < head.Through; {
		batch, err := load(ctx, q, after, batchSize)
		if err != nil {
			return 0, err
		}
		if len(batch) == 0 {
			return 0, fmt.Errorf("audit export: entry %d is gone", head.Through)
		}
		for _, e := range batch {
			if e.id > head.Through { // done; a through pruned meanwhile leaves a file that does not verify
				after = head.Through
				break
			}
			row, err := jcs.Canonicalize(e.row())
			if err != nil {
				return 0, fmt.Errorf("audit: %w", err)
			}
			if err := enc.Encode(line{Kind: "entry", ID: e.id, PrevHash: e.prev, EntryHash: e.entryHash, Row: row}); err != nil {
				return 0, err
			}
			after = e.id
		}
	}
	return head.Through, nil
}

// FileResult is the verification of an export, offline.
type FileResult struct {
	Valid        bool   `json:"valid"`
	From         int64  `json:"from"`
	Through      int64  `json:"through"`
	Entries      int    `json:"entries"`
	Checkpoints  int    `json:"checkpoints"`
	FirstBroken  int64  `json:"firstBroken,omitempty"`
	Reason       string `json:"reason,omitempty"`
	KeysFromFile bool   `json:"keysFromFile"` // the public keys came from the file under test
}

// VerifyFile checks an export without the database or the signer: every
// checkpoint's signature, under keys or else the file's own; every entry
// re-hashed from the header's prevHash; every checkpoint matching its entry;
// the newest checkpoint below the first entry matching that prevHash; and
// the last entry being the header's through, a checkpoint. A malformed file
// is an error; a file that does not verify is a Result with Valid false.
func VerifyFile(r io.Reader, keys sealing.KeySet) (FileResult, error) {
	dec := json.NewDecoder(r)
	var head line
	if err := dec.Decode(&head); err != nil || head.Kind != "header" {
		return FileResult{}, fmt.Errorf("audit file: no header (%v)", err)
	}
	res := FileResult{From: head.From, Through: head.Through}
	if keys == nil {
		res.KeysFromFile, keys = true, sealing.KeySet{}
		for id, versions := range head.PublicKeys {
			keys[id] = map[string]ed25519.PublicKey{}
			for v, b64 := range versions {
				pub, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					return res, fmt.Errorf("audit file: public key %s v%s: %w", id, v, err)
				}
				keys[id][v] = pub
			}
		}
	}
	broken := func(id int64, reason string) (FileResult, error) {
		res.FirstBroken, res.Reason = id, reason
		return res, nil
	}
	checkpoints := map[int64]string{} // entry, its signed hash
	prev, last := head.PrevHash, int64(0)
	for {
		var l line
		err := dec.Decode(&l)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, fmt.Errorf("audit file: %w", err)
		}
		switch l.Kind {
		case "checkpoint":
			if last != 0 {
				return res, errors.New("audit file: a checkpoint after the entries")
			}
			at, err := time.Parse(timeLayout, l.CreatedAt)
			if err != nil {
				return res, fmt.Errorf("audit file: checkpoint %d: %w", l.AuditID, err)
			}
			msg, err := checkpointMessage(l.AuditID, l.EntryHash, at)
			if err != nil {
				return res, err
			}
			if keys.Verify(l.KeyID, msg, l.Signature) != nil {
				return broken(l.AuditID, "checkpoint signature does not verify")
			}
			if l.AuditID < head.From && l.EntryHash != head.PrevHash {
				return broken(l.AuditID, "the first entry does not chain onto the checkpoint below it")
			}
			checkpoints[l.AuditID] = l.EntryHash
			res.Checkpoints++
		case "entry":
			if l.ID <= last || (last == 0 && l.ID != head.From) {
				return broken(l.ID, "entries out of order, or not starting at the header's from")
			}
			canonical, err := jcs.Transform(l.Row)
			if err != nil {
				return res, fmt.Errorf("audit file: entry %d: %w", l.ID, err)
			}
			sum := sha256.Sum256(append([]byte(prev), canonical...))
			hash := hex.EncodeToString(sum[:])
			if l.PrevHash != prev || l.EntryHash != hash {
				return broken(l.ID, "entry hash does not match")
			}
			if signed, ok := checkpoints[l.ID]; ok && signed != hash {
				return broken(l.ID, "entry does not match its signed checkpoint")
			}
			prev, last = hash, l.ID
			res.Entries++
		default:
			return res, fmt.Errorf("audit file: unknown line kind %q", l.Kind)
		}
	}
	if _, ok := checkpoints[last]; !ok || last != head.Through {
		return broken(last, "the file does not end on the header's through, a signed checkpoint")
	}
	res.Valid = true
	return res, nil
}

// RecordExport records, in tx, that an export through a checkpoint was taken
// and verified, with the SHA-256 of its file, and audits it. Pruning never
// passes the newest record.
func RecordExport(ctx context.Context, tx pgx.Tx, through int64, sha string, actor string, groups []string) error {
	if b, err := hex.DecodeString(sha); err != nil || len(b) != sha256.Size {
		return ErrBadExport
	}
	var checkpoint, newer bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM audit_checkpoints WHERE audit_id = $1),
		EXISTS (SELECT 1 FROM audit_exports WHERE through >= $1)`, through).Scan(&checkpoint, &newer); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	switch {
	case !checkpoint:
		return ErrNotCheckpoint
	case newer:
		return ErrExported
	}
	if _, err := tx.Exec(ctx, "INSERT INTO audit_exports (through, sha256, actor) VALUES ($1, $2, $3)", through, sha, actor); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	snapshot, _ := json.Marshal(map[string]any{"through": through, "sha256": sha})
	_, err := Append(ctx, tx, Entry{Action: "SYSTEM_AUDIT_EXPORTED", Actor: actor, ActorGroups: groups, Snapshot: snapshot})
	return err
}
