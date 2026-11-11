package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dihedron/ligo/internal/sealing"
	"github.com/jackc/pgx/v5"
)

// Pruned is what a prune deleted: the entries through Through, a signed
// checkpoint, relying on the export through Export. Deleted is 0 when
// nothing was due.
type Pruned struct {
	Through, Export, Deleted int64
}

// Prune deletes the head of the chain through the boundary of
// .specs/ligo-pruning.md §3.4: the newest checkpoint that verifies, is at or
// below the newest recorded export, was signed over 24 hours ago, and whose
// entry is older than now minus retention. It audits SYSTEM_AUDIT_PRUNED in
// the same transaction. The checkpoint stays, as the anchor of what is left.
func Prune(ctx context.Context, db interface {
	Begin(context.Context) (pgx.Tx, error)
}, s sealing.Signer, retention time.Duration, now time.Time) (Pruned, error) {
	var p Pruned
	err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		var (
			entryHash, keyID, sig string
			at                    time.Time
		)
		err := tx.QueryRow(ctx, `SELECT c.audit_id, c.entry_hash, c.created_at, c.key_id, c.signature, e.through
			FROM audit_checkpoints c JOIN audit_log a ON a.id = c.audit_id
			CROSS JOIN (SELECT max(through) AS through FROM audit_exports) e
			WHERE c.audit_id <= e.through AND a.occurred_at < $1 AND c.created_at < now() - interval '24 hours'
			ORDER BY c.audit_id DESC LIMIT 1`, now.Add(-retention)).Scan(&p.Through, &entryHash, &at, &keyID, &sig, &p.Export)
		if errors.Is(err, pgx.ErrNoRows) {
			p = Pruned{}
			return nil
		}
		if err != nil {
			return fmt.Errorf("audit prune: %w", err)
		}
		msg, err := checkpointMessage(p.Through, entryHash, at)
		if err != nil {
			return fmt.Errorf("audit prune: %w", err)
		}
		if err := s.Verify(ctx, keyID, msg, sig); err != nil {
			return fmt.Errorf("audit prune: checkpoint %d: %w", p.Through, err)
		}
		if err := tx.QueryRow(ctx, "SELECT audit_prune($1)", p.Through).Scan(&p.Deleted); err != nil {
			return fmt.Errorf("audit prune: %w", err)
		}
		snapshot, _ := json.Marshal(map[string]any{"through": p.Through, "deleted": p.Deleted, "export": p.Export, "retention": retention.String()})
		_, err = Append(ctx, tx, Entry{Action: "SYSTEM_AUDIT_PRUNED", Actor: "system:audit", Snapshot: snapshot})
		return err
	})
	if err != nil {
		return Pruned{}, err
	}
	return p, nil
}
