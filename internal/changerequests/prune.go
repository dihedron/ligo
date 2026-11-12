package changerequests

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/jackc/pgx/v5"
)

// Prune deletes, through change_requests_prune, the closed requests decided
// more than retention ago that no audit entry names and nothing that stays
// refers to (.specs/ligo-cr-pruning.md §4.3), and audits SYSTEM_CR_PRUNED in
// the same transaction when it deleted any. The cut-off is computed on the
// database's clock, which also checks it is at least 24 hours ago: with the
// replica's clock, retention 24h would fail on any skew.
func Prune(ctx context.Context, db interface {
	Begin(context.Context) (pgx.Tx, error)
}, retention time.Duration) (int64, error) {
	var deleted int64
	err := pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		var olderThan time.Time
		if err := tx.QueryRow(ctx, "SELECT now() - $1::interval", retention.String()).Scan(&olderThan); err != nil {
			return fmt.Errorf("change requests prune: %w", err)
		}
		if err := tx.QueryRow(ctx, "SELECT change_requests_prune($1)", olderThan).Scan(&deleted); err != nil {
			return fmt.Errorf("change requests prune: %w", err)
		}
		if deleted == 0 {
			return nil
		}
		snapshot, _ := json.Marshal(map[string]any{"deleted": deleted, "olderThan": olderThan.UTC().Format(time.RFC3339), "retention": retention.String()})
		_, err := audit.Append(ctx, tx, audit.Entry{Action: "SYSTEM_CR_PRUNED", Actor: "system:audit", Snapshot: snapshot})
		return err
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}
