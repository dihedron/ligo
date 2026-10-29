// Package store holds ligo's access to PostgreSQL: the connection pools of
// §4.1, the fenced binding status update of §6.1 (ADR-08) and the
// compare-and-set statements that decide change requests (§4.3).
package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
	"uuid"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Statement timeouts of the pools (§4.1).
const (
	statementTimeoutApp    = 5 * time.Second
	statementTimeoutReader = 500 * time.Millisecond
)

var (
	// ErrInsecureConnection refuses a DSN without sslmode=verify-full (§4.1).
	ErrInsecureConnection = errors.New("database connections must use sslmode=verify-full")
	// ErrFenced means that the workflow was superseded: it must return at
	// once, without further side effects (ADR-08).
	ErrFenced = errors.New("binding update fenced: the workflow was superseded")
	// ErrNotPending is 409 change-request-not-pending.
	ErrNotPending = errors.New("change-request-not-pending")
	// ErrPayloadMismatch is 409 payload-mismatch: the approval named another
	// payload than the request's.
	ErrPayloadMismatch = errors.New("payload-mismatch")
	// ErrSideTaken means that another decider took a side first; the caller
	// rolls back and returns 409 change-request-not-pending.
	ErrSideTaken = errors.New("side already decided")
)

// Pools are the application's connection pools (§4.1); DBOS has its own.
type Pools struct {
	App    *pgxpool.Pool
	Reader *pgxpool.Pool
}

// Open connects the app and reader pools. allowInsecure accepts connections
// without verify-full, for the tests' containers only.
func Open(ctx context.Context, appDSN, readerDSN string, allowInsecure bool) (*Pools, error) {
	var p Pools
	for _, c := range []struct {
		pool    **pgxpool.Pool
		dsn     string
		timeout time.Duration
	}{{&p.App, appDSN, statementTimeoutApp}, {&p.Reader, readerDSN, statementTimeoutReader}} {
		cfg, err := poolConfig(c.dsn, c.timeout, allowInsecure)
		if err != nil {
			p.Close()
			return nil, err
		}
		if *c.pool, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
			p.Close()
			return nil, fmt.Errorf("store: %w", err)
		}
		if err := (*c.pool).Ping(ctx); err != nil {
			p.Close()
			return nil, fmt.Errorf("store: %w", err)
		}
	}
	return &p, nil
}

// Close closes the pools that are open.
func (p *Pools) Close() {
	for _, pool := range []*pgxpool.Pool{p.App, p.Reader} {
		if pool != nil {
			pool.Close()
		}
	}
}

// poolConfig parses a DSN, checks that it verifies the server (verify-full:
// TLS, certificate and host name, no plaintext fallback) and sets the
// statement timeout.
func poolConfig(dsn string, timeout time.Duration, allowInsecure bool) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	tls := cfg.ConnConfig.TLSConfig
	if !allowInsecure && (tls == nil || tls.InsecureSkipVerify || len(cfg.ConnConfig.Fallbacks) > 0) {
		return nil, ErrInsecureConnection
	}
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(timeout.Milliseconds(), 10)
	return cfg, nil
}

// Querier is a pool or a transaction.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// MarkStep records a workflow's progress on its binding, fenced by the
// workflow ID (§6.1 rule 7): ErrFenced when the binding has another
// workflow or is no longer in flight.
func MarkStep(ctx context.Context, q Querier, bindingID uuid.UUID, workflowID, step, message string) error {
	tag, err := q.Exec(ctx, `UPDATE bindings
		SET current_step = $3, status_message = $4, last_transition_at = now(), updated_at = now()
		WHERE id = $1 AND workflow_id = $2 AND phase IN ('PROVISIONING','DELETING')`,
		bindingID, workflowID, step, message)
	if err != nil {
		return fmt.Errorf("store: mark step: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrFenced
	}
	return nil
}

// Enqueue queues for propagation the bindings of a source, or of a target
// (at levels, or at every level if levels is nil), that are not being
// deleted; a binding already queued keeps the lower priority (§6.2.1 step
// 5). It returns how many bindings it queued.
func Enqueue(ctx context.Context, q Querier, cause string, resourceID, crID uuid.UUID, priority int, levels []string) (int64, error) {
	column := map[string]string{"SOURCE": "source_id", "TARGET": "target_id"}[cause]
	if column == "" {
		return 0, fmt.Errorf("store: enqueue: cause %q", cause)
	}
	tag, err := q.Exec(ctx, `INSERT INTO binding_propagation_queue (binding_id, cause_change_request_id, cause, priority)
		SELECT id, $2, $3, $4 FROM bindings
		WHERE `+column+` = $1 AND phase NOT IN ('DELETING', 'DELETE_FAILED') AND ($5::text[] IS NULL OR access_level = ANY($5))
		ON CONFLICT (binding_id) DO UPDATE SET cause_change_request_id = EXCLUDED.cause_change_request_id,
			cause = EXCLUDED.cause, priority = least(binding_propagation_queue.priority, EXCLUDED.priority),
			enqueued_at = now(), attempts = 0`, resourceID, crID, cause, priority, levels)
	if err != nil {
		return 0, fmt.Errorf("store: enqueue: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DecideSides records decision ("APPROVED" or "DECLINED") on the sides of a
// pending change request (§4.3, side decision). It serializes the deciders
// of the request on its row, so that the caller, reading the sides
// afterwards in the same transaction, sees every earlier decision.
// payloadSHA256 is checked for an approval; it is ignored for a decline.
// It returns the request's decision_seq.
func DecideSides(ctx context.Context, tx pgx.Tx, crID uuid.UUID, payloadSHA256 string, sides []string, decision, actor, comment string) (int, error) {
	var seq int
	var hash any
	if decision == "APPROVED" {
		hash = payloadSHA256
	}
	err := tx.QueryRow(ctx, `UPDATE change_requests
		SET decision_seq = decision_seq + 1
		WHERE id = $1 AND status = 'PENDING' AND ($2::char(64) IS NULL OR payload_sha256 = $2)
		RETURNING decision_seq`, crID, hash).Scan(&seq)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, notPendingOrMismatch(ctx, tx, crID)
	}
	if err != nil {
		return 0, fmt.Errorf("store: decide sides: %w", err)
	}
	var comm any
	if comment != "" {
		comm = comment
	}
	tag, err := tx.Exec(ctx, `UPDATE change_request_sides
		SET decision = $3, decided_by = $4, decided_at = now(), decision_comment = $5
		WHERE change_request_id = $1 AND side = ANY($2) AND decision IS NULL AND basis = 'HUMAN'`,
		crID, sides, decision, actor, comm)
	if err != nil {
		return 0, fmt.Errorf("store: decide sides: %w", err)
	}
	if int(tag.RowsAffected()) < len(sides) {
		return 0, ErrSideTaken
	}
	return seq, nil
}

// notPendingOrMismatch tells a decided request from a stale payload hash.
func notPendingOrMismatch(ctx context.Context, tx pgx.Tx, crID uuid.UUID) error {
	var status string
	err := tx.QueryRow(ctx, "SELECT status FROM change_requests WHERE id = $1", crID).Scan(&status)
	if err == nil && status == "PENDING" {
		return ErrPayloadMismatch
	}
	return ErrNotPending
}

// CloseRequest decides a pending change request (§4.3, request decision):
// status is APPLIED, REJECTED, WITHDRAWN, EXPIRED or FAILED_TO_APPLY.
// ErrNotPending means it was decided concurrently: the caller rolls back.
func CloseRequest(ctx context.Context, tx pgx.Tx, crID uuid.UUID, status, actor, comment, applyError string) error {
	optional := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	tag, err := tx.Exec(ctx, `UPDATE change_requests
		SET status = $2, decided_by = $3, decided_at = now(), decision_comment = $4, apply_error = $5
		WHERE id = $1 AND status = 'PENDING'`,
		crID, status, actor, optional(comment), optional(applyError))
	if err != nil {
		return fmt.Errorf("store: close request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotPending
	}
	return nil
}
