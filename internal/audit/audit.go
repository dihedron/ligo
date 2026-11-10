// Package audit writes and verifies the hash-chained audit log (§4.3,
// T-13, INV-11).
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/jcs"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
)

// Genesis is the prev_hash of the first entry.
var Genesis = strings.Repeat("0", 64)

// timeLayout is RFC 3339 with microseconds, in UTC: the database keeps
// microseconds, so the hash can be recomputed from what it stores.
const timeLayout = "2006-01-02T15:04:05.000000Z07:00"

// Entry is an audit record: every column of audit_log except id, prev_hash
// and entry_hash.
type Entry struct {
	ResourceType    string // SOURCE, TARGET, BINDING; "" for SESSION_*, CONFIG_*, SYSTEM_*
	ResourceID      *uuid.UUID
	ResourceName    string
	ChangeRequestID *uuid.UUID
	Action          string
	Actor           string
	ActorGroups     []string
	Approver        string
	Revision        *int64
	Attempt         *int64
	WorkflowID      string
	RequestID       string
	// Snapshot is NON-SECRET JSON (INV-03), or nil.
	Snapshot   json.RawMessage
	OccurredAt time.Time // set by Append when zero
}

// row is the canonical form of an entry, hashed with JCS.
func (e *Entry) row() map[string]any {
	opt := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	optUUID := func(u *uuid.UUID) any {
		if u == nil {
			return nil
		}
		return u.String()
	}
	optInt := func(n *int64) any {
		if n == nil {
			return nil
		}
		return *n
	}
	groups := e.ActorGroups
	if groups == nil {
		groups = []string{}
	}
	var snapshot any
	if e.Snapshot != nil {
		snapshot = e.Snapshot
	}
	return map[string]any{
		"resource_type":     opt(e.ResourceType),
		"resource_id":       optUUID(e.ResourceID),
		"resource_name":     opt(e.ResourceName),
		"change_request_id": optUUID(e.ChangeRequestID),
		"action":            e.Action,
		"actor":             e.Actor,
		"actor_groups":      groups,
		"approver":          opt(e.Approver),
		"revision":          optInt(e.Revision),
		"attempt":           optInt(e.Attempt),
		"workflow_id":       opt(e.WorkflowID),
		"request_id":        opt(e.RequestID),
		"snapshot":          snapshot,
		"occurred_at":       e.OccurredAt.UTC().Truncate(time.Microsecond).Format(timeLayout),
	}
}

// hash returns hex(SHA-256(prev || JCS(row))) (§4.3), after checking the
// entry.
func (e *Entry) hash(prev string) (string, error) {
	if e.Action == "" || e.Actor == "" {
		return "", errors.New("audit: action and actor are required")
	}
	system := strings.HasPrefix(e.Action, "SESSION_") || strings.HasPrefix(e.Action, "CONFIG_") || strings.HasPrefix(e.Action, "SYSTEM_")
	if !system && (e.ResourceType == "" || e.ResourceName == "") {
		return "", fmt.Errorf("audit: %s needs a resource", e.Action)
	}
	if e.Snapshot != nil && !json.Valid(e.Snapshot) {
		return "", errors.New("audit: snapshot is not valid JSON")
	}
	canonical, err := jcs.Canonicalize(e.row())
	if err != nil {
		return "", fmt.Errorf("audit: %w", err)
	}
	sum := sha256.Sum256(append([]byte(prev), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

type requestIDKey struct{}

// WithRequestID tags the entries appended under ctx with the id of the API
// request that caused them.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// Hook, when set, runs first in Append, in the entry's transaction: ligo
// serve announces the entries that are notification events (§7.5), whose
// outbox rows go before the audit row (§4.3 lock order). It is set once at
// startup, before any transaction.
var Hook func(ctx context.Context, tx pgx.Tx, e Entry) error

// Append adds an entry to the chain in tx and returns its id. It MUST be the
// last operation of the transaction before COMMIT (§4.3, lock ordering): the
// chain's lock is held until then. The entry is also logged, for the SIEM.
func Append(ctx context.Context, tx pgx.Tx, e Entry) (int64, error) {
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now()
	}
	if e.RequestID == "" {
		e.RequestID, _ = ctx.Value(requestIDKey{}).(string)
	}
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	if Hook != nil {
		if err := Hook(ctx, tx, e); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('ligo_audit_chain'))"); err != nil {
		return 0, fmt.Errorf("audit: lock: %w", err)
	}
	prev := Genesis
	err := tx.QueryRow(ctx, "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("audit: %w", err)
	}
	hash, err := e.hash(prev)
	if err != nil {
		return 0, err
	}
	r := e.row()
	var id int64
	err = tx.QueryRow(ctx, `INSERT INTO audit_log (resource_type, resource_id, resource_name, change_request_id, action, actor,
		actor_groups, approver, revision, attempt, workflow_id, request_id, snapshot, occurred_at, prev_hash, entry_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) RETURNING id`,
		r["resource_type"], r["resource_id"], r["resource_name"], r["change_request_id"], e.Action, e.Actor,
		r["actor_groups"], r["approver"], r["revision"], r["attempt"], r["workflow_id"], r["request_id"],
		r["snapshot"], e.OccurredAt, prev, hash).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}
	slog.InfoContext(ctx, "audit", "audit_id", id, "action", e.Action, "actor", e.Actor,
		"resource_type", e.ResourceType, "resource_name", e.ResourceName, "request_id", e.RequestID, "entry_hash", hash)
	return id, nil
}

// Verification and checkpoints (§4.3).
var (
	// batchSize is how many entries one statement reads: each batch is a
	// short statement of its own, so no statement timeout bounds the chain.
	batchSize = 5000
)

const (
	// checkpointEntries and checkpointAge: a checkpoint is due after either.
	checkpointEntries = 1000
	checkpointAge     = time.Hour
)

// Result of a verification.
type Result struct {
	Valid       bool
	Entries     int   // entries re-hashed by this pass
	FirstBroken int64 // the first entry, or checkpoint's entry, that does not match, when not Valid
	Checkpoints int   // signed checkpoints checked
	Full        bool  // from the oldest entry, not from the newest checkpoint

	head     int64 // the last entry verified, and its hash: what Checkpoint signs
	headHash string
}

// stored is an entry as read back, with its id and hashes.
type stored struct {
	Entry
	id              int64
	prev, entryHash string
}

// load reads up to limit entries after id, in id order.
func load(ctx context.Context, q store.Querier, after int64, limit int) ([]stored, error) {
	rows, err := q.Query(ctx, `SELECT id, resource_type::text, resource_id, resource_name, change_request_id, action, actor,
		actor_groups, approver, revision, attempt, workflow_id, request_id, snapshot, occurred_at, prev_hash, entry_hash
		FROM audit_log WHERE id > $1 ORDER BY id LIMIT $2`, after, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	defer rows.Close()
	var out []stored
	for rows.Next() {
		var (
			e                                                       stored
			rtype, rname, approver, wf, req, storedPrev, storedHash *string
			snapshot                                                []byte
		)
		if err := rows.Scan(&e.id, &rtype, &e.ResourceID, &rname, &e.ChangeRequestID, &e.Action, &e.Actor, &e.ActorGroups,
			&approver, &e.Revision, &e.Attempt, &wf, &req, &snapshot, &e.OccurredAt, &storedPrev, &storedHash); err != nil {
			return nil, fmt.Errorf("audit: %w", err)
		}
		e.ResourceType, e.ResourceName, e.Approver, e.WorkflowID, e.RequestID = deref(rtype), deref(rname), deref(approver), deref(wf), deref(req)
		e.prev, e.entryHash = deref(storedPrev), deref(storedHash)
		if snapshot != nil {
			e.Snapshot = snapshot
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// checkpointMessage is what a checkpoint signs: through entry_hash, every
// entry up to auditID.
func checkpointMessage(auditID int64, entryHash string, at time.Time) ([]byte, error) {
	return jcs.Canonicalize(map[string]any{
		"auditId":   auditID,
		"entryHash": entryHash,
		"createdAt": at.UTC().Truncate(time.Microsecond).Format(timeLayout),
	})
}

// insertCheckpoint signs entryHash as the hash of entry auditID and records it.
func insertCheckpoint(ctx context.Context, q store.Querier, s sealing.Signer, auditID int64, entryHash string, at time.Time) error {
	at = at.UTC().Truncate(time.Microsecond)
	msg, err := checkpointMessage(auditID, entryHash, at)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	keyID, sig, err := s.Sign(ctx, msg)
	if err != nil {
		return fmt.Errorf("audit checkpoint: %w", err)
	}
	if _, err := q.Exec(ctx, `INSERT INTO audit_checkpoints (audit_id, entry_hash, created_at, key_id, signature)
		VALUES ($1, $2, $3, $4, $5)`, auditID, entryHash, at, keyID, sig); err != nil {
		return fmt.Errorf("audit checkpoint: %w", err)
	}
	return nil
}

// anchor is a checked checkpoint.
type anchor struct {
	auditID int64
	hash    string
}

// checkpoints checks every checkpoint: its signature, and that the entry it
// names still has the hash it signed. An entry below the oldest one left is
// pruned, not missing. It returns the checkpoints in order, or the entry of
// the first one that fails.
func checkpoints(ctx context.Context, q store.Querier, s sealing.Signer, oldest int64) ([]anchor, int64, error) {
	if s == nil {
		return nil, 0, errors.New("audit: no signer to verify the checkpoints with")
	}
	rows, err := q.Query(ctx, `SELECT c.audit_id, c.entry_hash, c.created_at, c.key_id, c.signature, a.entry_hash
		FROM audit_checkpoints c LEFT JOIN audit_log a ON a.id = c.audit_id ORDER BY c.audit_id`)
	if err != nil {
		return nil, 0, fmt.Errorf("audit: %w", err)
	}
	defer rows.Close()
	var out []anchor
	for rows.Next() {
		var (
			c          anchor
			at         time.Time
			keyID, sig string
			current    *string
		)
		if err := rows.Scan(&c.auditID, &c.hash, &at, &keyID, &sig, &current); err != nil {
			return nil, 0, fmt.Errorf("audit: %w", err)
		}
		msg, err := checkpointMessage(c.auditID, c.hash, at)
		if err != nil {
			return nil, 0, fmt.Errorf("audit: %w", err)
		}
		switch err := s.Verify(ctx, keyID, msg, sig); {
		case errors.Is(err, sealing.ErrBadSignature):
			return nil, c.auditID, nil
		case err != nil:
			return nil, 0, fmt.Errorf("audit checkpoint %d: %w", c.auditID, err)
		}
		pruned := current == nil && (oldest == 0 || c.auditID < oldest)
		if !pruned && deref(current) != c.hash {
			return nil, c.auditID, nil
		}
		out = append(out, c)
	}
	return out, 0, rows.Err()
}

// Verify checks the chain (§4.3, GET /v1/admin/audit/verify). Every signed
// checkpoint is checked first, then the entries are re-hashed in batches:
// from the newest checkpoint, or with full from the oldest entry left,
// whose prev_hash must be genesis or the hash of the newest checkpoint
// below it (a pruned head). Incremental verification does not see an entry
// before the newest checkpoint changed without its hash: the full pass
// does. A signer that cannot be reached is an error wrapping
// sealing.ErrSignerUnavailable, never a broken chain.
func Verify(ctx context.Context, q store.Querier, s sealing.Signer, full bool) (Result, error) {
	var oldest, newest *int64
	if err := q.QueryRow(ctx, "SELECT min(id), max(id) FROM audit_log").Scan(&oldest, &newest); err != nil {
		return Result{}, fmt.Errorf("audit: %w", err)
	}
	var first int64
	if oldest != nil {
		first = *oldest
	}
	anchors, broken, err := checkpoints(ctx, q, s, first)
	if err != nil {
		return Result{}, err
	}
	res := Result{Valid: true, Checkpoints: len(anchors), Full: full}
	if broken != 0 {
		res.Valid, res.FirstBroken = false, broken
		return res, nil
	}
	start := anchor{hash: Genesis}
	for _, a := range anchors {
		if (full && a.auditID < first) || (!full && (newest == nil || a.auditID <= *newest)) {
			start = a
		}
	}
	res.head, res.headHash = start.auditID, start.hash
	for {
		batch, err := load(ctx, q, res.head, batchSize)
		if err != nil {
			return Result{}, err
		}
		for _, e := range batch {
			res.Entries++
			hash, err := e.hash(res.headHash)
			if err != nil || e.prev != res.headHash || e.entryHash != hash {
				res.Valid, res.FirstBroken = false, e.id
				return res, nil
			}
			res.head, res.headHash = e.id, hash
		}
		if len(batch) < batchSize {
			return res, nil
		}
	}
}

// Checkpoint signs the head that res verified, when one is due at now:
// after checkpointEntries entries or checkpointAge since the last
// checkpoint, and never twice for one entry. It reports whether it signed.
func Checkpoint(ctx context.Context, q store.Querier, s sealing.Signer, res Result, now time.Time) (bool, error) {
	if !res.Valid || res.head == 0 {
		return false, nil
	}
	var (
		last int64
		at   *time.Time
	)
	if err := q.QueryRow(ctx, "SELECT coalesce(max(audit_id), 0), max(created_at) FROM audit_checkpoints").Scan(&last, &at); err != nil {
		return false, fmt.Errorf("audit: %w", err)
	}
	if res.head <= last {
		return false, nil
	}
	var since int
	if err := q.QueryRow(ctx, "SELECT count(*) FROM audit_log WHERE id > $1 AND id <= $2", last, res.head).Scan(&since); err != nil {
		return false, fmt.Errorf("audit: %w", err)
	}
	if at != nil && since < checkpointEntries && now.Sub(*at) < checkpointAge {
		return false, nil
	}
	if err := insertCheckpoint(ctx, q, s, res.head, res.headHash, now); err != nil {
		return false, err
	}
	return true, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
