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

// Result of a verification.
type Result struct {
	Valid       bool
	Entries     int
	FirstBroken int64 // the first entry whose hash does not match, when not Valid
}

// Verify recomputes the chain from the first entry (§4.3,
// GET /v1/admin/audit/verify).
func Verify(ctx context.Context, q store.Querier) (Result, error) {
	rows, err := q.Query(ctx, `SELECT id, resource_type::text, resource_id, resource_name, change_request_id, action, actor,
		actor_groups, approver, revision, attempt, workflow_id, request_id, snapshot, occurred_at, prev_hash, entry_hash
		FROM audit_log ORDER BY id`)
	if err != nil {
		return Result{}, fmt.Errorf("audit: %w", err)
	}
	defer rows.Close()
	res := Result{Valid: true}
	prev := Genesis
	for rows.Next() {
		var (
			e                                                       Entry
			id                                                      int64
			rtype, rname, approver, wf, req, storedPrev, storedHash *string
			snapshot                                                []byte
		)
		if err := rows.Scan(&id, &rtype, &e.ResourceID, &rname, &e.ChangeRequestID, &e.Action, &e.Actor, &e.ActorGroups,
			&approver, &e.Revision, &e.Attempt, &wf, &req, &snapshot, &e.OccurredAt, &storedPrev, &storedHash); err != nil {
			return Result{}, fmt.Errorf("audit: %w", err)
		}
		e.ResourceType, e.ResourceName, e.Approver, e.WorkflowID, e.RequestID = deref(rtype), deref(rname), deref(approver), deref(wf), deref(req)
		if snapshot != nil {
			e.Snapshot = snapshot
		}
		res.Entries++
		hash, err := e.hash(prev)
		if err != nil || deref(storedPrev) != prev || deref(storedHash) != hash {
			return Result{Valid: false, Entries: res.Entries, FirstBroken: id}, rows.Err()
		}
		prev = hash
	}
	return res, rows.Err()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
