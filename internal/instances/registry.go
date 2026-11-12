package instances

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/jcs"
	"github.com/dihedron/ligo/internal/metrics"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// channel is what trg_instances_notify notifies.
const channel = "ligo_instances_changed"

// Signed is the message the audit key signs for an instance row (§8).
func Signed(k Kind, name string, revision int64, sha string) []byte {
	msg, _ := jcs.Canonicalize(map[string]any{"kind": string(k), "name": name, "revision": revision, "definitionSha256": sha}) // strings and a number
	return msg
}

// Registry holds the ACTIVE instances, for every reader of platforms and
// instances: LISTEN for changes, and a full reload every Interval, as the
// account registry does (.specs/ligo-instances.md §8).
type Registry struct {
	DB       *pgxpool.Pool
	Signer   sealing.Signer
	Interval time.Duration
	Logger   *slog.Logger
	// OnChange is called with each new set, once loaded (the plugin
	// manager's reconcile, §7.2).
	OnChange func(*Set)

	cur atomic.Pointer[Set]

	mu        sync.Mutex
	reported  map[string]string // kind/name -> the drifted hash already audited
	sameAsSet string            // fingerprint of the current set
}

// Current is the set in force; empty before the first load.
func (r *Registry) Current() *Set {
	if s := r.cur.Load(); s != nil {
		return s
	}
	return NewSet()
}

// row is an instance as stored.
type row struct {
	id              uuid.UUID
	kind            Kind
	name            string
	revision        int64
	definition      []byte
	sha, keyID, sig string
	auditedRevision *int64
}

// Load reads the ACTIVE instances, quarantines those that do not verify, and
// swaps the set. With the signing key unreachable it keeps the set it has.
func (r *Registry) Load(ctx context.Context) error {
	rows, err := r.DB.Query(ctx, `SELECT i.id, i.kind, i.name, i.revision, i.definition, i.definition_sha256, i.key_id, i.signature,
		(SELECT max(a.revision) FROM audit_log a WHERE a.resource_id = i.id)
		FROM instances i WHERE i.status = 'ACTIVE' ORDER BY i.kind, i.name`)
	if err != nil {
		return fmt.Errorf("instances: %w", err)
	}
	stored, err := pgx.CollectRows(rows, func(cr pgx.CollectableRow) (row, error) {
		var x row
		err := cr.Scan(&x.id, &x.kind, &x.name, &x.revision, &x.definition, &x.sha, &x.keyID, &x.sig, &x.auditedRevision)
		return x, err
	})
	if err != nil {
		return fmt.Errorf("instances: %w", err)
	}
	var defs []*Definition
	fingerprint := ""
	for _, x := range stored {
		d, why, err := r.verify(ctx, x)
		if err != nil {
			return err // the key cannot be had: keep the set in force
		}
		key := string(x.kind) + "/" + x.name
		if why != "" {
			r.quarantine(ctx, x, why)
			continue
		}
		metrics.InstanceDrift.WithLabelValues(string(x.kind), x.name).Set(0)
		defs = append(defs, d)
		fingerprint += key + "@" + x.sha + ";"
	}
	set := NewSet(defs...)
	r.cur.Store(set)
	r.mu.Lock()
	changed := fingerprint != r.sameAsSet
	r.sameAsSet = fingerprint
	r.mu.Unlock()
	if changed && r.OnChange != nil {
		r.OnChange(set)
	}
	return nil
}

// verify checks a row against its own hash, its signature, and the newest
// revision the audit still holds; why says what failed, err that the key
// could not be had.
func (r *Registry) verify(ctx context.Context, x row) (*Definition, string, error) {
	d, err := Decode(x.definition)
	if err != nil {
		return nil, "the definition does not decode: " + err.Error(), nil
	}
	_, sha, err := d.Normalized()
	switch {
	case err != nil:
		return nil, "the definition cannot be hashed", nil
	case sha != x.sha:
		return nil, "the definition does not match its definition_sha256", nil
	case d.Metadata.Name != x.name || d.Kind != x.kind.ManifestKind():
		return nil, "the definition names another instance", nil
	case x.auditedRevision != nil && *x.auditedRevision > x.revision:
		return nil, fmt.Sprintf("revision %d is older than the audited revision %d", x.revision, *x.auditedRevision), nil
	}
	err = r.Signer.Verify(ctx, x.keyID, Signed(x.kind, x.name, x.revision, x.sha), x.sig)
	switch {
	case errors.Is(err, sealing.ErrSignerUnavailable):
		return nil, "", err
	case err != nil:
		return nil, "the signature does not verify: " + err.Error(), nil
	}
	return d, "", nil
}

// quarantine leaves an instance out of the set, and reports it: the log and
// the metric every time, the audit once per drifted hash.
func (r *Registry) quarantine(ctx context.Context, x row, why string) {
	key := string(x.kind) + "/" + x.name
	r.Logger.Error("instance quarantined: its row does not verify", "kind", x.kind, "instance", x.name, "reason", why)
	metrics.InstanceDrift.WithLabelValues(string(x.kind), x.name).Set(1)
	r.mu.Lock()
	if r.reported == nil {
		r.reported = map[string]string{}
	}
	done := r.reported[key] == x.sha
	r.reported[key] = x.sha
	r.mu.Unlock()
	if done {
		return
	}
	snapshot, _ := json.Marshal(map[string]any{"kind": x.kind, "reason": why, "definitionSha256": x.sha, "revision": x.revision}) // strings and a number
	id := x.id
	err := pgx.BeginFunc(ctx, r.DB, func(tx pgx.Tx) error {
		_, err := audit.Append(ctx, tx, audit.Entry{ResourceType: string(x.kind), ResourceID: &id, ResourceName: x.name,
			Action: "SYSTEM_INSTANCE_DRIFT", Actor: "system:instances", Snapshot: snapshot})
		return err
	})
	if err != nil {
		r.Logger.Error("instance drift: cannot audit", "kind", x.kind, "instance", x.name, "error", err)
		r.mu.Lock()
		delete(r.reported, key) // try again on the next load
		r.mu.Unlock()
	}
}

// Run keeps the registry fresh until ctx ends; a lost connection is retried.
func (r *Registry) Run(ctx context.Context) {
	for {
		err := r.listen(ctx)
		if ctx.Err() != nil {
			return
		}
		r.Logger.Warn("instance registry: listener lost, reconnecting", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// listen loads after LISTEN, so that nothing is missed while not listening.
func (r *Registry) listen(ctx context.Context) error {
	// its own connection: held for good, one from the pool would starve requests
	conn, err := pgx.ConnectConfig(ctx, r.DB.Config().ConnConfig)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if _, err := conn.Exec(ctx, "LISTEN "+channel); err != nil {
		return err
	}
	for {
		if err := r.Load(ctx); err != nil {
			r.Logger.Warn("instance registry: load failed, keeping the instances in force", "error", err)
		}
		wait, cancel := context.WithTimeout(ctx, r.Interval)
		_, err := conn.WaitForNotification(wait)
		expired := wait.Err() != nil
		cancel()
		if err != nil && !expired {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}
