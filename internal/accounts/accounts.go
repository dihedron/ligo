// Package accounts is the registry of tenants: an account-managed scope
// (governance.Accounts) is usable only while its account is registered and
// ACTIVE (.specs/ligo-tenancy.md §7).
package accounts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The SQLSTATEs the triggers of 001_init_schema.sql raise.
const (
	codeRetired = "LG001" // a source or target on a retired account
	codeInUse   = "LG002" // retiring an account that has sources or targets
)

const (
	maxName        = 30 // with a tenancy of 32, {account}_{tenancy} fits PostgreSQL's 63
	maxDisplayName = 128
)

// Account is the representation of an account.
type Account struct {
	Name         string     `json:"name"`
	DisplayName  string     `json:"displayName,omitempty"`
	Status       string     `json:"status"`
	RegisteredBy string     `json:"registeredBy"`
	RegisteredAt time.Time  `json:"registeredAt"`
	RetiredBy    string     `json:"retiredBy,omitempty"`
	RetiredAt    *time.Time `json:"retiredAt,omitempty"`
	Counts       *Counts    `json:"counts,omitempty"` // only for a single account
}

// Counts are what an account holds, retired resources excluded.
type Counts struct {
	Sources  int `json:"sources"`
	Targets  int `json:"targets"`
	Bindings int `json:"bindings"`
}

const columns = `name, coalesce(display_name, ''), status, registered_by, registered_at, coalesce(retired_by, ''), retired_at`

func scan(row pgx.Row) (*Account, error) {
	var a Account
	err := row.Scan(&a.Name, &a.DisplayName, &a.Status, &a.RegisteredBy, &a.RegisteredAt, &a.RetiredBy, &a.RetiredAt)
	return &a, err
}

func refuse(status int, slug, format string, args ...any) *changerequests.Error {
	return &changerequests.Error{Status: status, Slug: slug, Detail: fmt.Sprintf(format, args...)}
}

// write runs one change of the registry and its audit entry in a transaction.
func write(ctx context.Context, db *pgxpool.Pool, c changerequests.Caller, action, name string, change func(pgx.Tx) (*Account, error)) (a *Account, err error) {
	err = pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		if err := changerequests.Maintenance(ctx, tx); err != nil {
			return err
		}
		if a, err = change(tx); err != nil {
			return err
		}
		snapshot, err := json.Marshal(map[string]string{"name": name})
		if err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, audit.Entry{Action: action, Actor: c.ID(), ActorGroups: c.Principal.Groups, Snapshot: snapshot})
		return err
	})
	return a, err
}

// Register adds an account, at once: it grants nothing by itself, as no
// source or target exists yet and those still need consent.
func Register(ctx context.Context, db *pgxpool.Pool, c changerequests.Caller, name, displayName string) (*Account, error) {
	if !c.Grants.AccountAdmin() {
		return nil, refuse(403, "forbidden", "%s is no account_admin", c.ID())
	}
	if !governance.ValidAccountValue(name) || len(name) > maxName {
		return nil, refuse(422, "validation-failed", "name: lower case letters and digits, starting with a letter, at most %d characters", maxName)
	}
	if len(displayName) > maxDisplayName {
		return nil, refuse(422, "validation-failed", "displayName: at most %d bytes", maxDisplayName)
	}
	return write(ctx, db, c, "SYSTEM_ACCOUNT_REGISTERED", name, func(tx pgx.Tx) (*Account, error) {
		a, err := scan(tx.QueryRow(ctx, `INSERT INTO accounts (name, display_name, registered_by) VALUES ($1, nullif($2, ''), $3)
			RETURNING `+columns, name, displayName, c.ID()))
		if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.Code == "23505" {
			return nil, refuse(409, "account-exists", "account %q exists, or existed: a retired name is never reused", name)
		}
		return a, err
	})
}

// Retire ends an account that holds no active source or target; the trigger
// decides, under the account's lock, so that a source filed at the same
// moment either blocks the retirement or is refused.
func Retire(ctx context.Context, db *pgxpool.Pool, c changerequests.Caller, name string) (*Account, error) {
	if !c.Grants.AccountAdmin() {
		return nil, refuse(403, "forbidden", "%s is no account_admin", c.ID())
	}
	return write(ctx, db, c, "SYSTEM_ACCOUNT_RETIRED", name, func(tx pgx.Tx) (*Account, error) {
		a, err := scan(tx.QueryRow(ctx, `UPDATE accounts SET status = 'RETIRED', retired_by = $2, retired_at = now()
			WHERE name = $1 AND status = 'ACTIVE' RETURNING `+columns, name, c.ID()))
		if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.Code == codeInUse {
			return nil, refuse(409, "account-in-use", "%s", pe.Message)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return a, err
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM accounts WHERE name = $1", name).Scan(&n); err != nil {
			return nil, err
		}
		if n > 0 {
			return nil, refuse(409, "invalid-transition", "account %q is already retired", name)
		}
		return nil, refuse(404, "not-found", "account %q", name)
	})
}

// sees reports whether the caller may read an account: account_admin, or a
// role anywhere in it, a project's included.
func sees(c changerequests.Caller, cfg *governance.Accounts, name string) bool {
	if c.Grants.AccountAdmin() {
		return true
	}
	if cfg == nil {
		return false
	}
	return c.Grants.InScopes(governance.ExpandTemplate(cfg.Scope, map[string]string{"{account}": name}) + "/*")
}

// Get returns an account the caller may read, with its counts (404
// otherwise).
func Get(ctx context.Context, db *pgxpool.Pool, c changerequests.Caller, cfg *governance.Accounts, name string) (*Account, error) {
	a, err := scan(db.QueryRow(ctx, "SELECT "+columns+" FROM accounts WHERE name = $1", name))
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !sees(c, cfg, name) {
		return nil, refuse(404, "not-found", "account %q", name)
	}
	if err != nil {
		return nil, err
	}
	a.Counts = &Counts{}
	err = db.QueryRow(ctx, `SELECT (SELECT count(*) FROM sources WHERE account = $1 AND state <> 'RETIRED'),
		(SELECT count(*) FROM targets WHERE account = $1 AND state <> 'RETIRED'),
		(SELECT count(*) FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id
			WHERE s.account = $1 OR t.account = $1)`, name).Scan(&a.Counts.Sources, &a.Counts.Targets, &a.Counts.Bindings)
	return a, err
}

// List returns up to limit accounts after the name after that the caller may
// read, and whether there are more.
func List(ctx context.Context, db *pgxpool.Pool, c changerequests.Caller, cfg *governance.Accounts, after string, limit int) ([]*Account, bool, error) {
	var out []*Account
	for {
		rows, err := db.Query(ctx, "SELECT "+columns+" FROM accounts WHERE name > $1 ORDER BY name LIMIT $2", after, 2*limit)
		if err != nil {
			return nil, false, err
		}
		batch, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (*Account, error) { return scan(r) })
		if err != nil {
			return nil, false, err
		}
		for _, a := range batch {
			after = a.Name
			if !sees(c, cfg, a.Name) {
				continue
			}
			if len(out) == limit {
				return out, true, nil
			}
			out = append(out, a)
		}
		if len(batch) < 2*limit {
			return out, false, nil
		}
	}
}

// Require returns the account of scope, which is "" outside account-managed
// scopes; an account-managed scope whose account is not registered and ACTIVE
// is refused. A segment outside the account grammar is refused too: no such
// account can exist.
func Require(ctx context.Context, q store.Querier, cfg *governance.Accounts, scope string) (string, error) {
	name, managed := cfg.AccountOf(scope)
	if !managed {
		return "", nil
	}
	var active bool
	err := q.QueryRow(ctx, "SELECT status = 'ACTIVE' FROM accounts WHERE name = $1", name).Scan(&active)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if !active {
		return "", refuse(422, "account-not-registered", "account %q of scope %s is not registered, or is retired", name, scope)
	}
	return name, nil
}

// Refused maps the trigger's refusal of a resource on a retired account, the
// loser of a race with Require, to the same refusal.
func Refused(err error) error {
	if pe := (*pgconn.PgError)(nil); errors.As(err, &pe) && pe.Code == codeRetired {
		return refuse(422, "account-not-registered", "%s", pe.Message)
	}
	return err
}
