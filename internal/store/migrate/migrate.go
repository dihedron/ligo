// Package migrate applies the database migrations, in order, each once
// (§4.2). It runs as ligo_migrator, which owns the objects (§4.1).
package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ErrChanged is returned when an applied migration's content changed since:
// migrations are never edited, a change is a new migration.
var ErrChanged = errors.New("applied migration changed")

// lockKey serializes migrations across replicas (pg_advisory_lock).
const lockKey = 0x6c69676f // "ligo"

var nameRE = regexp.MustCompile(`^([0-9]{3})_[a-z0-9_]+\.sql$`)

// Migration is one migration file.
type Migration struct {
	Version string
	Name    string
	SHA256  string
	SQL     string
}

// scan reads the migrations of fsys, sorted by version.
func scan(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	var out []Migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := nameRE.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("migrations: %q must be named NNN_description.sql", e.Name())
		}
		data, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			return nil, fmt.Errorf("migrations: %w", err)
		}
		if strings.TrimSpace(string(data)) == "" {
			return nil, fmt.Errorf("migrations: %s is empty", e.Name())
		}
		sum := sha256.Sum256(data)
		out = append(out, Migration{Version: m[1], Name: e.Name(), SHA256: hex.EncodeToString(sum[:]), SQL: string(data)})
	}
	if len(out) == 0 {
		return nil, errors.New("migrations: none found")
	}
	slices.SortFunc(out, func(a, b Migration) int { return strings.Compare(a.Version, b.Version) })
	for i := 1; i < len(out); i++ {
		if out[i].Version == out[i-1].Version {
			return nil, fmt.Errorf("migrations: %s and %s share version %s", out[i-1].Name, out[i].Name, out[i].Version)
		}
	}
	return out, nil
}

// Apply runs the migrations of fsys that are not yet applied, each in a
// transaction of its own, under an advisory lock, and returns the names of
// those it applied.
func Apply(ctx context.Context, conn *pgx.Conn, fsys fs.FS) ([]string, error) {
	all, err := scan(fsys)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "select pg_advisory_lock($1)", lockKey); err != nil {
		return nil, fmt.Errorf("migrations: lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), "select pg_advisory_unlock($1)", lockKey) }()

	if _, err := conn.Exec(ctx, `create table if not exists schema_migrations (
		version    char(3) primary key,
		name       text not null,
		sha256     char(64) not null,
		applied_at timestamptz not null default now())`); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	applied := map[string]string{}
	rows, err := conn.Query(ctx, "select version, sha256 from schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}
	for rows.Next() {
		var version, sum string
		if err := rows.Scan(&version, &sum); err != nil {
			return nil, fmt.Errorf("migrations: %w", err)
		}
		applied[version] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrations: %w", err)
	}

	var done []string
	for _, m := range all {
		if sum, ok := applied[m.Version]; ok {
			if sum != m.SHA256 {
				return done, fmt.Errorf("%w: %s (applied %s, now %s)", ErrChanged, m.Name, sum, m.SHA256)
			}
			continue
		}
		if err := apply(ctx, conn, m); err != nil {
			return done, err
		}
		done = append(done, m.Name)
	}
	return done, nil
}

// apply runs one migration and records it in the same transaction.
func apply(ctx context.Context, conn *pgx.Conn, m Migration) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		// no arguments: the simple protocol, which runs every statement
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			return fmt.Errorf("migration %s: %w", m.Name, err)
		}
		if _, err := tx.Exec(ctx, "insert into schema_migrations (version, name, sha256) values ($1, $2, $3)", m.Version, m.Name, m.SHA256); err != nil {
			return fmt.Errorf("migration %s: %w", m.Name, err)
		}
		return nil
	})
}
