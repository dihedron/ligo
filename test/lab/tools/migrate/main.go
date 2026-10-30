// Command migrate applies ligo's migrations as ligo_migrator to the database
// of its DSN: the lab migrates the service's database ligo_serve with it
// (.specs/ligo-test-environment.md, "The ligo service on ligo1"). Lab only:
// ligo has no migration command yet.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
)

func main() {
	if err := run(os.Getenv("LIGO_MIGRATOR_DSN")); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
}

// run reads the DSN from the environment, never from the command line.
func run(dsn string) error {
	if dsn == "" {
		return fmt.Errorf("LIGO_MIGRATOR_DSN is not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close(ctx) }()
	done, err := migrate.Apply(ctx, conn, migrations.FS)
	for _, name := range done {
		fmt.Println("applied", name)
	}
	return err
}
