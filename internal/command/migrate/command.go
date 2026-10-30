// Package migrate is ligo migrate: it applies the migrations embedded in
// the binary as ligo_migrator, before a rollout (§8.4, §10.3).
package migrate

import (
	"context"
	"fmt"
	"os"

	"github.com/dihedron/ligo/internal/store"
	storemigrate "github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/migrations"
)

// Migrate is §8.4 MigrateCommand.
type Migrate struct {
	DSNEnv string `long:"dsn-env" default:"LIGO_MIGRATOR_DSN" description:"Environment variable holding the ligo_migrator DSN."`

	insecureDB bool // the tests' database container has no TLS; never set by a flag
}

// Execute applies what is not yet applied and prints each migration it
// applied; the DSN comes from the environment, never the command line.
func (cmd *Migrate) Execute([]string) error {
	dsn := os.Getenv(cmd.DSNEnv)
	if dsn == "" {
		return fmt.Errorf("migrate: environment variable %q is not set", cmd.DSNEnv)
	}
	ctx := context.Background()
	conn, err := store.Migrator(ctx, dsn, cmd.insecureDB)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer func() { _ = conn.Close(ctx) }()
	done, err := storemigrate.Apply(ctx, conn, migrations.FS)
	for _, name := range done {
		fmt.Println("applied", name)
	}
	if err == nil && len(done) == 0 {
		fmt.Println("the database is up to date")
	}
	return err
}
