//go:build integration

package migrate

import (
	"errors"
	"os"
	"testing"

	"github.com/dihedron/ligo/internal/store"
)

// TestMigrate: ligo migrate applies what is missing (nothing on a migrated
// database), reads the DSN only from the named variable, and refuses a
// connection without verify-full.
func TestMigrate(t *testing.T) {
	dsn := os.Getenv("LIGO_TEST_PG_MIGRATOR_DSN")
	if dsn == "" {
		t.Fatal("LIGO_TEST_PG_MIGRATOR_DSN is not set: run the integration tests with test/lab/lab.sh test")
	}
	insecure := os.Getenv("CI") != ""
	cmd := &Migrate{DSNEnv: "LIGO_TEST_PG_MIGRATOR_DSN", insecureDB: insecure}
	for range 2 {
		if err := cmd.Execute(nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := (&Migrate{DSNEnv: "LIGO_TEST_NOT_SET"}).Execute(nil); err == nil {
		t.Error("an unset variable")
	}
	t.Setenv("LIGO_TEST_PLAIN_DSN", "postgres://ligo_migrator:x@127.0.0.1:1/ligo?sslmode=disable")
	if err := (&Migrate{DSNEnv: "LIGO_TEST_PLAIN_DSN"}).Execute(nil); !errors.Is(err, store.ErrInsecureConnection) {
		t.Errorf("a DSN without TLS: %v", err)
	}
}
