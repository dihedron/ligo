package migrate

import (
	"testing"
	"testing/fstest"

	"github.com/dihedron/ligo/migrations"
)

func TestScan(t *testing.T) {
	got, err := scan(fstest.MapFS{
		"002_more.sql":        {Data: []byte("select 2;")},
		"001_init_schema.sql": {Data: []byte("select 1;")},
		"README.md":           {Data: []byte("not a migration")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Version != "001" || got[1].Version != "002" || got[0].Name != "001_init_schema.sql" || len(got[0].SHA256) != 64 {
		t.Errorf("scan = %+v", got)
	}
}

func TestScanRefusals(t *testing.T) {
	for name, fs := range map[string]fstest.MapFS{
		"no number":         {"init.sql": {Data: []byte("x")}},
		"duplicate version": {"001_a.sql": {Data: []byte("x")}, "001_b.sql": {Data: []byte("y")}},
		"empty":             {"001_a.sql": {Data: []byte("  \n")}},
		"none":              {},
	} {
		if _, err := scan(fs); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestEmbedded checks the migrations shipped with ligo.
func TestEmbedded(t *testing.T) {
	got, err := scan(migrations.FS)
	if err != nil || len(got) == 0 || got[0].Name != "001_init_schema.sql" {
		t.Fatalf("embedded migrations: %+v, %v", got, err)
	}
}
