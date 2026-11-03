package bindings

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPropagatorLogs: a failed pass is logged, not dropped (finding 3.4).
func TestPropagatorLogs(t *testing.T) {
	db, err := pgxpool.New(context.Background(), "postgres://ligo@127.0.0.1:1/ligo?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	(&Propagator{Service: &Service{DB: db}, Logger: slog.New(slog.NewTextHandler(&out, nil)), Interval: 20 * time.Millisecond}).Run(ctx)
	if !strings.Contains(out.String(), "level=ERROR msg=propagator") {
		t.Errorf("logged %q", out.String())
	}
}
