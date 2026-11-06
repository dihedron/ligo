package serve

import (
	"context"
	"log/slog"
	"testing"

	"github.com/dihedron/ligo/internal/client"
)

// TestSetGlobalsLevel: off silences even errors; it is not a fall back to info.
func TestSetGlobalsLevel(t *testing.T) {
	var cmd Serve
	cmd.SetGlobals(&client.Globals{LogLevel: "warn"})
	if cmd.level != slog.LevelWarn {
		t.Errorf("warn: got %v", cmd.level)
	}
	cmd.SetGlobals(&client.Globals{LogLevel: "off"})
	h := slog.NewJSONHandler(nil, &slog.HandlerOptions{Level: cmd.level})
	if h.Enabled(context.Background(), slog.LevelError) {
		t.Errorf("off: errors are logged, level %v", cmd.level)
	}
}
