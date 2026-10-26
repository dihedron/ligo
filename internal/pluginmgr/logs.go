package pluginmgr

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/hashicorp/go-hclog"
)

// newHCLogger is the logger go-plugin writes its messages to, as JSON lines
// for w.
func newHCLogger(w *hclogWriter) hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{Output: w, JSONFormat: true, Level: hclog.Debug})
}

// hclogWriter turns hclog's JSON lines, and any other line, into records of
// a logger that redacts them (§5.3 rule 5): go-plugin's messages and what a
// plugin writes to stdout and stderr.
type hclogWriter struct{ log *slog.Logger }

var hclogLevels = map[string]slog.Level{
	"trace": slog.LevelDebug, "debug": slog.LevelDebug, "info": slog.LevelInfo,
	"warn": slog.LevelWarn, "error": slog.LevelError,
}

func (w *hclogWriter) Write(p []byte) (int, error) {
	for line := range bytes.Lines(p) {
		var fields map[string]any
		if err := json.Unmarshal(line, &fields); err != nil {
			w.log.Debug(strings.TrimSpace(string(line)))
			continue
		}
		level, msg := hclogLevels[str(fields["@level"])], str(fields["@message"])
		attrs := make([]any, 0, 2*len(fields))
		for k, v := range fields {
			if k != "@level" && k != "@message" && k != "@timestamp" {
				attrs = append(attrs, strings.TrimPrefix(k, "@"), v)
			}
		}
		w.log.Log(context.Background(), level, msg, attrs...)
	}
	return len(p), nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
