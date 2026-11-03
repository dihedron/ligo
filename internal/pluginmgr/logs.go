package pluginmgr

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"

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

// maxLine is the longest line a plugin may write to stdout or stderr.
const maxLine = 64 << 10

// lineWriter passes whole lines to next, so a line split across writes is
// redacted as one; a longer line than maxLine is dropped, never logged in
// pieces.
// shortcut: a last line without a newline is lost when the plugin exits; flush on exit if plugins need it.
type lineWriter struct {
	mu      sync.Mutex
	next    io.Writer
	buf     []byte
	dropped bool // the current line is over maxLine
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		part := p
		if i >= 0 {
			part = p[:i+1]
		}
		p = p[len(part):]
		if !w.dropped && len(w.buf)+len(part) > maxLine {
			w.buf, w.dropped = w.buf[:0], true
		}
		if !w.dropped {
			w.buf = append(w.buf, part...)
		}
		if i < 0 {
			break
		}
		line := w.buf
		if w.dropped {
			line = []byte("[a line over 64 KiB was dropped]\n")
		}
		if _, err := w.next.Write(line); err != nil {
			return 0, err
		}
		w.buf, w.dropped = w.buf[:0], false
	}
	return n, nil
}
