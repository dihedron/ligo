package pluginmgr

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/dihedron/ligo/pkg/pluginsdk"
)

// TestLogsRedacted: no secret a plugin writes reaches the log, whatever the
// shape it comes in (§5.3 rule 5, INV-03).
func TestLogsRedacted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		writes []string
		log    func(*slog.Logger)
	}{
		{"nested object", []string{`{"@level":"info","@message":"connect","conn":{"password":"hunter2"}}` + "\n"}, nil},
		{"error value", nil, func(l *slog.Logger) { l.Info("apply", "error", errors.New("ALTER USER app IDENTIFIED BY hunter2")) }},
		{"postgres password", []string{"CREATE ROLE app LOGIN PASSWORD 'hunter2'\n"}, nil},
		{"split line", []string{`{"@level":"info","@message":"x","password":"hun`, `ter2"}` + "\n"}, nil},
		{"long line", []string{`{"@message":"x","password":"hunter2","pad":"` + strings.Repeat("x", maxLine), `"}` + "\n"}, nil},
	} {
		var buf bytes.Buffer
		l := slog.New(pluginsdk.NewRedactingHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
		w := &lineWriter{next: &hclogWriter{log: l}} // as Start passes stdout and stderr
		for _, s := range tc.writes {
			_, _ = w.Write([]byte(s))
		}
		if tc.log != nil {
			tc.log(l)
		}
		if strings.Contains(buf.String(), "hunter2") || strings.Contains(buf.String(), "hun\"") {
			t.Errorf("%s: %s", tc.name, buf.String())
		}
	}
}

// TestLogsKept: words that only look like secrets are logged, and lines
// pass whole.
func TestLogsKept(t *testing.T) {
	var buf bytes.Buffer
	w := &lineWriter{next: &hclogWriter{log: slog.New(pluginsdk.NewRedactingHandler(slog.NewJSONHandler(&buf, nil)))}}
	for _, s := range []string{`{"@level":"warn","@message":"password expired for app"}` + "\n" + `{"@level":"in`, `fo","@message":"two"}` + "\n"} {
		if n, err := w.Write([]byte(s)); err != nil || n != len(s) {
			t.Fatalf("write %d %v", n, err)
		}
	}
	if out := buf.String(); !strings.Contains(out, "password expired for app") || !strings.Contains(out, `"msg":"two"`) {
		t.Errorf("logged %s", out)
	}
}
