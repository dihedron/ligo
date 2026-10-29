package pluginsdk

import (
	"context"
	"log/slog"
	"strings"
)

// secretKeys are the attribute key fragments whose values never reach a log.
var secretKeys = []string{"password", "passwd", "secret", "token", "credential", "private_key"}

// RedactingHandler drops secrets from log records before next sees them:
// attributes with a secret-looking key, and any message or string value
// containing IDENTIFIED BY (§5.8 rule 6).
type RedactingHandler struct{ next slog.Handler }

// NewRedactingHandler wraps next.
func NewRedactingHandler(next slog.Handler) *RedactingHandler { return &RedactingHandler{next: next} }

func (h *RedactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *RedactingHandler) Handle(ctx context.Context, r slog.Record) error {
	msg := r.Message
	if hasSQLSecret(msg) {
		msg = redacted
	}
	out := slog.NewRecord(r.Time, r.Level, msg, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(redact(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *RedactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clean := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		clean[i] = redact(a)
	}
	return &RedactingHandler{next: h.next.WithAttrs(clean)}
}

func (h *RedactingHandler) WithGroup(name string) slog.Handler {
	return &RedactingHandler{next: h.next.WithGroup(name)}
}

func redact(a slog.Attr) slog.Attr {
	a.Value = a.Value.Resolve()
	key := strings.ToLower(a.Key)
	for _, k := range secretKeys {
		if strings.Contains(key, k) {
			return slog.String(a.Key, redacted)
		}
	}
	switch a.Value.Kind() {
	case slog.KindGroup:
		group := a.Value.Group()
		clean := make([]any, len(group))
		for i, g := range group {
			clean[i] = redact(g)
		}
		return slog.Group(a.Key, clean...)
	case slog.KindString:
		if hasSQLSecret(a.Value.String()) {
			return slog.String(a.Key, redacted)
		}
	}
	return a
}

func hasSQLSecret(s string) bool {
	return strings.Contains(strings.ToUpper(s), "IDENTIFIED BY")
}
