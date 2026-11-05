package pluginsdk

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
)

// secretKeys are the attribute key fragments whose values never reach a log.
var secretKeys = []string{"password", "passwd", "secret", "token", "credential", "private_key", "authorization"}

// RedactingHandler drops secrets from log records before next sees them:
// attributes and map keys with a secret-looking key, and any message,
// string or error containing SQL that sets a password (§5.8 rule 6).
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
	if secretKey(a.Key) {
		return slog.String(a.Key, redacted)
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
	case slog.KindAny:
		return slog.Any(a.Key, clean(a.Value.Any()))
	}
	return a
}

// clean redacts the values an attribute of any kind may hold: decoded JSON
// (maps and slices, as plugin log lines arrive) and errors.
func clean(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			if secretKey(k) {
				out[k] = redacted
			} else {
				out[k] = clean(e)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = clean(e)
		}
		return out
	case string:
		if hasSQLSecret(v) {
			return redacted
		}
	case error:
		if hasSQLSecret(v.Error()) {
			return redacted
		}
	}
	return v
}

func secretKey(key string) bool {
	key = strings.ToLower(key)
	for _, k := range secretKeys {
		if strings.Contains(key, k) {
			return true
		}
	}
	return false
}

// sqlSecretRE is SQL that sets a password: Oracle's IDENTIFIED BY, and
// PostgreSQL's PASSWORD followed by a literal ('...', E'...' or $$...$$).
var sqlSecretRE = regexp.MustCompile(`(?i)IDENTIFIED\s+BY|\bPASSWORD\s+(E?'|\$)`)

func hasSQLSecret(s string) bool { return sqlSecretRE.MatchString(s) }
