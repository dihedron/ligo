package client

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"
)

func mustPrefix(t testing.TB, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// recordKeys returns a logger that records the attribute keys it was given.
func recordKeys(keys map[string]bool) *slog.Logger {
	return slog.New(keyHandler{keys})
}

type keyHandler struct{ keys map[string]bool }

func (keyHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h keyHandler) Handle(_ context.Context, r slog.Record) error {
	r.Attrs(func(a slog.Attr) bool { h.keys[a.Key] = true; return true })
	return nil
}
func (h keyHandler) WithAttrs(as []slog.Attr) slog.Handler {
	for _, a := range as {
		h.keys[a.Key] = true
	}
	return h
}
func (h keyHandler) WithGroup(string) slog.Handler { return h }
