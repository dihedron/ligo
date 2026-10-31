package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/config"
)

// TestBackoff: 10s doubling to 15m (§7.5).
func TestBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{1: 10 * time.Second, 2: 20 * time.Second, 4: 80 * time.Second, 7: 640 * time.Second, 8: 15 * time.Minute, 30: 15 * time.Minute} {
		if got := backoff(n); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// TestSign: HMAC-SHA256 over "<timestamp>.<body>", hex, prefixed sha256=.
func TestSign(t *testing.T) {
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write([]byte("1700000000.{}"))
	if got := Sign([]byte("k"), "1700000000", []byte("{}")); got != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Errorf("signature %s", got)
	}
}

// TestWants: a webhook receives the events it subscribes to; its scope
// filter applies to all but configuration and system events.
func TestWants(t *testing.T) {
	dba := config.Webhook{Events: []string{"CR_AWAITING_APPROVAL", "CONFIG_PLATFORM_CHANGED"}, Scopes: []string{"dc/corp-prod/*"}}
	all := config.Webhook{Events: []string{"CR_AWAITING_APPROVAL"}}
	for _, tc := range []struct {
		w    config.Webhook
		e    Event
		want bool
	}{
		{dba, Event{Name: "CR_AWAITING_APPROVAL", Scopes: []string{"dc/corp-prod/ledger"}}, true},
		{dba, Event{Name: "CR_AWAITING_APPROVAL", Scopes: []string{"cloud/fin-01/payments"}}, false},
		{dba, Event{Name: "CONFIG_PLATFORM_CHANGED"}, true},
		{dba, Event{Name: "BREAK_GLASS_USED", Scopes: []string{"dc/corp-prod"}}, false},
		{all, Event{Name: "CR_AWAITING_APPROVAL", Scopes: []string{"anything"}}, true},
	} {
		if got := wants(tc.w, tc.e); got != tc.want {
			t.Errorf("wants(%v, %v) = %v", tc.w.Scopes, tc.e, got)
		}
	}
}
