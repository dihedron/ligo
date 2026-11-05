package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHandler(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	fresh := strconv.FormatInt(now.Unix(), 10)
	sign := func(secret, ts, body string) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "." + body))
		return "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	const body = `{"eventId":"1"}`
	for _, c := range []struct {
		name, hook, ts, signature, verdict string
		code                               int
	}{
		{"good", "oncall", fresh, sign("s3cret", fresh, body), "ok", http.StatusOK},
		{"other secret", "oncall", fresh, sign("other", fresh, body), "bad-signature", http.StatusUnauthorized},
		{"no signature", "oncall", fresh, "", "bad-signature", http.StatusUnauthorized},
		{"signed another time", "oncall", fresh, sign("s3cret", "1", body), "bad-signature", http.StatusUnauthorized},
		{"no timestamp", "oncall", "", sign("s3cret", "", body), "bad-timestamp", http.StatusUnauthorized},
		{"old", "oncall", strconv.FormatInt(now.Add(-6*time.Minute).Unix(), 10), "", "stale", http.StatusUnauthorized},
		{"ahead", "oncall", strconv.FormatInt(now.Add(6*time.Minute).Unix(), 10), "", "stale", http.StatusUnauthorized},
		{"unknown hook", "nobody", fresh, sign("s3cret", fresh, body), "unknown-hook", http.StatusUnauthorized},
	} {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			secret := func(hook string) string {
				if hook == "oncall" {
					return "s3cret"
				}
				return ""
			}
			req := httptest.NewRequest(http.MethodPost, "/hooks/"+c.hook, strings.NewReader(body))
			req.Header.Set("X-Ligo-Timestamp", c.ts)
			req.Header.Set("X-Ligo-Signature", c.signature)
			w := httptest.NewRecorder()
			handler(secret, &out, func() time.Time { return now }).ServeHTTP(w, req)
			if w.Code != c.code {
				t.Errorf("code %d, want %d", w.Code, c.code)
			}
			var rec record
			if err := json.Unmarshal(out.Bytes(), &rec); err != nil {
				t.Fatal(err)
			}
			if rec.Verdict != c.verdict || rec.Hook != c.hook || rec.Body != body {
				t.Errorf("recorded %+v, want verdict %s", rec, c.verdict)
			}
		})
	}
}
