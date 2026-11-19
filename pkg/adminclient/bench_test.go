// SPDX-License-Identifier: MIT

package adminclient

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// BenchmarkListAuditTenThousand reads 10,000 items through the iterator, in
// 50 pages of 200 (the server's largest), over TLS: the cost of a list.
func BenchmarkListAuditTenThousand(b *testing.B) {
	var page strings.Builder
	page.WriteString(`{"items":[`)
	for i := range 200 {
		if i > 0 {
			page.WriteByte(',')
		}
		page.WriteString(`{"id":` + strconv.Itoa(i+1) + `,"action":"BINDING_UPDATED","actor":"ada","approver":"dora","revision":4,"occurredAt":"2026-11-14T10:00:00Z"}`)
	}
	page.WriteString(`]`)
	body := page.String()
	u, pool := serveTLS(b, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("pageToken"))
		next := `,"nextPageToken":"` + strconv.Itoa(n+1) + `"`
		if n >= 49 {
			next = ""
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body + next + `}`))
	}))
	c, err := New(Config{ServerURL: u, RootCAs: pool, Basic: &BasicAuth{Username: "a", Password: "b"}})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = c.Close() })
	b.ReportAllocs()
	for b.Loop() {
		n := 0
		for _, err := range c.SourceAudit(context.Background(), "s", 200) {
			if err != nil {
				b.Fatal(err)
			}
			n++
		}
		if n != 10000 {
			b.Fatalf("%d items", n)
		}
	}
}
