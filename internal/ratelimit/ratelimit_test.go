package ratelimit

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// TestLoginsConcurrent: logins checked at the same time all count, so no
// more than the user's limit pass Begin; credentials that are not refused
// give their tokens back.
func TestLoginsConcurrent(t *testing.T) {
	g := &Logins{}
	var passed atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			if g.Begin("10.0.0.1", "alice", "") {
				passed.Add(1)
			}
		})
	}
	wg.Wait()
	if n := passed.Load(); n != 5 {
		t.Fatalf("%d passed, want 5", n)
	}
	for range 5 {
		g.Done("10.0.0.1", "alice", "", false)
	}
	if !g.Begin("10.0.0.1", "alice", "") {
		t.Error("tokens of logins that were not refused not given back")
	}
	g.Done("10.0.0.1", "alice", "", true)
	for range 4 {
		g.Begin("10.0.0.1", "alice", "")
	}
	if g.Begin("10.0.0.1", "alice", "") {
		t.Error("five refused logins and still allowed")
	}
}

// TestLoginsLockout: refused logins from one address do not lock the user
// out of others; the user's limit from any address stops guessing spread
// over addresses; a session's re-authentication is not blocked by either,
// and its failures spend the user's bucket (§7.3 rule 6).
func TestLoginsLockout(t *testing.T) {
	g := &Logins{}
	fail := func(ip, session string) bool {
		if !g.Begin(ip, "alice", session) {
			return false
		}
		g.Done(ip, "alice", session, true)
		return true
	}
	for range 5 {
		fail("10.0.0.1", "")
	}
	if g.Begin("10.0.0.1", "alice", "") {
		t.Error("the address and user not limited")
	}
	if !g.Begin("10.0.0.2", "alice", "") {
		t.Fatal("another address locked out")
	}
	g.Done("10.0.0.2", "alice", "", false)
	for i := 2; i <= 10; i++ { // nine more addresses, five failures each: 50 in all
		for range 5 {
			fail(fmt.Sprintf("10.0.0.%d", i+1), "")
		}
	}
	if g.Begin("10.0.1.1", "alice", "") {
		t.Error("a new address allowed past the user's limit from any address")
	}
	if !fail("10.0.2.1", "s1") {
		t.Error("a session's re-authentication blocked by the user's lockout")
	}
	for range 4 {
		fail("10.0.2.1", "s1")
	}
	if g.Begin("10.0.2.1", "alice", "s1") {
		t.Error("the session not limited")
	}
}

// TestLimiterMax: full buckets make room for new keys; when every bucket
// is in use, a new key is refused and the existing ones keep their state.
func TestLimiterMax(t *testing.T) {
	l := &Limiter{Max: 3}
	r := Rate{PerSecond: 0, Burst: 1}
	for i := range 3 {
		if !l.Allow(fmt.Sprint("full", i), Rate{PerSecond: 1e9, Burst: 1}) { // refilled at once: full again
			t.Fatal("refused")
		}
	}
	if !l.Allow("a", r) {
		t.Fatal("no room made by pruning full buckets")
	}
	l.Allow("b", r)
	l.pruned = l.pruned.Add(-2e9)
	l.Allow("c", r)
	l.pruned = l.pruned.Add(-2e9)
	if l.Allow("d", r) {
		t.Error("a new key allowed while every bucket is in use")
	}
	if l.Allow("a", r) {
		t.Error("an empty bucket forgotten")
	}
}
