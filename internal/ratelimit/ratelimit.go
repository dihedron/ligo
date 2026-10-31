// Package ratelimit keeps the token buckets of the listeners' rate limits
// (§7.1 controls, §7.3 rule 6).
package ratelimit

import (
	"sync"
	"time"
)

// Rate is a token bucket's refill per second and size.
type Rate struct{ PerSecond, Burst float64 }

type bucket struct {
	tokens float64
	at     time.Time
}

// Limiter keeps a token bucket per key; the zero value is ready to use.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

// refill returns key's bucket, refilled up to now; l.mu is held.
func (l *Limiter) refill(key string, r Rate) *bucket {
	now := time.Now()
	if l.buckets == nil || len(l.buckets) > 100_000 {
		l.buckets = map[string]*bucket{} // shortcut: forgets every bucket when the map grows past 100k keys; prune by age if that ever matters
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: r.Burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = min(r.Burst, b.tokens+now.Sub(b.at).Seconds()*r.PerSecond)
	b.at = now
	return b
}

// Allow takes a token from key's bucket, if one is left.
func (l *Limiter) Allow(key string, r Rate) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refill(key, r)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Exhausted reports whether key's bucket has no token left, taking none.
func (l *Limiter) Exhausted(key string, r Rate) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refill(key, r).tokens < 1
}

// Spend takes a token from key's bucket, down to none.
func (l *Limiter) Spend(key string, r Rate) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refill(key, r)
	b.tokens = max(0, b.tokens-1)
}
