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

// Logins are the failed-login limits of §7.3 rule 6, shared by the UI's
// login and the admin API's Basic credentials: only refused credentials
// spend, and while an address's or a user's bucket is empty, every login
// from it or for them is refused, the right password included.
type Logins struct {
	PerIPPerMin, PerUserPerMin int // login_per_ip_per_min (default 10), login_per_user_per_min (default 5)

	l Limiter
}

func perMinute(n, fallback int) Rate {
	if n <= 0 {
		n = fallback
	}
	return Rate{PerSecond: float64(n) / 60, Burst: float64(n)}
}

// Limited reports whether logins from ip or for user are refused now.
func (g *Logins) Limited(ip, user string) bool {
	return g.l.Exhausted("ip:"+ip, perMinute(g.PerIPPerMin, 10)) || g.l.Exhausted("user:"+user, perMinute(g.PerUserPerMin, 5))
}

// Failed counts a refused login against ip and user.
func (g *Logins) Failed(ip, user string) {
	g.l.Spend("ip:"+ip, perMinute(g.PerIPPerMin, 10))
	g.l.Spend("user:"+user, perMinute(g.PerUserPerMin, 5))
}
