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
	rate   Rate
}

// DefaultMaxKeys is the number of keys a Limiter keeps when Max is 0.
const DefaultMaxKeys = 1_000_000

// Limiter keeps a token bucket per key, up to Max keys; the zero value is
// ready to use. A full bucket is the same as none, so full buckets are
// pruned to make room; while there is none, a new key is refused.
type Limiter struct {
	Max int // default DefaultMaxKeys

	mu      sync.Mutex
	buckets map[string]*bucket
	pruned  time.Time
}

// refill returns key's bucket, refilled up to now, or nil if there is no
// room for a new key; l.mu is held.
func (l *Limiter) refill(key string, r Rate) *bucket {
	now := time.Now()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	b, ok := l.buckets[key]
	if !ok {
		if !l.room(now) {
			return nil
		}
		b = &bucket{tokens: r.Burst, at: now}
		l.buckets[key] = b
	}
	b.tokens = min(r.Burst, b.tokens+now.Sub(b.at).Seconds()*r.PerSecond)
	b.at, b.rate = now, r
	return b
}

// room reports whether a new key fits, pruning full buckets at most once a
// second when the map is full, so a flood of keys cannot make every request
// scan it.
func (l *Limiter) room(now time.Time) bool {
	limit := l.Max
	if limit <= 0 {
		limit = DefaultMaxKeys
	}
	if len(l.buckets) < limit {
		return true
	}
	if now.Sub(l.pruned) < time.Second {
		return false
	}
	l.pruned = now
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.at).Seconds()*b.rate.PerSecond >= b.rate.Burst {
			delete(l.buckets, k)
		}
	}
	return len(l.buckets) < limit
}

// Allow takes a token from key's bucket, if one is left.
func (l *Limiter) Allow(key string, r Rate) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.refill(key, r)
	if b == nil || b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Logins are the failed-login limits of §7.3 rule 6, shared by the UI's
// login and the admin API's Basic credentials: only refused credentials
// spend, and while an address's or a user's bucket is empty, every login
// from it or for them is refused, the right password included.
type Logins struct {
	PerIPPerMin, PerUserPerMin int // login_per_ip_per_min (default 10), login_per_user_per_min (default 5)
	MaxKeys                    int // max_tracked_keys (default DefaultMaxKeys)

	once sync.Once
	l    Limiter
}

func perMinute(n, fallback int) Rate {
	if n <= 0 {
		n = fallback
	}
	return Rate{PerSecond: float64(n) / 60, Burst: float64(n)}
}

// Begin reports whether a login from ip for user may be checked now. It
// takes a token from both buckets before the check, so logins checked at
// the same time all count; Done returns them unless the credentials were
// refused.
func (g *Logins) Begin(ip, user string) bool {
	g.once.Do(func() { g.l.Max = g.MaxKeys })
	g.l.mu.Lock()
	defer g.l.mu.Unlock()
	a, b := g.l.refill("ip:"+ip, perMinute(g.PerIPPerMin, 10)), g.l.refill("user:"+user, perMinute(g.PerUserPerMin, 5))
	if a == nil || b == nil || a.tokens < 1 || b.tokens < 1 {
		return false
	}
	a.tokens--
	b.tokens--
	return true
}

// Done ends a login that Begin allowed: refused credentials keep their
// tokens spent, anything else gives them back.
func (g *Logins) Done(ip, user string, refused bool) {
	if refused {
		return
	}
	g.l.mu.Lock()
	defer g.l.mu.Unlock()
	for _, k := range []struct {
		key string
		r   Rate
	}{{"ip:" + ip, perMinute(g.PerIPPerMin, 10)}, {"user:" + user, perMinute(g.PerUserPerMin, 5)}} {
		if b := g.l.refill(k.key, k.r); b != nil {
			b.tokens = min(k.r.Burst, b.tokens+1)
		}
	}
}
