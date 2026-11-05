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
// spend, and while a bucket of the login is empty, it is refused, the right
// password included. A login has three buckets: its address, its address
// and user, and its user from any address, whose higher limit stops
// guessing spread over addresses without letting one address lock a user
// out. A re-authentication within a session (break-glass) uses its address
// and that session instead, so no one outside the session can block it;
// its failures still spend the user's bucket.
type Logins struct {
	PerIPPerMin         int // login_per_ip_per_min (default 10)
	PerUserPerMin       int // login_per_user_per_min (default 5), per address and user, or per session
	PerUserGlobalPerMin int // login_per_user_global_per_min (default 50), per user from any address
	MaxKeys             int // max_tracked_keys (default DefaultMaxKeys)

	once sync.Once
	l    Limiter
}

func perMinute(n, fallback int) Rate {
	if n <= 0 {
		n = fallback
	}
	return Rate{PerSecond: float64(n) / 60, Burst: float64(n)}
}

type limit struct {
	key string
	r   Rate
}

// limits are the buckets of a login; session is "" outside a session.
func (g *Logins) limits(ip, user, session string) []limit {
	ls := []limit{{"ip:" + ip, perMinute(g.PerIPPerMin, 10)}}
	if session != "" {
		return append(ls, limit{"session:" + session, perMinute(g.PerUserPerMin, 5)})
	}
	return append(ls, limit{"ipuser:" + ip + "\x00" + user, perMinute(g.PerUserPerMin, 5)},
		limit{"user:" + user, perMinute(g.PerUserGlobalPerMin, 50)})
}

// Begin reports whether a login from ip for user may be checked now; session
// identifies the session of a re-authentication, else it is "". It takes a
// token from each bucket before the check, so logins checked at the same
// time all count; Done returns them unless the credentials were refused.
func (g *Logins) Begin(ip, user, session string) bool {
	g.once.Do(func() { g.l.Max = g.MaxKeys })
	g.l.mu.Lock()
	defer g.l.mu.Unlock()
	ls := g.limits(ip, user, session)
	bs := make([]*bucket, len(ls))
	for i, l := range ls {
		if bs[i] = g.l.refill(l.key, l.r); bs[i] == nil || bs[i].tokens < 1 {
			return false
		}
	}
	for _, b := range bs {
		b.tokens--
	}
	return true
}

// Done ends a login that Begin allowed: refused credentials keep their
// tokens spent (and a session's also spend the user's bucket, down to
// none), anything else gives them back.
func (g *Logins) Done(ip, user, session string, refused bool) {
	g.l.mu.Lock()
	defer g.l.mu.Unlock()
	if refused {
		if session != "" {
			if b := g.l.refill("user:"+user, perMinute(g.PerUserGlobalPerMin, 50)); b != nil {
				b.tokens = max(0, b.tokens-1)
			}
		}
		return
	}
	for _, l := range g.limits(ip, user, session) {
		if b := g.l.refill(l.key, l.r); b != nil {
			b.tokens = min(l.r.Burst, b.tokens+1)
		}
	}
}
