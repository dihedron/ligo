package adminhttp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/dihedron/ligo/internal/authz"
)

// basicTTL is how long a successful Basic login is remembered (§7.3 rule 6).
const basicTTL = 10 * time.Second

// basicCache remembers successful Basic logins for basicTTL, so that the
// CLI, which sends its credentials on every request, does not cost a
// directory round trip each time. Entries are keyed by an HMAC of the user
// and password under a key of this process: no password is kept.
type basicCache struct {
	mu  sync.Mutex
	key []byte
	m   map[[sha256.Size]byte]basicEntry
}

type basicEntry struct {
	p     authz.Principal
	until time.Time
}

func (c *basicCache) sum(user, password string) [sha256.Size]byte {
	if c.key == nil {
		c.key, c.m = make([]byte, 32), map[[sha256.Size]byte]basicEntry{}
		_, _ = rand.Read(c.key)
	}
	h := hmac.New(sha256.New, c.key)
	h.Write([]byte(user + "\x00" + password))
	return [sha256.Size]byte(h.Sum(nil))
}

// get returns the principal of a login remembered at now.
func (c *basicCache) get(user, password string, now time.Time) (authz.Principal, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[c.sum(user, password)]
	return e.p, ok && now.Before(e.until)
}

// put remembers a successful login, and forgets the expired ones.
func (c *basicCache) put(user, password string, p authz.Principal, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := c.sum(user, password)
	for key, e := range c.m {
		if !now.Before(e.until) {
			delete(c.m, key)
		}
	}
	c.m[k] = basicEntry{p: p, until: now.Add(basicTTL)}
}
