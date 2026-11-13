package pluginsdk

import (
	"fmt"
	"time"
)

// The bounds of the lease of a credential that a secret store issues on
// demand (DelegatedRoleSpec.default_ttl_seconds and max_ttl_seconds).
const (
	MinCredentialTTL = time.Minute
	MaxCredentialTTL = 720 * time.Hour
)

// CredentialTTL checks a lease and the longest it may be renewed to. A 0
// is "not set": ligo fills it from its own configuration. Both set, ttl
// must not exceed maxTTL.
func CredentialTTL(ttl, maxTTL time.Duration) error {
	for _, d := range []time.Duration{ttl, maxTTL} {
		if d != 0 && (d < MinCredentialTTL || d > MaxCredentialTTL) {
			return fmt.Errorf("%s is not between %s and %s", d, MinCredentialTTL, MaxCredentialTTL)
		}
	}
	if ttl != 0 && maxTTL != 0 && ttl > maxTTL {
		return fmt.Errorf("the lease %s is longer than the maximum %s", ttl, maxTTL)
	}
	return nil
}
