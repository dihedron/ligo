package engine

import (
	"slices"
	"time"
)

// PrivilegesNarrower reports whether the proposed privileges are a subset of
// the current ones; equal sets count as narrowing (§3.10 rule 3).
func PrivilegesNarrower(current, proposed []string) bool {
	for _, p := range proposed {
		if !slices.Contains(current, p) {
			return false
		}
	}
	return true
}

// ExpiryNarrower reports whether the proposed expiry brings access to an end
// sooner: it is set and earlier than the current one, or there was none
// (§3.10).
func ExpiryNarrower(current, proposed *time.Time) bool {
	return proposed != nil && (current == nil || proposed.Before(*current))
}
