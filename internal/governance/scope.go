// Package governance implements governance scopes and the derivation of a
// source's scope from its SVID regex (§3.9, Appendix D).
package governance

import (
	"regexp"
	"strings"
)

const (
	maxScopeLen      = 128
	maxScopeSegments = 8
)

var scopePathRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(/[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// ValidScopePath reports whether s is a governance scope path (§3.9).
func ValidScopePath(s string) bool {
	return len(s) <= maxScopeLen && scopePathRE.MatchString(s) &&
		strings.Count(s, "/")+1 <= maxScopeSegments
}

// ValidScopePattern reports whether p is "*", an exact scope path, or
// "<scope path>/*".
func ValidScopePattern(p string) bool {
	if p == "*" {
		return true
	}
	return ValidScopePath(strings.TrimSuffix(p, "/*"))
}

// ScopeMatches reports whether pattern covers scope, on whole segments.
func ScopeMatches(pattern, scope string) bool {
	if pattern == "*" {
		return true
	}
	if base, ok := strings.CutSuffix(pattern, "/*"); ok {
		return scope == base || strings.HasPrefix(scope, base+"/")
	}
	return pattern == scope
}
