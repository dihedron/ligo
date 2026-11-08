// Package charter implements jurisdictions and the derivation of a
// source's jurisdiction from its SVID regex (§3.9, Appendix D).
package charter

import (
	"regexp"
	"strings"
)

const (
	maxJurisdictionLen      = 128
	maxJurisdictionSegments = 8
)

var jurisdictionPathRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(/[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// ValidJurisdictionPath reports whether s is a jurisdiction path (§3.9).
func ValidJurisdictionPath(s string) bool {
	return len(s) <= maxJurisdictionLen && jurisdictionPathRE.MatchString(s) &&
		strings.Count(s, "/")+1 <= maxJurisdictionSegments
}

// ValidJurisdictionPattern reports whether p is "*", an exact jurisdiction path, or
// "<jurisdiction path>/*".
func ValidJurisdictionPattern(p string) bool {
	if p == "*" {
		return true
	}
	return ValidJurisdictionPath(strings.TrimSuffix(p, "/*"))
}

// JurisdictionMatches reports whether pattern covers jurisdiction, on whole segments.
func JurisdictionMatches(pattern, jurisdiction string) bool {
	if pattern == "*" {
		return true
	}
	if base, ok := strings.CutSuffix(pattern, "/*"); ok {
		return jurisdiction == base || strings.HasPrefix(jurisdiction, base+"/")
	}
	return pattern == jurisdiction
}
