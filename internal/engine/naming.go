// Package engine holds the domain rules shared by the API, the change
// requests and the workflows.
package engine

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"uuid"

	"github.com/dihedron/ligo/internal/governance"
)

// Kind is a resource type with its own name space (§3.8).
type Kind string

const (
	KindSource  Kind = "source"
	KindTarget  Kind = "target"
	KindBinding Kind = "binding"
)

// ErrInvalidName is returned for a name that breaks §3.8 (422
// validation-failed).
var ErrInvalidName = errors.New("invalid name")

var (
	nameRE            = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	principalPrefixRE = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,3}$`)
	resolvedPrefixRE  = regexp.MustCompile(`^[a-z0-9][-a-z0-9]{0,31}$`)
	placeholderRE     = regexp.MustCompile(`\{([0-9]+)\}`)
	principalEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// ValidName reports whether name is a valid source, target or binding name.
func ValidName(name string) bool { return nameRE.MatchString(name) }

// DerivedPrincipalName returns the external principal name of a binding
// (Appendix B); prefix replaces "bnd_" when set.
func DerivedPrincipalName(id uuid.UUID, prefix string) (string, error) {
	if prefix == "" {
		prefix = "bnd_"
	} else if !principalPrefixRE.MatchString(prefix) {
		return "", fmt.Errorf("principal prefix %q must match %s", prefix, principalPrefixRE)
	}
	sum := sha256.Sum256(id[:])
	return prefix + strings.ToLower(principalEncoding.EncodeToString(sum[:]))[:16], nil
}

// NamePrefix is an entry of governance.name_prefixes (§3.8).
type NamePrefix struct {
	Scopes    []string `yaml:"scopes"`
	Prefix    string   `yaml:"prefix"`
	Resources []Kind   `yaml:"resources"` // empty means all three kinds
}

// CheckName checks a new resource's name against §3.8. ownerScope is the
// source's scope for a source and a binding, the target's for a target.
func CheckName(kind Kind, name, ownerScope string, prefixes []NamePrefix) error {
	if !ValidName(name) {
		return fmt.Errorf("%w: %q must match %s", ErrInvalidName, name, nameRE)
	}
	prefix, err := ResolvePrefix(kind, ownerScope, prefixes)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return fmt.Errorf("%w: %q must start with %q and be longer", ErrInvalidName, name, prefix)
	}
	return nil
}

// ResolvePrefix returns the prefix of the first entry matching kind and
// scope, with {n} replaced by the n-th segment of scope, or "" if none
// matches.
func ResolvePrefix(kind Kind, scope string, prefixes []NamePrefix) (string, error) {
	for _, p := range prefixes {
		if len(p.Resources) > 0 && !slices.Contains(p.Resources, kind) {
			continue
		}
		if !slices.ContainsFunc(p.Scopes, func(pattern string) bool { return governance.ScopeMatches(pattern, scope) }) {
			continue
		}
		segments := strings.Split(scope, "/")
		var missing error
		prefix := placeholderRE.ReplaceAllStringFunc(p.Prefix, func(ph string) string {
			n, _ := strconv.Atoi(ph[1 : len(ph)-1])
			if n < 1 || n > len(segments) {
				missing = fmt.Errorf("%w: name prefix %q needs segment %d of scope %q", ErrInvalidName, p.Prefix, n, scope)
				return ""
			}
			return segments[n-1]
		})
		if missing != nil {
			return "", missing
		}
		if !resolvedPrefixRE.MatchString(prefix) {
			return "", fmt.Errorf("%w: resolved name prefix %q must match %s", ErrInvalidName, prefix, resolvedPrefixRE)
		}
		return prefix, nil
	}
	return "", nil
}
