// Package regexpolicy validates the SVID regexes of sources (Appendix A).
package regexpolicy

// Policy is the regex_policy section of server.yaml (§8.1).
type Policy struct {
	// MaxLength is the longest pattern accepted, in bytes (Appendix A.2, rule 1).
	MaxLength int `yaml:"max_length"`
	// MinLiteralPathSegments is the minimum number of '/' in the literal
	// prefix after the trust domain (Appendix A.2, rule 6).
	MinLiteralPathSegments int `yaml:"min_literal_path_segments"`
	// NarrowingStateLimit bounds the narrowing check; undecided means not
	// narrowing (§3.10, Appendix D.3).
	NarrowingStateLimit int `yaml:"narrowing_state_limit"`
}

// DefaultPolicy returns the defaults of §8.1.
func DefaultPolicy() Policy {
	return Policy{MaxLength: 512, MinLiteralPathSegments: 2, NarrowingStateLimit: 20000}
}
