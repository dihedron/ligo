package regexpolicy

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ErrInvalid is matched by every rejection of the validator.
var ErrInvalid = errors.New("invalid SVID regex")

// InvalidError is a rejection, with the Appendix A.2 rule that failed.
type InvalidError struct {
	// Rule is the rule number, such as "4" or "7d".
	Rule string
	// Reason explains the rule to the person who wrote the pattern.
	Reason string
}

func (e *InvalidError) Error() string {
	return fmt.Sprintf("%v (rule %s): %s", ErrInvalid, e.Rule, e.Reason)
}

func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

func invalid(rule, reason string) error { return &InvalidError{Rule: rule, Reason: reason} }

// ValidateSVIDRegex checks a source's SVID regex against the rules of
// Appendix A.2 and returns the compiled program used for matching.
func ValidateSVIDRegex(pattern, trustDomain string, pol Policy) (*regexp.Regexp, error) {
	if len(pattern) > pol.MaxLength || !utf8.ValidString(pattern) {
		return nil, invalid("1", fmt.Sprintf("the pattern must be valid UTF-8 of at most %d bytes", pol.MaxLength))
	}
	if _, err := spiffeid.TrustDomainFromString(trustDomain); err != nil {
		return nil, invalid("2", "invalid trust domain")
	}
	ast, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, invalid("3", "syntax error: "+err.Error())
	}
	n := len(ast.Sub)
	if ast.Op != syntax.OpConcat || n < 3 ||
		ast.Sub[0].Op != syntax.OpBeginText || ast.Sub[n-1].Op != syntax.OpEndText ||
		ast.Sub[1].Op != syntax.OpLiteral {
		return nil, invalid("4", "the pattern must be ^<literal spiffe://trust-domain/ prefix>...$ without top-level alternation")
	}
	if ast.Sub[1].Flags&syntax.FoldCase != 0 {
		return nil, invalid("7a", "case-insensitive matching is forbidden")
	}
	literal := string(ast.Sub[1].Rune)
	prefix := "spiffe://" + trustDomain + "/"
	if !strings.HasPrefix(literal, prefix) {
		return nil, invalid("5", "the pattern must start with the literal prefix "+prefix)
	}
	if strings.Count(literal[len(prefix):], "/") < pol.MinLiteralPathSegments {
		return nil, invalid("6", fmt.Sprintf("the literal prefix must fix at least %d path segments", pol.MinLiteralPathSegments))
	}
	if err := walkForbidden(ast, true, false); err != nil {
		return nil, err
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, invalid("8", "does not compile: "+err.Error())
	}
	return re, nil
}

// isRepeat reports whether n can match its operand zero times or more than once.
func isRepeat(n *syntax.Regexp) bool {
	switch n.Op {
	case syntax.OpStar, syntax.OpPlus, syntax.OpQuest:
		return true
	case syntax.OpRepeat:
		return n.Min != 1 || n.Max != 1
	}
	return false
}

// walkForbidden applies rule 7 to every node of the AST.
func walkForbidden(n *syntax.Regexp, isRoot, inRepeat bool) error {
	if err := checkNode(n, isRoot, inRepeat); err != nil {
		return err
	}
	childInRepeat := inRepeat || isRepeat(n)
	for i, sub := range n.Sub {
		anchorAllowed := isRoot && (i == 0 || i == len(n.Sub)-1)
		if !anchorAllowed && (sub.Op == syntax.OpBeginText || sub.Op == syntax.OpEndText) {
			return invalid("7e", "text anchors are allowed only at the start and the end")
		}
		if err := walkForbidden(sub, false, childInRepeat); err != nil {
			return err
		}
	}
	return nil
}

// checkNode applies rules 7a to 7d and 7f to one node.
func checkNode(n *syntax.Regexp, isRoot, inRepeat bool) error {
	if n.Flags&syntax.FoldCase != 0 {
		return invalid("7a", "case-insensitive matching is forbidden")
	}
	switch n.Op {
	case syntax.OpBeginLine, syntax.OpEndLine, syntax.OpAnyChar, syntax.OpAnyCharNotNL:
		return invalid("7b", "'.' and line anchors are forbidden; use a character class that excludes '/'")
	case syntax.OpCharClass:
		if classMatchesSlash(n.Rune) {
			return invalid("7c", "a character class must not match '/'")
		}
	case syntax.OpLiteral:
		if inRepeat && strings.ContainsRune(string(n.Rune), '/') {
			return invalid("7d", "'/' must not appear inside a repeated or optional group")
		}
	case syntax.OpAlternate:
		if isRoot {
			return invalid("7f", "top-level alternation is forbidden")
		}
	}
	return nil
}

// classMatchesSlash reports whether the rune ranges of a class contain '/'.
func classMatchesSlash(ranges []rune) bool {
	for i := 0; i+1 < len(ranges); i += 2 {
		if ranges[i] <= '/' && '/' <= ranges[i+1] {
			return true
		}
	}
	return false
}
