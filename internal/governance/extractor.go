package governance

import (
	"errors"
	"fmt"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
)

// ErrScopeUnresolvable means that the fixed beginning of a source regex does
// not identify exactly one scope (422 scope-unresolvable).
var ErrScopeUnresolvable = errors.New("scope-unresolvable")

// Extractor derives the scope of the sources of one trust domain
// (governance.source_scopes, §3.9).
type Extractor struct {
	scope    string // static mode
	re       *regexp.Regexp
	template string
}

var (
	templateRE    = regexp.MustCompile(`^(?:[a-z0-9/-]|\$\{[1-9]\})+$`)
	placeholderRE = regexp.MustCompile(`\$\{([1-9])\}`)
)

// NewStaticExtractor returns an extractor that assigns every source the
// same scope.
func NewStaticExtractor(scope string) (*Extractor, error) {
	if !ValidScopePath(scope) {
		return nil, fmt.Errorf("scope %q is not a valid scope path", scope)
	}
	return &Extractor{scope: scope}, nil
}

// NewPathTemplateExtractor validates path_regex and scope_template
// (§3.9, §8.2 rule 16).
func NewPathTemplateExtractor(pathRegex, template string) (*Extractor, error) {
	ast, err := syntax.Parse(pathRegex, syntax.Perl)
	if err != nil {
		return nil, fmt.Errorf("path_regex: %w", err)
	}
	if ast.Op != syntax.OpConcat || len(ast.Sub) < 3 || ast.Sub[0].Op != syntax.OpBeginText {
		return nil, errors.New("path_regex must start with ^ and contain literals and capture groups")
	}
	first, last := ast.Sub[1], ast.Sub[len(ast.Sub)-1]
	if first.Op != syntax.OpLiteral || !strings.HasPrefix(string(first.Rune), "/") {
		return nil, errors.New("path_regex must start with ^/")
	}
	if last.Op != syntax.OpLiteral || !strings.HasSuffix(string(last.Rune), "/") {
		return nil, errors.New("path_regex must end with a literal /")
	}
	groups, err := countGroups(ast.Sub[1:])
	if err != nil {
		return nil, err
	}
	if err := checkTemplate(template, groups); err != nil {
		return nil, err
	}
	re, err := regexp.Compile(pathRegex)
	if err != nil {
		return nil, fmt.Errorf("path_regex: %w", err)
	}
	return &Extractor{re: re, template: template}, nil
}

// countGroups checks that the parts of path_regex are literals and capture
// groups, and returns the number of groups (1 to 9).
func countGroups(parts []*syntax.Regexp) (int, error) {
	groups := 0
	for _, s := range parts {
		if s.Flags&syntax.FoldCase != 0 {
			return 0, errors.New("path_regex: case folding is forbidden")
		}
		switch s.Op {
		case syntax.OpLiteral:
		case syntax.OpCapture:
			groups++
			if err := checkGroup(s.Sub[0]); err != nil {
				return 0, err
			}
		default:
			return 0, errors.New("path_regex may contain only literals and capture groups")
		}
	}
	if groups == 0 || groups > 9 {
		return 0, errors.New("path_regex must have 1 to 9 capture groups")
	}
	return groups, nil
}

// checkTemplate checks scope_template against the groups of path_regex.
func checkTemplate(template string, groups int) error {
	if !templateRE.MatchString(template) {
		return errors.New("scope_template may contain only [a-z0-9/-] and ${1}..${9}")
	}
	for _, m := range placeholderRE.FindAllStringSubmatch(template, -1) {
		if n, _ := strconv.Atoi(m[1]); n > groups {
			return fmt.Errorf("scope_template references ${%d} but path_regex has %d groups", n, groups)
		}
	}
	return nil
}

// checkGroup accepts only a character class excluding '/', repeated with +.
func checkGroup(p *syntax.Regexp) error {
	if p.Op != syntax.OpPlus || p.Sub[0].Op != syntax.OpCharClass || p.Flags&syntax.FoldCase != 0 || p.Sub[0].Flags&syntax.FoldCase != 0 {
		return errors.New("path_regex: each capture group must be a single character class repeated with +")
	}
	cc := p.Sub[0].Rune
	for i := 0; i < len(cc); i += 2 {
		if cc[i] <= '/' && '/' <= cc[i+1] {
			return errors.New("path_regex: a capture group's character class must not match /")
		}
	}
	return nil
}

// SourceScope derives the scope of an svidRegex that passed the Appendix A
// validator for trust domain td, from its fixed beginning only (§3.9).
func (e *Extractor) SourceScope(svidRegex, td string) (string, error) {
	if e.re == nil {
		return e.scope, nil
	}
	ast, err := syntax.Parse(svidRegex, syntax.Perl)
	if err != nil || ast.Op != syntax.OpConcat || len(ast.Sub) < 3 || ast.Sub[1].Op != syntax.OpLiteral {
		return "", ErrScopeUnresolvable
	}
	literal := string(ast.Sub[1].Rune)
	prefix := "spiffe://" + td
	if !strings.HasPrefix(literal, prefix+"/") {
		return "", ErrScopeUnresolvable
	}
	m := e.re.FindStringSubmatch(literal[len(prefix):])
	if m == nil {
		return "", ErrScopeUnresolvable
	}
	scope := placeholderRE.ReplaceAllStringFunc(e.template, func(ph string) string {
		n, _ := strconv.Atoi(ph[2 : len(ph)-1])
		return m[n]
	})
	if !ValidScopePath(scope) {
		return "", ErrScopeUnresolvable
	}
	return scope, nil
}
