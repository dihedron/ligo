package governance

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// The placeholders of governance.accounts (.specs/ligo-tenancy.md §4).
const (
	account = "{account}"
	project = "{project}"
	tenancy = "{tenancy}"
)

// accountValueRE is narrower than a scope segment on purpose: with no "-",
// and no "_" in a value, a namespace such as {account}_{tenancy} is injective.
var accountValueRE = regexp.MustCompile(`^[a-z][a-z0-9]*$`)

// ValidAccountValue reports whether v may stand for a placeholder.
func ValidAccountValue(v string) bool { return accountValueRE.MatchString(v) }

// Accounts is the structure of account-managed scopes and of their LDAP
// groups; absent, ligo has no accounts.
type Accounts struct {
	Scope       string        `yaml:"scope"`
	SourceScope string        `yaml:"source_scope"`
	TargetScope string        `yaml:"target_scope"`
	LDAPGroups  AccountGroups `yaml:"ldap_groups"`
}

// AccountGroups derives roles from the directory, one rule for all accounts.
type AccountGroups struct {
	SearchBase string        `yaml:"search_base"`
	Roles      []AccountRole `yaml:"roles"`
}

// AccountRole gives Role on Scope to the members of the groups GroupDN
// describes.
type AccountRole struct {
	GroupDN string `yaml:"group_dn"`
	Role    string `yaml:"role"`
	Scope   string `yaml:"scope"`
}

// MatchScope matches scope against template, segment by segment, and returns
// the placeholders' values; both must have the same number of segments.
func MatchScope(template, scope string) (map[string]string, bool) {
	ts, ss := strings.Split(template, "/"), strings.Split(scope, "/")
	if len(ts) != len(ss) {
		return nil, false
	}
	values := map[string]string{}
	for i, t := range ts {
		switch {
		case isPlaceholder(t):
			if !ValidAccountValue(ss[i]) {
				return nil, false
			}
			values[t] = ss[i]
		case t != ss[i]:
			return nil, false
		}
	}
	return values, true
}

// ExpandTemplate replaces the placeholders of template with values.
func ExpandTemplate(template string, values map[string]string) string {
	var pairs []string
	for k, v := range values {
		pairs = append(pairs, k, v)
	}
	return strings.NewReplacer(pairs...).Replace(template)
}

// AccountOf returns the account of an account-managed scope: one that matches
// Scope or lies below it, on its literal segments. The value is not checked
// against the grammar, so that "cloud/a-b" reads as an account no registry
// holds and is refused, not as a scope that needs no account.
func (a *Accounts) AccountOf(scope string) (string, bool) {
	if a == nil {
		return "", false
	}
	ts, ss := strings.Split(a.Scope, "/"), strings.Split(scope, "/")
	if len(ss) < len(ts) {
		return "", false
	}
	var value string
	for i, t := range ts {
		switch {
		case isPlaceholder(t):
			value = ss[i]
		case t != ss[i]:
			return "", false
		}
	}
	return value, true
}

// conforms reports whether scope has the form of template, when it is
// account-managed at all.
func (a *Accounts) conforms(template, scope string) bool {
	if _, managed := a.AccountOf(scope); !managed {
		return true
	}
	_, ok := MatchScope(template, scope)
	return ok
}

// SourceConforms reports whether a source may have scope: outside accounts,
// or in the form of SourceScope.
func (a *Accounts) SourceConforms(scope string) bool {
	return a == nil || a.conforms(a.SourceScope, scope)
}

// TargetConforms reports whether a target may have scope: outside accounts,
// or in the form of TargetScope.
func (a *Accounts) TargetConforms(scope string) bool {
	return a == nil || a.conforms(a.TargetScope, scope)
}

// NamespaceOf expands template with the values of a target's scope; false if
// the scope does not have the form of TargetScope.
func (a *Accounts) NamespaceOf(template, scope string) (string, bool) {
	if a == nil {
		return "", false
	}
	values, ok := MatchScope(a.TargetScope, scope)
	if !ok {
		return "", false
	}
	return ExpandTemplate(template, values), true
}

// namespacePlaceholderRE finds the placeholders of a namespace template.
var namespacePlaceholderRE = regexp.MustCompile(`\{[^{}]*\}`)

// CheckNamespaceTemplate refuses a template that two tenancies could share: it
// must use each placeholder of TargetScope once, and what separates two of
// them must hold a character that values cannot.
func (a *Accounts) CheckNamespaceTemplate(template string) error {
	var want []string
	for _, s := range strings.Split(a.TargetScope, "/") {
		if isPlaceholder(s) {
			want = append(want, s)
		}
	}
	locations := namespacePlaceholderRE.FindAllStringIndex(template, -1)
	seen := map[string]bool{}
	for i, l := range locations {
		name := template[l[0]:l[1]]
		if !slices.Contains(want, name) || seen[name] {
			return fmt.Errorf("namespace template %q: %s must be a placeholder of %q, used once", template, name, a.TargetScope)
		}
		seen[name] = true
		if i > 0 && !strings.ContainsFunc(template[locations[i-1][1]:l[0]], outsideValues) {
			return fmt.Errorf("namespace template %q: the placeholders must be separated by a character values cannot hold", template)
		}
	}
	if len(seen) != len(want) {
		return fmt.Errorf("namespace template %q must use every one of %v", template, want)
	}
	return nil
}

func outsideValues(r rune) bool { return (r < 'a' || r > 'z') && (r < '0' || r > '9') }

// SampleScope is the account root for an example account, to check what
// patterns cover: only "*"-ended patterns above the root can cover it.
func (a *Accounts) SampleScope() string {
	return ExpandTemplate(a.Scope, map[string]string{account: "zzzsample"})
}

// Validate checks the structure itself (§8.2 rule 16).
func (a *Accounts) Validate() error {
	errs := []error{
		checkScopeTemplate("scope", a.Scope, []string{account}, []string{account}),
		checkScopeTemplate("source_scope", a.SourceScope, []string{account, project}, []string{account, project}),
		checkScopeTemplate("target_scope", a.TargetScope, []string{account, tenancy}, []string{account, tenancy}),
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	if !below(a.Scope, a.SourceScope) || !below(a.Scope, a.TargetScope) {
		errs = append(errs, fmt.Errorf("source_scope and target_scope must lie below scope %q", a.Scope))
	}
	if templatesOverlap(a.SourceScope, a.TargetScope) {
		errs = append(errs, fmt.Errorf("source_scope %q and target_scope %q overlap: a project and a tenancy of one name would be one scope", a.SourceScope, a.TargetScope))
	}
	errs = append(errs, a.LDAPGroups.validate(a))
	return errors.Join(errs...)
}

func (g *AccountGroups) validate(a *Accounts) error {
	if len(g.Roles) == 0 {
		return nil
	}
	base, err := ldap.ParseDN(g.SearchBase)
	if err != nil || len(base.RDNs) == 0 {
		return fmt.Errorf("ldap_groups.search_base %q must be a DN", g.SearchBase)
	}
	var errs []error
	depths := map[string]int{}
	for i, r := range g.Roles {
		where := fmt.Sprintf("ldap_groups.roles[%d]", i)
		found, err := dnPlaceholders(r.GroupDN, base)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: group_dn %q: %w", where, r.GroupDN, err))
			continue
		}
		for name, depth := range found {
			if d, ok := depths[name]; ok && d != depth {
				errs = append(errs, fmt.Errorf("%s: %s is at depth %d here and %d in another rule: its depth holds for the whole organisation", where, name, depth, d))
			}
			depths[name] = depth
		}
		errs = append(errs, checkRoleScope(where, r.Scope, a.Scope, found))
	}
	return errors.Join(errs...)
}

// dnPlaceholders parses a group DN and returns its placeholders with their
// depths, counted from the root. A placeholder is one whole attribute value
// and the DN lies below base.
func dnPlaceholders(groupDN string, base *ldap.DN) (map[string]int, error) {
	dn, err := ldap.ParseDN(groupDN)
	if err != nil {
		return nil, err
	}
	if !base.AncestorOfFold(dn) {
		return nil, errors.New("must lie below search_base")
	}
	found := map[string]int{}
	for i, rdn := range dn.RDNs {
		if len(rdn.Attributes) != 1 {
			return nil, errors.New("every RDN must have one attribute")
		}
		v := rdn.Attributes[0].Value
		if !isPlaceholder(v) {
			if strings.ContainsAny(v, "{}") {
				return nil, fmt.Errorf("%q: a placeholder must be a whole value", v)
			}
			continue
		}
		if v != account && v != project {
			return nil, fmt.Errorf("%s: only %s and %s are allowed", v, account, project)
		}
		if _, dup := found[v]; dup {
			return nil, fmt.Errorf("%s appears twice", v)
		}
		found[v] = len(dn.RDNs) - i
	}
	if _, ok := found[account]; !ok {
		return nil, fmt.Errorf("must contain %s", account)
	}
	return found, nil
}

// checkRoleScope checks a rule's scope, which may end in "/*": it lies at or
// below the account's root and uses only placeholders of its group DN.
func checkRoleScope(where, scope, root string, inDN map[string]int) error {
	path := strings.TrimSuffix(scope, "/*")
	var inScope []string
	for k := range inDN {
		inScope = append(inScope, k)
	}
	if err := checkScopeTemplate("scope", path, inScope, []string{account}); err != nil {
		return fmt.Errorf("%s: %w", where, err)
	}
	if path != root && !below(root, path) {
		return fmt.Errorf("%s: scope %q must lie at or below %q", where, scope, root)
	}
	return nil
}

// checkScopeTemplate checks a scope with placeholders: every segment is a
// valid scope segment or one allowed placeholder, used once.
func checkScopeTemplate(name, template string, allowed, required []string) error {
	seen := map[string]bool{}
	segments := strings.Split(template, "/")
	if len(segments) > maxScopeSegments {
		return fmt.Errorf("%s %q has more than %d segments", name, template, maxScopeSegments)
	}
	for _, s := range segments {
		switch {
		case isPlaceholder(s):
			if !slices.Contains(allowed, s) || seen[s] {
				return fmt.Errorf("%s %q: %s must be allowed here and used once", name, template, s)
			}
			seen[s] = true
		case !ValidScopePath(s):
			return fmt.Errorf("%s %q: segment %q is neither a scope segment nor a placeholder", name, template, s)
		}
	}
	for _, r := range required {
		if !seen[r] {
			return fmt.Errorf("%s %q must contain %s", name, template, r)
		}
	}
	return nil
}

func isPlaceholder(s string) bool {
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")
}

// below reports whether template lies strictly below root, segment for segment.
func below(root, template string) bool {
	return strings.HasPrefix(template, root+"/")
}

// templatesOverlap reports whether one scope could match both templates.
func templatesOverlap(a, b string) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if !isPlaceholder(as[i]) && !isPlaceholder(bs[i]) && as[i] != bs[i] {
			return false
		}
	}
	return true
}
