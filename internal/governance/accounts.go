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
