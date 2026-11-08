package authz

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/governance"
)

const groups = ",ou=groups,dc=corp,dc=internal"

// authorizer is built from the authorization bindings of the §8.1 example.
func authorizer(t *testing.T, extra ...config.RoleBinding) *Authorizer {
	t.Helper()
	data, err := os.ReadFile("../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc := regexp.MustCompile(`<64-hex-sha256-of-[a-z-]+>`).ReplaceAllString(string(data), strings.Repeat("ab", 32))
	cfg, err := config.Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(append(cfg.Authorization.Bindings, extra...))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func ldap(names ...string) Principal {
	p := Principal{Name: "user"}
	for _, n := range names {
		p.Groups = append(p.Groups, "cn="+n+groups)
	}
	return p
}

func TestViewer(t *testing.T) {
	g := authorizer(t).For(ldap("ligo-viewers"))
	if !g.Sees("dc/corp-prod") || !g.Sees("cloud/fin-01/payments") {
		t.Error("viewer on * does not see every jurisdiction")
	}
	if g.ActsFor("dc/corp-prod", "") || g.CanApprove("dc/corp-prod") {
		t.Error("viewer acts or approves")
	}
	if !g.Viewer() || (Grants{{Role: config.RoleBreakGlass}}).Viewer() || Grants(nil).Viewer() {
		t.Error("Viewer: any role but break_glass alone")
	}
}

func TestOperatorJurisdictions(t *testing.T) {
	a := authorizer(t)
	ledger := a.For(ldap("ledger-dbas"))
	if !ledger.ActsFor("dc/corp-prod/ledger", "oracle-prod") || ledger.ActsFor("dc/corp-prod", "") || ledger.ActsFor("dc/corp-prod/orders", "") {
		t.Error("ledger operator jurisdictions")
	}
	if !ledger.Sees("dc/corp-prod/ledger") || ledger.Sees("dc/corp-prod") {
		t.Error("ledger operator visibility")
	}
	prod := a.For(ldap("ligo-operators-prod"))
	if !prod.ActsFor("dc/corp-prod", "") || prod.ActsFor("dc/corp-prod/ledger", "") {
		t.Error("an exact pattern must not cover the jurisdictions below it")
	}
	// a binding is visible through any of its jurisdictions (§7.2.2)
	if !prod.Sees("cloud/fin-01/payments", "dc/corp-prod/ledger", "dc/corp-prod") {
		t.Error("platform owner does not see a binding on its platform")
	}
	leads := a.For(ldap("ledger-leads"))
	if !leads.CanApprove("dc/corp-prod/ledger") || leads.ActsFor("dc/corp-prod/ledger", "") {
		t.Error("approver rights")
	}
}

func TestDNCase(t *testing.T) {
	g := authorizer(t).For(Principal{Name: "u", Groups: []string{"CN=Ledger-DBAs,OU=Groups,DC=corp,DC=internal"}})
	if !g.ActsFor("dc/corp-prod/ledger", "") {
		t.Error("group DN matching is case-sensitive")
	}
}

// TestTrustedAutomation covers ADR-11 and the platform part of AC-28.
func TestTrustedAutomation(t *testing.T) {
	a := authorizer(t)
	awx := Principal{Name: "spiffe://prod.internal/ns/automation-prod/sa/awx-runner-db-team", SPIFFEID: "spiffe://prod.internal/ns/automation-prod/sa/awx-runner-db-team"}
	g := a.For(awx)
	d := g.Delegates("dc/corp-prod/ledger", "oracle-prod")
	if d == nil || d.ApprovalReference == nil || !d.ApprovalReference.MatchString("CHG0012345") || d.ApprovalReference.MatchString("CHG12") {
		t.Fatalf("delegation on oracle-prod: %+v", d)
	}
	if d.RateLimit == nil || d.RateLimit.APIRPS != 50 {
		t.Errorf("rate limit: %+v", d.RateLimit)
	}
	if g.Delegates("dc/corp-prod/ledger", "oracle-test-dynamic") != nil || g.ActsFor("dc/corp-prod/ledger", "oracle-test-dynamic") {
		t.Error("delegation outside its platforms")
	}
	if g.Delegates("cloud/fin-01/payments", "oracle-prod") != nil {
		t.Error("delegation outside its jurisdictions")
	}
	if !g.ActsFor("dc/corp-prod/ledger", "oracle-prod") || !g.ActsFor("dc/corp-prod/ledger", "") || g.CanApprove("dc/corp-prod/ledger") {
		t.Error("trusted_automation operator rights")
	}
	// the same identity as an LDAP group name never matches
	if a.For(Principal{Name: "x", Groups: []string{awx.SPIFFEID}}).ActsFor("dc/corp-prod/ledger", "") {
		t.Error("a SPIFFE ID matched as a group")
	}
	// a SPIFFE principal never matches LDAP groups
	if a.For(Principal{Name: "spiffe://prod.internal/x", SPIFFEID: "spiffe://prod.internal/x", Groups: []string{"cn=ligo-viewers" + groups}}).Sees("dc/corp-prod") {
		t.Error("a SPIFFE principal matched an LDAP group")
	}
}

func TestBreakGlassAlone(t *testing.T) {
	g := authorizer(t).For(ldap("ligo-breakglass-prod"))
	if !g.BreakGlass("dc/corp-prod/ledger") || g.BreakGlass("cloud/fin-01/payments") {
		t.Error("break_glass jurisdictions")
	}
	if g.Sees("dc/corp-prod/ledger") || g.ActsFor("dc/corp-prod/ledger", "") {
		t.Error("break_glass alone grants visibility or operator rights")
	}
}

func TestFullAccess(t *testing.T) {
	a := authorizer(t, config.RoleBinding{LDAPGroupDN: "cn=ligo-admins" + groups, Role: config.RoleFullAccess, Jurisdictions: []string{"*"}})
	g := a.For(ldap("ligo-admins"))
	if !g.FullAccess() || !g.ActsFor("sec/infosec", "x") || !g.CanApprove("dc/corp-prod/ledger") || !g.Sees("any/jurisdiction") {
		t.Error("admin.full_access")
	}
	if g.BreakGlass("dc/corp-prod") {
		t.Error("admin.full_access is not break_glass")
	}
	if a.For(ldap("ligo-viewers")).FullAccess() {
		t.Error("viewer has full access")
	}
}

// TestVisible: a resource is visible through a role on its jurisdictions, or
// beyond them as its visibility says (§7.2.4).
func TestVisible(t *testing.T) {
	gs := Grants{{Role: config.RoleOperator, Jurisdictions: []string{"dc/corp-prod/ledger"}}}
	for _, tc := range []struct {
		jurisdiction, mode string
		visibleTo          []string
		want               bool
	}{
		{"dc/corp-prod/ledger", "PRIVATE", nil, true},
		{"cloud/fin-01/payments", "PRIVATE", nil, false},
		{"cloud/fin-01/payments", "LISTED", []string{"dc/corp-prod/*"}, true},
		{"cloud/fin-01/payments", "LISTED", []string{"dc/corp-test/*"}, false},
		{"cloud/fin-01/payments", "PUBLIC", nil, true},
	} {
		if got := gs.Visible([]string{tc.jurisdiction}, tc.mode, tc.visibleTo); got != tc.want {
			t.Errorf("%+v: %t", tc, got)
		}
	}
	if (Grants{{Role: config.RoleBreakGlass, Jurisdictions: []string{"*"}}}).Visible([]string{"x"}, "PUBLIC", nil) {
		t.Error("break_glass alone sees a PUBLIC resource")
	}
}

// account_admin manages the registry and nothing else (spec §7.3).
func TestAccountAdmin(t *testing.T) {
	admin := Grants{{Role: config.RoleAccountAdmin}}
	if !admin.AccountAdmin() {
		t.Error("account_admin is no account admin")
	}
	if !(Grants{{Role: config.RoleFullAccess, Jurisdictions: []string{"*"}}}).AccountAdmin() {
		t.Error("admin.full_access includes account_admin")
	}
	if (Grants{{Role: config.RoleOperator, Jurisdictions: []string{"*"}}}).AccountAdmin() {
		t.Error("an operator is no account admin")
	}
	if admin.Viewer() {
		t.Error("account_admin alone reads resources")
	}
	if admin.Sees("cloud/acme") || admin.ActsFor("cloud/acme", "") || admin.CanApprove("cloud/acme") || admin.Operator("cloud/acme") {
		t.Error("account_admin alone reaches a jurisdiction")
	}
	if admin.Visible([]string{"cloud/acme"}, "PUBLIC", nil) {
		t.Error("account_admin alone sees PUBLIC resources")
	}
}

func TestInJurisdictions(t *testing.T) {
	const account = "cloud/acme/*"
	for _, c := range []struct {
		gs   Grants
		want bool
	}{
		{Grants{{Role: config.RoleViewer, Jurisdictions: []string{"*"}}}, true},
		{Grants{{Role: config.RoleOperator, Jurisdictions: []string{"cloud/*"}}}, true},
		{Grants{{Role: config.RoleApprover, Jurisdictions: []string{"cloud/acme/*"}}}, true},
		{Grants{{Role: config.RoleOperator, Jurisdictions: []string{"cloud/acme/app/p1"}}}, true},
		{Grants{{Role: config.RoleFullAccess, Jurisdictions: []string{"*"}}}, true},
		{Grants{{Role: config.RoleOperator, Jurisdictions: []string{"cloud/globex/*"}}}, false},
		{Grants{{Role: config.RoleOperator, Jurisdictions: []string{"cloud/acmesub/*"}}}, false},
		{Grants{{Role: config.RoleBreakGlass, Jurisdictions: []string{"*"}}}, false},
		{Grants{{Role: config.RoleAccountAdmin}}, false},
		{nil, false},
	} {
		if got := c.gs.InJurisdictions(account); got != c.want {
			t.Errorf("%+v: %v", c.gs, got)
		}
	}
}

// TestAccountGroups: TN-7, TN-8 and TN-18: a group gives its rule's role on its
// account only while that account is active, added to the static bindings.
func TestAccountGroups(t *testing.T) {
	rules, err := (&governance.AccountGroups{SearchBase: "ou=accounts,dc=corp", Roles: []governance.AccountRole{
		{GroupDN: "cn=approvers,ou={account},ou=accounts,dc=corp", Role: config.RoleApprover, Jurisdiction: "cloud/{account}/*"},
		{GroupDN: "cn=approvers,ou={project},ou={account},ou=accounts,dc=corp", Role: config.RoleApprover, Jurisdiction: "cloud/{account}/app/{project}"},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	active := map[string]bool{"acme": true, "globex": true}
	a := authorizer(t)
	a.UseAccounts(rules, func(name string) bool { return active[name] })
	account := Principal{Name: "u", AccountGroups: []string{"cn=approvers,ou=acme,ou=accounts,dc=corp"}}
	gs := a.For(account)
	if !gs.CanApprove("cloud/acme/data/db01") || gs.CanApprove("cloud/globex/data/db01") {
		t.Errorf("TN-7: %+v", gs)
	}
	project := a.For(Principal{Name: "u", AccountGroups: []string{"cn=approvers,ou=app01,ou=acme,ou=accounts,dc=corp"}})
	if !project.CanApprove("cloud/acme/app/app01") || project.CanApprove("cloud/acme/app/app02") || project.CanApprove("cloud/acme/data/db01") {
		t.Errorf("TN-18: %+v", project)
	}
	static := ldap("ligo-viewers")
	static.AccountGroups = account.AccountGroups
	if gs := a.For(static); len(gs) != len(a.For(ldap("ligo-viewers")))+1 {
		t.Errorf("not the union: %+v", gs)
	}
	if gs := a.For(Principal{Name: "u", AccountGroups: []string{"cn=approvers,ou=nosuch,ou=accounts,dc=corp"}}); len(gs) != 0 {
		t.Errorf("an unregistered account: %+v", gs)
	}
	if gs := a.For(Principal{SPIFFEID: "spiffe://x/y", AccountGroups: account.AccountGroups}); len(gs) != 0 {
		t.Errorf("a SPIFFE principal: %+v", gs)
	}
	active["acme"] = false
	if gs := a.For(account); len(gs) != 0 {
		t.Errorf("TN-8, retired: %+v", gs)
	}
}
