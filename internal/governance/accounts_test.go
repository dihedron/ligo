package governance

import (
	"strings"
	"testing"
)

func accounts() *Accounts {
	return &Accounts{
		Jurisdiction:       "cloud/{account}",
		SourceJurisdiction: "cloud/{account}/app/{project}",
		TargetJurisdiction: "cloud/{account}/data/{tenancy}",
		LDAPGroups: AccountGroups{
			SearchBase: "ou=accounts,dc=corp,dc=internal",
			Roles: []AccountRole{
				{GroupDN: "cn=operators,ou={account},ou=accounts,dc=corp,dc=internal", Role: "operator", Jurisdiction: "cloud/{account}/*"},
				{GroupDN: "cn=approvers,ou={project},ou={account},ou=accounts,dc=corp,dc=internal", Role: "approver", Jurisdiction: "cloud/{account}/app/{project}"},
			},
		},
	}
}

func TestAccountsValid(t *testing.T) {
	if err := accounts().Validate(); err != nil {
		t.Fatal(err)
	}
	deeper := accounts() // the account at depth 5, the project at depth 7 (TN-19)
	deeper.LDAPGroups.SearchBase = "ou=accounts,o=corp,dc=internal"
	deeper.LDAPGroups.Roles = []AccountRole{
		{GroupDN: "cn=operators,ou=teams,ou={project},ou=units,ou={account},ou=accounts,o=corp,dc=internal", Role: "operator", Jurisdiction: "cloud/{account}/app/{project}"},
		{GroupDN: "cn=approvers,ou=units,ou={account},ou=accounts,o=corp,dc=internal", Role: "approver", Jurisdiction: "cloud/{account}/*"},
	}
	if err := deeper.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAccountsRefused(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Accounts)
		want   string
	}{
		{"no account in jurisdiction", func(a *Accounts) { a.Jurisdiction = "cloud/x" }, "must contain {account}"},
		{"unknown placeholder", func(a *Accounts) { a.SourceJurisdiction = "cloud/{account}/app/{team}" }, "{team}"},
		{"placeholder twice", func(a *Accounts) { a.SourceJurisdiction = "cloud/{account}/{account}/{project}" }, "used once"},
		{"partial placeholder", func(a *Accounts) { a.TargetJurisdiction = "cloud/{account}/data/x{tenancy}" }, "neither"},
		{"not below jurisdiction", func(a *Accounts) { a.TargetJurisdiction = "other/{account}/data/{tenancy}" }, "lie below"},
		{"one branch for both", func(a *Accounts) { a.TargetJurisdiction = "cloud/{account}/app/{tenancy}" }, "overlap"},
		{"bad search base", func(a *Accounts) { a.LDAPGroups.SearchBase = "not a dn" }, "search_base"},
		{"group outside the base", func(a *Accounts) {
			a.LDAPGroups.Roles[0].GroupDN = "cn=x,ou={account},dc=other"
		}, "below search_base"},
		{"group without account", func(a *Accounts) {
			a.LDAPGroups.Roles[0].GroupDN = "cn=x,ou=accounts,dc=corp,dc=internal"
		}, "must contain {account}"},
		{"partial value in a DN", func(a *Accounts) {
			a.LDAPGroups.Roles[0].GroupDN = "cn=ops-{account},ou={account},ou=accounts,dc=corp,dc=internal"
		}, "whole value"},
		{"tenancy in a DN", func(a *Accounts) {
			a.LDAPGroups.Roles[0].GroupDN = "cn={tenancy},ou={account},ou=accounts,dc=corp,dc=internal"
		}, "only {account} and {project}"},
		{"multi-valued RDN", func(a *Accounts) {
			a.LDAPGroups.Roles[0].GroupDN = "cn=x+uid=y,ou={account},ou=accounts,dc=corp,dc=internal"
		}, "one attribute"},
		{"account at another depth", func(a *Accounts) { // TN-19
			a.LDAPGroups.Roles[0].GroupDN = "cn=x,ou={account},ou=more,ou=accounts,dc=corp,dc=internal"
		}, "at depth"},
		{"project at another depth", func(a *Accounts) {
			a.LDAPGroups.Roles[0].GroupDN = "cn=x,ou=more,ou={project},ou={account},ou=accounts,dc=corp,dc=internal"
			a.LDAPGroups.Roles[0].Jurisdiction = "cloud/{account}/app/{project}"
			a.LDAPGroups.Roles[1].GroupDN = "cn=y,ou={project},ou=z,ou={account},ou=accounts,dc=corp,dc=internal"
		}, "at depth"},
		{"jurisdiction uses what the DN lacks", func(a *Accounts) {
			a.LDAPGroups.Roles[0].Jurisdiction = "cloud/{account}/app/{project}"
		}, "must be allowed"},
		{"jurisdiction of another tree", func(a *Accounts) {
			a.LDAPGroups.Roles[0].Jurisdiction = "other/{account}/*"
		}, "at or below"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := accounts()
			tc.change(a)
			err := a.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestMatchJurisdiction(t *testing.T) {
	tmpl := "cloud/{account}/data/{tenancy}"
	v, ok := MatchJurisdiction(tmpl, "cloud/acme/data/db01")
	if !ok || v["{account}"] != "acme" || v["{tenancy}"] != "db01" {
		t.Fatalf("got %v %v", v, ok)
	}
	for _, s := range []string{
		"cloud/acme/data",        // too short
		"cloud/acme/data/db01/x", // too long
		"cloud/acme/app/db01",    // another literal
		"cloud/a-b/data/c",       // TN-3: "-" would make {account}_{tenancy} ambiguous
		"cloud/acme/data/b-c",    // TN-3
		"cloud/1acme/data/db01",  // not a letter first
	} {
		if _, ok := MatchJurisdiction(tmpl, s); ok {
			t.Errorf("%s matched", s)
		}
	}
	if got := ExpandTemplate("{account}_{tenancy}", v); got != "acme_db01" {
		t.Errorf("got %s", got)
	}
}

func TestAccountOf(t *testing.T) {
	a := accounts()
	for jurisdiction, want := range map[string]string{
		"cloud/acme":             "acme",
		"cloud/acme/app/app01":   "acme",
		"cloud/globex/data/db02": "globex",
		// outside the grammar, but in an account's place: no such account can
		// be registered, so the registry refuses it instead of it going unmanaged
		"cloud/a-b/app/x": "a-b",
		"cloud/ACME":      "ACME",
	} {
		if got, ok := a.AccountOf(jurisdiction); !ok || got != want {
			t.Errorf("%s: got %q %v", jurisdiction, got, ok)
		}
	}
	for _, jurisdiction := range []string{"dc/corp-prod", "cloud", "cloudy/acme"} {
		if got, ok := a.AccountOf(jurisdiction); ok {
			t.Errorf("%s: account %q", jurisdiction, got)
		}
	}
	if got, ok := (*Accounts)(nil).AccountOf("cloud/acme"); ok {
		t.Errorf("no accounts configured: account %q", got)
	}
}

func TestConforms(t *testing.T) {
	a := accounts()
	for _, c := range []struct {
		jurisdiction   string
		source, target bool
	}{
		{"dc/corp-prod/ledger", true, true}, // not account-managed
		{"cloud/acme/app/app01", true, false},
		{"cloud/acme/data/db01", false, true},
		{"cloud/acme", false, false},
		{"cloud/acme/other/x", false, false},
		{"cloud/acme/app/app01/deeper", false, false},
		{"cloud/a-b/app/app01", false, false},
		{"cloud/acme/app/App01", false, false},
	} {
		if got := a.SourceConforms(c.jurisdiction); got != c.source {
			t.Errorf("source %s: %v", c.jurisdiction, got)
		}
		if got := a.TargetConforms(c.jurisdiction); got != c.target {
			t.Errorf("target %s: %v", c.jurisdiction, got)
		}
	}
	var none *Accounts
	if !none.SourceConforms("cloud/a-b") || !none.TargetConforms("cloud/a-b") {
		t.Error("no accounts configured: every jurisdiction conforms")
	}
}

func TestNamespaceOf(t *testing.T) {
	a := accounts()
	if got, ok := a.NamespaceOf("{account}_{tenancy}", "cloud/acme/data/db01"); !ok || got != "acme_db01" {
		t.Errorf("got %q %v", got, ok)
	}
	for _, jurisdiction := range []string{"cloud/acme/app/db01", "dc/corp-prod/ledger", "cloud/a-b/data/c"} {
		if got, ok := a.NamespaceOf("{account}_{tenancy}", jurisdiction); ok {
			t.Errorf("%s: %q", jurisdiction, got)
		}
	}
}

func TestCheckNamespaceTemplate(t *testing.T) {
	a := accounts()
	for _, ok := range []string{"{account}_{tenancy}", "{tenancy}_{account}", "t_{account}_{tenancy}", "{account}__{tenancy}", "{account}_x_{tenancy}"} {
		if err := a.CheckNamespaceTemplate(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"fixed",
		"{account}",               // two tenancies of an account would share it
		"{tenancy}",               // two accounts would share it
		"{account}{tenancy}",      // ab + c, a + bc
		"{account}x{tenancy}",     // a separator the values can hold
		"{account}_{project}",     // not of a target's jurisdiction
		"{account}_{tenancy}_{x}", // unknown
		"{account}_{account}",     // twice, and no tenancy
		"{account}_{tenancy}_{tenancy}",
	} {
		if err := a.CheckNamespaceTemplate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// What matches a template expands back to the jurisdiction, with values in the
// grammar, and AccountOf agrees.
func FuzzMatchJurisdiction(f *testing.F) {
	for _, s := range []string{"cloud/acme/data/db01", "cloud/acme", "cloud/a-b/data/c", "", "/", "cloud//data/x", "cloud/{account}/data/x", "cloud/ACME/data/x"} {
		f.Add(s)
	}
	a := accounts()
	f.Fuzz(func(t *testing.T, jurisdiction string) {
		values, ok := MatchJurisdiction(a.TargetJurisdiction, jurisdiction)
		account, managed := a.AccountOf(jurisdiction)
		if !ok {
			return
		}
		for k, v := range values {
			if !ValidAccountValue(v) {
				t.Fatalf("%s: %s = %q is outside the grammar", jurisdiction, k, v)
			}
		}
		if got := ExpandTemplate(a.TargetJurisdiction, values); got != jurisdiction {
			t.Fatalf("%s expands back to %s", jurisdiction, got)
		}
		if !managed || account != values["{account}"] {
			t.Fatalf("%s: AccountOf %q %v", jurisdiction, account, managed)
		}
		if !a.TargetConforms(jurisdiction) {
			t.Fatalf("%s matches but does not conform", jurisdiction)
		}
	})
}

// Two tenancies never share a namespace: the reason values have no mapping.
func FuzzNamespaceInjective(f *testing.F) {
	f.Add("a", "b", "a", "b")
	f.Add("ab", "c", "a", "bc")
	f.Add("a-b", "c", "a", "b-c")
	a := accounts()
	f.Fuzz(func(t *testing.T, a1, t1, a2, t2 string) {
		n1, ok1 := a.NamespaceOf("{account}_{tenancy}", "cloud/"+a1+"/data/"+t1)
		n2, ok2 := a.NamespaceOf("{account}_{tenancy}", "cloud/"+a2+"/data/"+t2)
		if ok1 && ok2 && n1 == n2 && (a1 != a2 || t1 != t2) {
			t.Fatalf("%s/%s and %s/%s share %s", a1, t1, a2, t2, n1)
		}
	})
}

// groupRules are the rules of the spec's example (.specs/ligo-tenancy.md §4).
func groupRules(t testing.TB) *GroupRules {
	t.Helper()
	const base = ",ou=accounts,dc=corp,dc=internal"
	r, err := (&AccountGroups{SearchBase: "ou=accounts,dc=corp,dc=internal", Roles: []AccountRole{
		{GroupDN: "cn=operators,ou={account}" + base, Role: "operator", Jurisdiction: "cloud/{account}/*"},
		{GroupDN: "cn=approvers,ou={account}" + base, Role: "approver", Jurisdiction: "cloud/{account}/*"},
		{GroupDN: "cn=approvers,ou={project},ou={account}" + base, Role: "approver", Jurisdiction: "cloud/{account}/app/{project}"},
		{GroupDN: "cn=breakglass,ou={account}" + base, Role: "break_glass", Jurisdiction: "cloud/{account}/*"},
	}}).Compile()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestGroupRulesMatch: TN-7, TN-9 and TN-18, RDN by RDN and never as text.
func TestGroupRulesMatch(t *testing.T) {
	r := groupRules(t)
	const base = ",ou=accounts,dc=corp,dc=internal"
	for dn, want := range map[string]string{
		"cn=approvers,ou=acme" + base:                          "acme approver cloud/acme/*",
		"cn=operators,ou=acme" + base:                          "acme operator cloud/acme/*",
		"cn=approvers,ou=app01,ou=acme" + base:                 "acme approver cloud/acme/app/app01",
		"CN=Approvers,OU=ACME,OU=Accounts,DC=corp,DC=INTERNAL": "acme approver cloud/acme/*",
		`cn=approvers,ou=acme\,ou=globex` + base:               "", // one value holding a comma
		"cn=x,cn=approvers,ou=acme" + base:                     "", // an extra RDN that no rule has
		"ou=acme" + base:                                       "", // a missing RDN
		"cn=viewers,ou=acme" + base:                            "", // no such rule
		"cn=approvers,ou=a-b" + base:                           "", // outside the grammar
		"cn=approvers,ou=acme+cn=x" + base:                     "", // a multi-valued RDN
		"cn=approvers,cn=acme" + base:                          "", // another attribute
		"cn=approvers,ou=acme,ou=other,dc=corp":                "", // another base
		"cn=approvers,ou=\u212Aacme" + base:                    "", // the Kelvin sign folds to k in Unicode
		"cn=brea\u212Aglass,ou=acme" + base:                    "",
		"cn=breakglass,ou=acme" + base:                         "acme break_glass cloud/acme/*",
		"not a dn":                                             "",
		"":                                                     "",
	} {
		var got []string
		for _, m := range r.Match(dn) {
			got = append(got, m.Account+" "+m.Role+" "+m.Jurisdiction)
		}
		if strings.Join(got, ";") != want {
			t.Errorf("%q: %v, want %q", dn, got, want)
		}
	}
	if got := r.Match("cn=approvers,ou=\u212Aacme" + base); len(got) != 0 {
		t.Errorf("the Kelvin sign read as an account: %v", got)
	}
	var none *GroupRules
	if got := none.Match("cn=approvers,ou=acme" + base); got != nil {
		t.Errorf("no rules: %v", got)
	}
}

// FuzzGroupRulesMatch: whatever the directory holds, a match names a valid
// account and a jurisdiction of that account alone (TN-9).
func FuzzGroupRulesMatch(f *testing.F) {
	const base = ",ou=accounts,dc=corp,dc=internal"
	for _, s := range []string{"cn=approvers,ou=acme" + base, `cn=approvers,ou=acme\,ou=globex` + base, "cn=approvers,ou=ACME" + base,
		"cn=approvers,ou=app01,ou=acme" + base, "cn=approvers,ou=\u212A" + base, "#04", "ou=#6162" + base, "cn=approvers,ou=#6163" + base} {
		f.Add(s)
	}
	r := groupRules(f)
	f.Fuzz(func(t *testing.T, dn string) {
		for _, m := range r.Match(dn) {
			if !ValidAccountValue(m.Account) || !strings.HasPrefix(m.Jurisdiction, "cloud/"+m.Account+"/") {
				t.Errorf("%q: %+v", dn, m)
			}
			if strings.ContainsAny(m.Jurisdiction, "{}") {
				t.Errorf("%q: a placeholder left in %q", dn, m.Jurisdiction)
			}
		}
	})
}

// TestAccountSourceExtractor: the path_regex the documentation gives for
// accounts is one that startup accepts, and it yields the jurisdiction of a project.
func TestAccountSourceExtractor(t *testing.T) {
	e, err := NewPathTemplateExtractor(`^/acct/([a-z0-9]+)/project/([a-z0-9]+)/`, `cloud/${1}/app/${2}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.SourceJurisdiction(`^spiffe://prod\.internal/acct/acme/project/app01/sa/x$`, "prod.internal")
	if err != nil || got != "cloud/acme/app/app01" {
		t.Errorf("%q, %v", got, err)
	}
	if _, err := NewPathTemplateExtractor(`^/acct/([a-z][a-z0-9]*)/project/([a-z0-9]+)/`, `cloud/${1}/app/${2}`); err == nil {
		t.Error("a group the extractor cannot reason about is accepted")
	}
}
