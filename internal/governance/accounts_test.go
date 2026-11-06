package governance

import (
	"strings"
	"testing"
)

func accounts() *Accounts {
	return &Accounts{
		Scope:       "cloud/{account}",
		SourceScope: "cloud/{account}/app/{project}",
		TargetScope: "cloud/{account}/data/{tenancy}",
		LDAPGroups: AccountGroups{
			SearchBase: "ou=accounts,dc=corp,dc=internal",
			Roles: []AccountRole{
				{GroupDN: "cn=operators,ou={account},ou=accounts,dc=corp,dc=internal", Role: "operator", Scope: "cloud/{account}/*"},
				{GroupDN: "cn=approvers,ou={project},ou={account},ou=accounts,dc=corp,dc=internal", Role: "approver", Scope: "cloud/{account}/app/{project}"},
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
		{GroupDN: "cn=operators,ou=teams,ou={project},ou=units,ou={account},ou=accounts,o=corp,dc=internal", Role: "operator", Scope: "cloud/{account}/app/{project}"},
		{GroupDN: "cn=approvers,ou=units,ou={account},ou=accounts,o=corp,dc=internal", Role: "approver", Scope: "cloud/{account}/*"},
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
		{"no account in scope", func(a *Accounts) { a.Scope = "cloud/x" }, "must contain {account}"},
		{"unknown placeholder", func(a *Accounts) { a.SourceScope = "cloud/{account}/app/{team}" }, "{team}"},
		{"placeholder twice", func(a *Accounts) { a.SourceScope = "cloud/{account}/{account}/{project}" }, "used once"},
		{"partial placeholder", func(a *Accounts) { a.TargetScope = "cloud/{account}/data/x{tenancy}" }, "neither"},
		{"not below scope", func(a *Accounts) { a.TargetScope = "other/{account}/data/{tenancy}" }, "lie below"},
		{"one branch for both", func(a *Accounts) { a.TargetScope = "cloud/{account}/app/{tenancy}" }, "overlap"},
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
			a.LDAPGroups.Roles[0].Scope = "cloud/{account}/app/{project}"
			a.LDAPGroups.Roles[1].GroupDN = "cn=y,ou={project},ou=z,ou={account},ou=accounts,dc=corp,dc=internal"
		}, "at depth"},
		{"scope uses what the DN lacks", func(a *Accounts) {
			a.LDAPGroups.Roles[0].Scope = "cloud/{account}/app/{project}"
		}, "must be allowed"},
		{"scope of another tree", func(a *Accounts) {
			a.LDAPGroups.Roles[0].Scope = "other/{account}/*"
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

func TestMatchScope(t *testing.T) {
	tmpl := "cloud/{account}/data/{tenancy}"
	v, ok := MatchScope(tmpl, "cloud/acme/data/db01")
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
		if _, ok := MatchScope(tmpl, s); ok {
			t.Errorf("%s matched", s)
		}
	}
	if got := ExpandTemplate("{account}_{tenancy}", v); got != "acme_db01" {
		t.Errorf("got %s", got)
	}
}

func TestAccountOf(t *testing.T) {
	a := accounts()
	for scope, want := range map[string]string{
		"cloud/acme":             "acme",
		"cloud/acme/app/app01":   "acme",
		"cloud/globex/data/db02": "globex",
	} {
		if got, ok := a.AccountOf(scope); !ok || got != want {
			t.Errorf("%s: got %q %v", scope, got, ok)
		}
	}
	for _, scope := range []string{"dc/corp-prod", "cloud", "cloud/a-b/app/x"} {
		if got, ok := a.AccountOf(scope); ok {
			t.Errorf("%s: account %q", scope, got)
		}
	}
}
