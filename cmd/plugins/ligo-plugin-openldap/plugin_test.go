package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/go-ldap/ldap/v3"
	"google.golang.org/grpc/codes"
)

const (
	ou        = "ou=ligo-accounts,dc=ligo,dc=lab"
	principal = "svc_abcdefghijklmnop"
	dn        = "uid=" + principal + "," + ou
	bindingID = "01a1890a-b363-7e0c-b649-384f55a42e50"
	mine      = "ligo:binding_id=" + bindingID
	other     = "ligo:binding_id=01a1890a-b363-7e0c-b649-000000000000"
)

// fake is a directory in memory: entries by DN, their description values.
type fake struct {
	entries   map[string][]string
	passwords map[string]string
	calls     []string
	readErr   error
	addErr    error
	passErr   error
	delErr    error
	closed    int
}

func (f *fake) read(entry string) (bool, []string, error) {
	f.calls = append(f.calls, "read")
	if f.readErr != nil {
		return false, nil, f.readErr
	}
	d, ok := f.entries[entry]
	return ok, d, nil
}

func (f *fake) add(entry, _, tag string) error {
	f.calls = append(f.calls, "add")
	if f.addErr != nil {
		err := f.addErr
		f.addErr = nil
		return err
	}
	f.entries[entry] = []string{tag}
	return nil
}

func (f *fake) setPassword(entry, password string) error {
	f.calls = append(f.calls, "password")
	if f.passErr != nil {
		return f.passErr
	}
	f.passwords[entry] = password
	return nil
}

func (f *fake) remove(entry string) error {
	f.calls = append(f.calls, "delete")
	if f.delErr != nil {
		return f.delErr
	}
	delete(f.entries, entry)
	return nil
}

func (f *fake) close() { f.closed++ }

func testPlugin(f *fake, dialErr error) *plugin {
	return &plugin{instances: map[string]*instance{"ldap-prod": {serviceOU: ou, dial: func(context.Context) (directory, error) {
		if dialErr != nil {
			return nil, dialErr
		}
		return f, nil
	}}}}
}

func newFake(entries map[string][]string) *fake {
	if entries == nil {
		entries = map[string][]string{}
	}
	return &fake{entries: entries, passwords: map[string]string{}}
}

func ensure(p *plugin, name string, rotate bool) (*pluginv1.IdentityArtifact, error) {
	r, err := p.EnsureIdentity(context.Background(), &pluginv1.EnsureIdentityRequest{Instance: "ldap-prod",
		Binding: &pluginv1.BindingContext{BindingId: bindingID, DerivedPrincipalName: name, RotateStaticSecrets: rotate}})
	return r.GetArtifact(), err
}

func codeOf(err error) (codes.Code, string, bool) {
	c, d := pluginsdk.FromError(err)
	return c, d.GetCode(), d.GetRetryable()
}

// TestEnsure is the table of §5: what each state of the entry does.
func TestEnsure(t *testing.T) {
	for name, tc := range map[string]struct {
		entries map[string][]string
		rotate  bool
		calls   string
		secret  bool
		code    string
	}{
		"absent, rotation":    {nil, true, "read add password", true, ""},
		"absent, no rotation": {nil, false, "read add password", true, ""},
		"ours, rotation":      {map[string][]string{dn: {mine}}, true, "read password", true, ""},
		"ours, no rotation":   {map[string][]string{dn: {mine}}, false, "read", false, ""},
		"ours among others":   {map[string][]string{dn: {"a note", mine}}, false, "read", false, ""},
		"foreign":             {map[string][]string{dn: {other}}, true, "read", false, "RESOURCE_OWNED_BY_OTHER_BINDING"},
		"untagged":            {map[string][]string{dn: nil}, true, "read", false, "RESOURCE_OWNED_BY_OTHER_BINDING"},
		"tag as a prefix":     {map[string][]string{dn: {mine + "0"}}, true, "read", false, "RESOURCE_OWNED_BY_OTHER_BINDING"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(tc.entries)
			a, err := ensure(testPlugin(f, nil), principal, tc.rotate)
			if got := strings.Join(f.calls, " "); got != tc.calls {
				t.Errorf("calls %q, want %q", got, tc.calls)
			}
			if f.closed != 1 {
				t.Errorf("closed %d times", f.closed)
			}
			if tc.code != "" {
				if c, code, retry := codeOf(err); c != codes.FailedPrecondition || code != tc.code || retry {
					t.Errorf("error %v %s %v", c, code, retry)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if a.GetMode() != pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR || a.GetPrincipalId() != principal || a.GetDistinguishedName() != dn ||
				len(a.GetGroups()) != 0 || len(a.GetMetadata()) != 0 {
				t.Errorf("artifact %+v", a)
			}
			if !tc.secret {
				if a.GetStaticSecret() != nil || !a.GetSecretUnchanged() {
					t.Errorf("no rotation returned a secret: %v %v", a.GetStaticSecret() != nil, a.GetSecretUnchanged())
				}
				return
			}
			s := a.GetStaticSecret()
			if a.GetSecretUnchanged() || s.GetUsername() != principal || len(s.GetPassword()) != 40 || f.passwords[dn] != s.GetPassword() {
				t.Errorf("secret: unchanged %v, user %s, %d characters, stored %v", a.GetSecretUnchanged(), s.GetUsername(), len(s.GetPassword()), f.passwords[dn] == s.GetPassword())
			}
		})
	}
}

// TestEnsureRace: an Add that finds the entry reads it again, once, and
// follows the table; a second conflict is an error.
func TestEnsureRace(t *testing.T) {
	exists := ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("exists"))
	f := newFake(nil)
	f.addErr = exists
	p := testPlugin(f, nil)
	// the concurrent call's entry appears between the read and the add
	f.readErr = nil
	racing := &racingFake{fake: f, tag: mine}
	p.instances["ldap-prod"].dial = func(context.Context) (directory, error) { return racing, nil }
	a, err := ensure(p, principal, true)
	if err != nil || a.GetStaticSecret() == nil {
		t.Fatalf("after a race: %v %+v", err, a)
	}
	if got := strings.Join(f.calls, " "); got != "read add read password" {
		t.Errorf("calls %q", got)
	}

	racing = &racingFake{fake: newFake(nil), tag: other}
	racing.addErr = exists
	if _, err := ensure(p, principal, true); !hasCode(err, "RESOURCE_OWNED_BY_OTHER_BINDING") {
		t.Errorf("another binding won the race: %v", err)
	}

	stubborn := newFake(nil)
	p.instances["ldap-prod"].dial = func(context.Context) (directory, error) { return &alwaysExists{stubborn}, nil }
	if _, err := ensure(p, principal, true); !hasCode(err, "DIRECTORY_REJECTED") {
		t.Errorf("conflict twice: %v", err)
	}
}

func hasCode(err error, want string) bool {
	_, code, _ := codeOf(err)
	return code == want
}

// racingFake adds the winner's entry when an Add is about to conflict.
type racingFake struct {
	*fake
	tag string
}

func (r *racingFake) add(entry, principal, tag string) error {
	if r.addErr != nil {
		r.entries[entry] = []string{r.tag}
	}
	return r.fake.add(entry, principal, tag)
}

// alwaysExists finds nothing on a read and a conflict on every Add.
type alwaysExists struct{ *fake }

func (a *alwaysExists) add(string, string, string) error {
	return ldap.NewError(ldap.LDAPResultEntryAlreadyExists, errors.New("exists"))
}

// TestPrincipalGrammar: nothing outside the grammar reaches the directory
// (OL-7, §5.8 rule 3).
func TestPrincipalGrammar(t *testing.T) {
	for _, name := range []string{"", "svc_abc,ou=admins", "uid=x", "svc)(uid=*", `svc\2c`, "SVC_ABC", "1svc", "svc abc", "svc_abcdefghijklmnopq", "svc_é"} {
		f := newFake(nil)
		dialed := false
		p := testPlugin(f, nil)
		p.instances["ldap-prod"].dial = func(context.Context) (directory, error) { dialed = true; return f, nil }
		_, err := ensure(p, name, true)
		if c, code, retry := codeOf(err); c != codes.InvalidArgument || code != "INVALID_PRINCIPAL" || retry || dialed {
			t.Errorf("ensure %q: %v %s retry=%v dialed=%v", name, c, code, retry, dialed)
		}
		_, err = p.CleanupIdentity(context.Background(), &pluginv1.CleanupIdentityRequest{Instance: "ldap-prod",
			Binding: &pluginv1.BindingContext{BindingId: bindingID, DerivedPrincipalName: name}})
		if !hasCode(err, "INVALID_PRINCIPAL") || dialed {
			t.Errorf("cleanup %q: %v dialed=%v", name, err, dialed)
		}
	}
	if _, err := testPlugin(newFake(nil), nil).EnsureIdentity(context.Background(), &pluginv1.EnsureIdentityRequest{Instance: "ldap-prod",
		Binding: &pluginv1.BindingContext{DerivedPrincipalName: principal}}); !hasCode(err, "INVALID_BINDING") {
		t.Errorf("no binding id: %v", err)
	}
}

// TestCleanup: absent succeeds, ours goes, foreign stays (§5.8 rules 1, 2);
// the previous artifact is not needed (AC-10).
func TestCleanup(t *testing.T) {
	for name, tc := range map[string]struct {
		entries map[string][]string
		calls   string
		skipped bool
	}{
		"absent":   {nil, "read", false},
		"ours":     {map[string][]string{dn: {mine}}, "read delete", false},
		"foreign":  {map[string][]string{dn: {other}}, "read", true},
		"untagged": {map[string][]string{dn: nil}, "read", true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(tc.entries)
			r, err := testPlugin(f, nil).CleanupIdentity(context.Background(), &pluginv1.CleanupIdentityRequest{Instance: "ldap-prod",
				Binding: &pluginv1.BindingContext{BindingId: bindingID, DerivedPrincipalName: principal}})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(f.calls, " "); got != tc.calls || r.GetSkippedNotOwner() != tc.skipped || f.closed != 1 {
				t.Errorf("calls %q, skipped %v, closed %d", got, r.GetSkippedNotOwner(), f.closed)
			}
		})
	}
	// deleted by someone else between the read and the delete: done
	f := newFake(map[string][]string{dn: {mine}})
	f.delErr = ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("gone"))
	if _, err := testPlugin(f, nil).CleanupIdentity(context.Background(), &pluginv1.CleanupIdentityRequest{Instance: "ldap-prod",
		Binding: &pluginv1.BindingContext{BindingId: bindingID, DerivedPrincipalName: principal}}); err != nil {
		t.Errorf("gone meanwhile: %v", err)
	}
}

// TestErrors is §6 (OL-10): the code, the retryability, a fixed message
// without the directory's diagnostics.
func TestErrors(t *testing.T) {
	const diagnostic = "secret-diagnostic"
	cause := errors.New(diagnostic)
	for _, tc := range []struct {
		err   error
		grpc  codes.Code
		code  string
		retry bool
	}{
		{ldap.NewError(ldap.ErrorNetwork, cause), codes.Unavailable, "DIRECTORY_UNAVAILABLE", true},
		{fmt.Errorf("dial: %w", cause), codes.Unavailable, "DIRECTORY_UNAVAILABLE", true},
		{ldap.NewError(ldap.LDAPResultBusy, cause), codes.Unavailable, "DIRECTORY_UNAVAILABLE", true},
		{ldap.NewError(ldap.LDAPResultUnavailable, cause), codes.Unavailable, "DIRECTORY_UNAVAILABLE", true},
		{errCredential, codes.Unavailable, "BOOTSTRAP_CREDENTIAL_UNAVAILABLE", true},
		{ldap.NewError(ldap.LDAPResultInvalidCredentials, cause), codes.Unavailable, "BOOTSTRAP_CREDENTIAL_REJECTED", true},
		{ldap.NewError(ldap.LDAPResultInsufficientAccessRights, cause), codes.PermissionDenied, "DIRECTORY_ACCESS_DENIED", false},
		{ldap.NewError(ldap.LDAPResultNoSuchObject, cause), codes.FailedPrecondition, "DIRECTORY_REJECTED", false},
		{ldap.NewError(ldap.LDAPResultConstraintViolation, cause), codes.FailedPrecondition, "DIRECTORY_REJECTED", false},
	} {
		for _, step := range []func(*fake){
			func(f *fake) { f.readErr = tc.err },
			func(f *fake) { f.addErr = tc.err },
			func(f *fake) { f.passErr = tc.err },
		} {
			f := newFake(nil)
			step(f)
			_, err := ensure(testPlugin(f, nil), principal, true)
			c, code, retry := codeOf(err)
			if c != tc.grpc || code != tc.code || retry != tc.retry {
				t.Errorf("%v: %v %s %v, want %v %s %v", tc.err, c, code, retry, tc.grpc, tc.code, tc.retry)
			}
			if strings.Contains(err.Error(), diagnostic) {
				t.Errorf("the diagnostic reached the caller: %v", err)
			}
		}
		if _, err := ensure(testPlugin(newFake(nil), tc.err), principal, true); !hasCode(err, tc.code) {
			t.Errorf("dial %v: %v", tc.err, err)
		}
	}
	if _, err := ensure(&plugin{}, principal, true); !hasCode(err, "UNKNOWN_INSTANCE") {
		t.Errorf("unknown instance: %v", err)
	}
}

// TestHealth: a bind serves; anything else does not, with a generic message.
func TestHealth(t *testing.T) {
	r, err := testPlugin(newFake(nil), nil).Health(context.Background(), &pluginv1.HealthRequest{Instance: "ldap-prod"})
	if err != nil || !r.GetServing() {
		t.Errorf("serving: %v %v", r, err)
	}
	r, err = testPlugin(newFake(nil), errors.New("secret-diagnostic")).Health(context.Background(), &pluginv1.HealthRequest{Instance: "ldap-prod"})
	if err != nil || r.GetServing() || strings.Contains(r.GetPublicMessage(), "secret") || r.GetPublicMessage() == "" {
		t.Errorf("not serving: %v %v", r, err)
	}
	if _, err := testPlugin(newFake(nil), nil).Health(context.Background(), &pluginv1.HealthRequest{Instance: "other"}); !hasCode(err, "UNKNOWN_INSTANCE") {
		t.Errorf("unknown: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	r, err := (&plugin{}).Describe(context.Background(), &pluginv1.DescribeRequest{})
	if err != nil || r.GetPluginType() != "openldap.v1" || r.GetKind() != pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER || r.GetPluginProtocolVersion() != 2 ||
		r.GetIdentityProvider().GetProducedIdentityMode() != pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR || r.GetInstanceConfigSchemaJson() == "" {
		t.Errorf("%+v %v", r, err)
	}
}

const goodBootstrap = `{"source":"vault","address":"https://vault.prod.internal:8200","auth_mount":"jwt-spiffe","role":"r","jwt_audience":"a","kv_path":"kv/data/ligo/bootstrap/ldap-prod"}`

func configJSON(url, ou, endpoints, extra string) string {
	return fmt.Sprintf(`{"url":%q,"service_ou_dn":%q,"allowed_endpoints":%s,"bootstrap_credential":%s%s}`, url, ou, endpoints, goodBootstrap, extra)
}

// TestParseConfig is OL-1: each refusal names its field; ConfigureInstances
// refuses before it touches SPIRE.
func TestParseConfig(t *testing.T) {
	good := `["ldap.ligo.lab:636"]`
	for name, tc := range map[string]struct {
		json, field string
	}{
		"plain ldap":        {configJSON("ldap://ldap.ligo.lab", ou, good, ""), "url"},
		"no host":           {configJSON("ldaps://", ou, good, ""), "url"},
		"path in url":       {configJSON("ldaps://ldap.ligo.lab/dc=x", ou, good, ""), "url"},
		"bad dn":            {configJSON("ldaps://ldap.ligo.lab", "not a dn", good, ""), "service_ou_dn"},
		"empty dn":          {configJSON("ldaps://ldap.ligo.lab", "", good, ""), "service_ou_dn"},
		"endpoint not kept": {configJSON("ldaps://ldap.ligo.lab", ou, `["other:636"]`, ""), "allowed_endpoints"},
		"other port":        {configJSON("ldaps://ldap.ligo.lab:1636", ou, good, ""), "allowed_endpoints"},
		"unknown field":     {configJSON("ldaps://ldap.ligo.lab", ou, good, `,"start_tls":true`), "start_tls"},
		"ca_file":           {configJSON("ldaps://ldap.ligo.lab", ou, good, `,"ca_file":"/etc/shadow"`), "ca_file"}, // no file paths (ligo-instances T-22d)
		"no bootstrap":      {fmt.Sprintf(`{"url":"ldaps://ldap.ligo.lab","service_ou_dn":%q,"allowed_endpoints":%s}`, ou, good), "bootstrap_credential"},
		"db static role": {`{"url":"ldaps://ldap.ligo.lab","service_ou_dn":"` + ou + `","allowed_endpoints":` + good +
			`,"bootstrap_credential":{"source":"vault","address":"https://v:8200","auth_mount":"m","role":"r","jwt_audience":"a","db_static_role":"x"}}`, "kv_path"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseConfig([]byte(tc.json))
			if err == nil || !strings.Contains(err.Error(), tc.field) {
				t.Errorf("err = %v, want one naming %s", err, tc.field)
			}
			_, err = (&plugin{}).ConfigureInstances(context.Background(), &pluginv1.ConfigureInstancesRequest{
				Instances: []*pluginv1.InstanceDescriptor{{Name: "ldap-prod", ConfigJson: tc.json}}})
			if c, code, _ := codeOf(err); c != codes.InvalidArgument || code != "INVALID_CONFIG" || !strings.Contains(err.Error(), tc.field) {
				t.Errorf("configure: %v %s (%v)", c, code, err)
			}
		})
	}
	c, err := parseConfig([]byte(configJSON("ldaps://ldap.ligo.lab", ou, good, "")))
	if err != nil || c.host != "ldap.ligo.lab" {
		t.Errorf("default port: %+v %v", c, err)
	}
	if _, err := parseConfig([]byte(configJSON("ldaps://ldap.ligo.lab:1636", ou, `["ldap.ligo.lab:1636"]`, ""))); err != nil {
		t.Errorf("explicit port: %v", err)
	}
}
