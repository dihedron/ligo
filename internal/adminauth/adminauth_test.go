package adminauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/dihedron/ligo/internal/config"
	"github.com/go-ldap/ldap/v3"
)

// fakeDirectory is a directory of entries and passwords; it evaluates the
// filters ligo sends: &, | and attribute equality.
type fakeDirectory struct {
	entries   map[string]map[string][]string // lower-case DN: attributes
	passwords map[string]string              // DN: password
	searches  int
	down      bool
}

func (f *fakeDirectory) Bind(dn, password string) error {
	if f.down {
		return errors.New("connection reset")
	}
	if p, ok := f.passwords[dn]; !ok || p != password {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
	}
	return nil
}

func (f *fakeDirectory) Search(r *ldap.SearchRequest) (*ldap.SearchResult, error) {
	f.searches++
	base := strings.ToLower(r.BaseDN)
	if _, ok := f.entries[base]; !ok && r.Scope == ldap.ScopeBaseObject {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	res := &ldap.SearchResult{}
	for dn, attrs := range f.entries {
		in := dn == base || r.Scope == ldap.ScopeWholeSubtree && strings.HasSuffix(dn, ","+base)
		if in && match(r.Filter, attrs) {
			res.Entries = append(res.Entries, ldap.NewEntry(dn, attrs))
		}
	}
	if r.SizeLimit > 0 && len(res.Entries) > r.SizeLimit {
		return res, ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("size limit"))
	}
	return res, nil
}

func (f *fakeDirectory) Close() error { return nil }

// match evaluates (&...), (|...) and (attr=value) with escaped values.
func match(filter string, attrs map[string][]string) bool {
	inner := filter[1 : len(filter)-1]
	switch inner[0] {
	case '&', '|':
		var parts []string
		for depth, start, i := 0, 1, 1; i < len(inner); i++ {
			switch inner[i] {
			case '(':
				if depth == 0 {
					start = i
				}
				depth++
			case ')':
				if depth--; depth == 0 {
					parts = append(parts, inner[start:i+1])
				}
			}
		}
		all := inner[0] == '&'
		for _, p := range parts {
			if match(p, attrs) != all {
				return !all
			}
		}
		return all
	}
	name, value, _ := strings.Cut(inner, "=")
	raw, _ := url.PathUnescape(strings.ReplaceAll(value, `\`, "%"))
	return slices.ContainsFunc(attrs[name], func(v string) bool { return strings.EqualFold(v, raw) })
}

const (
	service = "cn=ligo-admin-auth,ou=services,dc=ligo,dc=lab"
	olivia  = "uid=olivia,ou=users,dc=ligo,dc=lab"
	ops     = "cn=ligo-operators-prod,ou=groups,dc=ligo,dc=lab"
	staff   = "cn=prod-staff,ou=groups,dc=ligo,dc=lab" // has ops as a member
	all     = "cn=everyone,ou=groups,dc=ligo,dc=lab"   // has staff as a member
	viewers = "cn=ligo-viewers,ou=groups,dc=ligo,dc=lab"
)

func directoryOf() *fakeDirectory {
	person := func(uid string) map[string][]string {
		return map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {uid}}
	}
	group := func(members ...string) map[string][]string {
		return map[string][]string{"objectClass": {"groupOfNames"}, "member": members}
	}
	return &fakeDirectory{
		entries: map[string]map[string][]string{
			olivia: person("olivia"), "uid=twin,ou=users,dc=ligo,dc=lab": person("twin"), "uid=twin,ou=other,dc=ligo,dc=lab": person("twin"),
			ops: group(olivia), staff: group(ops), all: group(staff), viewers: group("uid=victor,ou=users,dc=ligo,dc=lab"),
		},
		passwords: map[string]string{service: "service-secret", olivia: "olivia-secret"},
	}
}

func authenticator(d *fakeDirectory, nested bool, groups ...string) *LDAP {
	return &LDAP{Config: config.LDAP{ServiceBindDN: service, UserBaseDN: "dc=ligo,dc=lab",
		UserFilter: "(&(objectClass=inetOrgPerson)(uid=%s))", NestedGroups: nested},
		BindPassword: "service-secret", Groups: groups, dial: func(context.Context) (directory, error) { return d, nil }}
}

// TestAuthenticate: search with the service account, bind as the one user
// found, then the configured groups the user is in; every refusal is the
// same error, and malformed usernames never reach the directory (T-04).
func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	d := directoryOf()
	l := authenticator(d, false, ops, staff, viewers)
	p, err := l.Authenticate(ctx, "olivia", "olivia-secret")
	if err != nil || p.Name != "olivia" || p.SPIFFEID != "" || !slices.Equal(p.Groups, []string{ops}) {
		t.Fatalf("olivia: %+v, %v", p, err)
	}
	for name, cred := range map[string][2]string{
		"wrong password":    {"olivia", "nope"},
		"unknown user":      {"nobody", "x"},
		"two entries match": {"twin", "x"},
	} {
		if _, err := l.Authenticate(ctx, cred[0], cred[1]); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: %v", name, err)
		}
	}
	before := d.searches
	for _, cred := range [][2]string{{"", "x"}, {"olivia", ""}, {"system:sweeper", "x"}, {"olivia)(uid=*", "x"}, {strings.Repeat("a", 65), "x"}} {
		if _, err := l.Authenticate(ctx, cred[0], cred[1]); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%q: %v", cred[0], err)
		}
	}
	if d.searches != before {
		t.Error("a malformed username reached the directory")
	}
	d.down = true
	if _, err := l.Authenticate(ctx, "olivia", "olivia-secret"); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("directory down: %v", err)
	}
	if _, err := (&LDAP{Config: config.LDAP{URL: "ldap" + "://directory"}}).Authenticate(ctx, "olivia", "x"); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("plain ldap:// accepted: %v", err)
	}
}

// TestLookup: a user's groups now, without a password, as the service
// (§7.3 rule 3); a user the directory no longer has is refused.
func TestLookup(t *testing.T) {
	ctx := context.Background()
	d := directoryOf()
	l := authenticator(d, false, ops, viewers)
	if p, err := l.Lookup(ctx, "olivia"); err != nil || p.Name != "olivia" || !slices.Equal(p.Groups, []string{ops}) {
		t.Fatalf("olivia: %+v %v", p, err)
	}
	d.entries[ops]["member"] = nil // removed from her group
	if p, err := l.Lookup(ctx, "olivia"); err != nil || len(p.Groups) != 0 {
		t.Errorf("after removal: %+v %v", p, err)
	}
	delete(d.entries, olivia)
	for _, user := range []string{"olivia", "olivia)(uid=*"} {
		if _, err := l.Lookup(ctx, user); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%q: %v", user, err)
		}
	}
}

// TestNestedGroups: with nested_groups, membership through groups of
// groups counts, one search per level; without, only direct membership.
func TestNestedGroups(t *testing.T) {
	ctx := context.Background()
	d := directoryOf()
	if p, err := authenticator(d, false, all).Authenticate(ctx, "olivia", "olivia-secret"); err != nil || len(p.Groups) != 0 {
		t.Errorf("not nested: %+v, %v", p, err)
	}
	d.searches = 0
	p, err := authenticator(d, true, all, "cn=missing,ou=groups,dc=ligo,dc=lab").Authenticate(ctx, "olivia", "olivia-secret")
	if err != nil || !slices.Equal(p.Groups, []string{all}) {
		t.Errorf("nested: %+v, %v", p, err)
	}
	if d.searches > 6 { // user, direct, 3 levels, the missing group
		t.Errorf("%d searches", d.searches)
	}
}

// TestSVID: the SPIFFE ID of a verified client certificate in an accepted
// trust domain; anything else is refused.
func TestSVID(t *testing.T) {
	cert := func(id string) *x509.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		u, _ := url.Parse(id)
		serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: serial, URIs: []*url.URL{u}},
			&x509.Certificate{SerialNumber: serial}, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	state := func(c *x509.Certificate) *tls.ConnectionState {
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c}}}
	}
	id := "spiffe://prod.lab/ns/ci/sa/deployer"
	if p, err := SVID(state(cert(id)), []string{"prod.lab"}); err != nil || p.SPIFFEID != id || p.Name != "" {
		t.Errorf("accepted: %+v, %v", p, err)
	}
	for name, cs := range map[string]*tls.ConnectionState{
		"other trust domain": state(cert("spiffe://test.lab/x")),
		"not a SPIFFE ID":    state(cert("https://example.com/" + hex.EncodeToString([]byte("x")))),
		"not verified":       {PeerCertificates: []*x509.Certificate{cert(id)}},
		"no TLS":             nil,
	} {
		if _, err := SVID(cs, []string{"prod.lab"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
