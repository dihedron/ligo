package adminhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/dihedron/ligo/internal/adminauth"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
)

// directory counts its calls; its groups can change between them.
type directory struct {
	calls  int
	groups []string
}

func (d *directory) Authenticate(_ context.Context, user, password string) (authz.Principal, error) {
	d.calls++
	if password != "pw" {
		return authz.Principal{}, adminauth.ErrInvalidCredentials
	}
	return authz.Principal{Name: user, Groups: slices.Clone(d.groups)}, nil
}

// TestBasicCache: a successful Basic login is remembered for basicTTL, by
// user and password; a group change shows once it expires (finding 2.8).
func TestBasicCache(t *testing.T) {
	var c basicCache
	now := time.Now()
	c.put("ann", "pw", authz.Principal{Name: "ann", Groups: []string{"g1"}}, now)
	if p, ok := c.get("ann", "pw", now.Add(basicTTL-time.Millisecond)); !ok || p.Groups[0] != "g1" {
		t.Errorf("within the TTL: %v %t", p, ok)
	}
	for _, tc := range []struct {
		user, password string
		at             time.Time
	}{{"ann", "other", now}, {"bob", "pw", now}, {"ann", "pw", now.Add(basicTTL)}} {
		if _, ok := c.get(tc.user, tc.password, tc.at); ok {
			t.Errorf("%s/%s at +%s: remembered", tc.user, tc.password, tc.at.Sub(now))
		}
	}
	c.put("bob", "pw", authz.Principal{Name: "bob"}, now.Add(basicTTL))
	if len(c.m) != 1 {
		t.Errorf("%d entries, the expired one kept", len(c.m))
	}
}

// TestBasicDirectory: repeated Basic requests ask the directory once, wrong
// passwords every time, and break-glass always, so it sees a group removed
// at once.
func TestBasicDirectory(t *testing.T) {
	az, err := authz.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	d := &directory{groups: []string{"cn=g1"}}
	s := &Server{Listener: config.AdminListener{AllowBasicAuth: true}, LDAP: d, Authz: az}
	call := func(method, path, password string) (authz.Principal, error) {
		r := httptest.NewRequest(method, path, nil)
		r.SetBasicAuth("ann", password)
		c, err := s.authenticate(r)
		return c.Principal, err
	}
	for range 3 {
		if _, err := call(http.MethodGet, "/v1/admin/bindings", "pw"); err != nil {
			t.Fatal(err)
		}
	}
	if d.calls != 1 {
		t.Errorf("%d directory calls for 3 requests, want 1", d.calls)
	}
	if _, err := call(http.MethodGet, "/v1/admin/bindings", "wrong"); err == nil || d.calls != 2 {
		t.Errorf("wrong password: %v, %d calls", err, d.calls)
	}
	d.groups = nil // removed from the group
	if p, err := call(http.MethodPost, "/v1/admin/break-glass", "pw"); err != nil || len(p.Groups) != 0 || d.calls != 3 {
		t.Errorf("break-glass: %v %v, %d calls", p.Groups, err, d.calls)
	}
}

// TestAPIRate: the highest rate_limit of the caller's bindings, in any
// order, else api_per_principal_rps (finding 4.2).
func TestAPIRate(t *testing.T) {
	s := &Server{}
	slow := authz.Grant{RateLimit: &config.APIRateLimit{APIRPS: 5, Burst: 20}}
	fast := authz.Grant{RateLimit: &config.APIRateLimit{APIRPS: 50, Burst: 10}}
	for _, gs := range []authz.Grants{{slow, fast}, {fast, slow}, {{}, fast, slow}} {
		if r := s.apiRate(changerequests.Caller{Grants: gs}); r.PerSecond != 50 || r.Burst != 20 {
			t.Errorf("%d grants: %+v, want 50/s, burst 20", len(gs), r)
		}
	}
	if r := s.apiRate(changerequests.Caller{Grants: authz.Grants{{}}}); r.PerSecond != 10 || r.Burst != 20 {
		t.Errorf("no rate_limit: %+v", r)
	}
}
