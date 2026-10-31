//go:build integration && lab

package adminauth

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/dihedron/ligo/internal/config"
)

func labEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set: run the lab tests with test/lab/lab.sh test --on ligo1", name)
	}
	return v
}

// TestLabLDAP: the lab's OpenLDAP over ldaps with the lab CA: a user found
// by the service account binds and gets the configured groups it is in; a
// wrong password is a refused login, a wrong service password is not.
func TestLabLDAP(t *testing.T) {
	ctx := context.Background()
	pem, err := os.ReadFile(labEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	base := labEnv(t, "LIGO_TEST_LDAP_BASE")
	ops, viewers := "cn=ligo-operators-prod,ou=groups,"+base, "cn=ligo-viewers,ou=groups,"+base
	l := &LDAP{Config: config.LDAP{URL: labEnv(t, "LIGO_TEST_LDAP_URL"), ServiceBindDN: "cn=ligo-admin-auth,ou=services," + base,
		UserBaseDN: "ou=users," + base, UserFilter: "(&(objectClass=inetOrgPerson)(uid=%s))", GroupMembershipFilter: "(member=%s)"},
		BindPassword: labEnv(t, "LIGO_TEST_LDAP_BIND_PASS"), RootCAs: roots, Groups: []string{ops, viewers}}
	p, err := l.Authenticate(ctx, "olivia", labEnv(t, "LIGO_TEST_LDAP_OLIVIA_PASS"))
	if err != nil || p.Name != "olivia" || !slices.Equal(p.Groups, []string{ops}) {
		t.Fatalf("olivia: %+v, %v", p, err)
	}
	if _, err := l.Authenticate(ctx, "olivia", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := l.Authenticate(ctx, "nobody", "x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("unknown user: %v", err)
	}
	l.BindPassword = "wrong"
	if _, err := l.Authenticate(ctx, "olivia", "x"); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("wrong service password: %v", err)
	}
}
