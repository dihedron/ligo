//go:build integration && lab

package standins

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/go-ldap/ldap/v3"
)

const ligoAccounts = "ou=ligo-accounts,dc=ligo,dc=lab"

// openldapConfig is an instance's config for this directory URL and bootstrap.
func openldapConfig(t *testing.T, url, endpoint, bootstrapName string) string {
	t.Helper()
	return `{"url":"` + url + `","service_ou_dn":"` + ligoAccounts + `","allowed_endpoints":["` + endpoint + `"],"ca_pem":` +
		caPEM(t) + `,"bootstrap_credential":` + strings.Replace(bootstrap(t, "openldap"), "bootstrap/openldap", "bootstrap/"+bootstrapName, 1) + `}`
}

func startOpenLDAP(t *testing.T, config string) *pluginmgr.Client {
	t.Helper()
	return start(t, "ligo-plugin-openldap", pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER,
		&pluginv1.InstanceDescriptor{Name: "ldap-prod", ConfigJson: config})
}

// ldapConn is a connection to the lab's directory, bound as dn.
func ldapConn(t *testing.T, dn, password string) (*ldap.Conn, error) {
	t.Helper()
	pem, err := os.ReadFile(labEnv(t, "LIGO_TEST_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	conn, err := ldap.DialURL(labEnv(t, "LIGO_TEST_LDAP_URL"), ldap.DialWithTLSConfig(&tls.Config{RootCAs: roots, ServerName: "ldap.ligo.lab", MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Bind(dn, password); err != nil {
		_ = conn.Close()
		return nil, err
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn, nil
}

const idpDN = "cn=ligo-idp,ou=services,dc=ligo,dc=lab"

func idp(t *testing.T) *ldap.Conn {
	t.Helper()
	conn, err := ldapConn(t, idpDN, labEnv(t, "LIGO_TEST_LDAP_IDP_PASS"))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

// account is a binding's context with a fresh principal, whose entry the test
// removes at its end.
func account(t *testing.T, admin *ldap.Conn, rotate bool) *pluginv1.BindingContext {
	t.Helper()
	id := uuid.NewV7().String()
	name := "bnd_" + strings.ReplaceAll(id, "-", "")[16:32]
	t.Cleanup(func() { _ = admin.Del(ldap.NewDelRequest(dnOf(name), nil)) })
	return &pluginv1.BindingContext{BindingId: id, DerivedPrincipalName: name, RotateStaticSecrets: rotate}
}

func dnOf(principal string) string { return "uid=" + principal + "," + ligoAccounts }

// seed creates an entry with these description values and no password.
func seed(t *testing.T, admin *ldap.Conn, principal string, descriptions ...string) {
	t.Helper()
	req := ldap.NewAddRequest(dnOf(principal), nil)
	req.Attribute("objectClass", []string{"inetOrgPerson"})
	req.Attribute("uid", []string{principal})
	req.Attribute("cn", []string{principal})
	req.Attribute("sn", []string{principal})
	if len(descriptions) > 0 {
		req.Attribute("description", descriptions)
	}
	if err := admin.Add(req); err != nil {
		t.Fatal(err)
	}
}

func binds(t *testing.T, principal, password string) bool {
	t.Helper()
	_, err := ldapConn(t, dnOf(principal), password)
	return err == nil
}

// TestLabOpenLDAP is OL-2, OL-3, OL-4, OL-6 and OL-8: the plugin against the
// real directory, with its SVID and its bootstrap credential from the
// secrets backend.
func TestLabOpenLDAP(t *testing.T) {
	ctx := context.Background()
	c := startOpenLDAP(t, openldapConfig(t, labEnv(t, "LIGO_TEST_LDAP_URL"), "ldap.ligo.lab:636", "openldap"))
	admin := idp(t)
	ensure := func(b *pluginv1.BindingContext) *pluginv1.IdentityArtifact {
		t.Helper()
		r, err := c.Identity.EnsureIdentity(ctx, &pluginv1.EnsureIdentityRequest{Instance: "ldap-prod", Binding: b})
		if err != nil {
			t.Fatal(err)
		}
		return r.GetArtifact()
	}
	if h, err := c.Control.Health(ctx, &pluginv1.HealthRequest{Instance: "ldap-prod"}); err != nil || !h.GetServing() {
		t.Fatalf("health: %v %v", h, err)
	}

	// OL-2: created, tagged, the returned password binds, stored hashed
	b := account(t, admin, true)
	principal := b.GetDerivedPrincipalName()
	a := ensure(b)
	first := a.GetStaticSecret().GetPassword()
	if a.GetMode() != pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR || a.GetPrincipalId() != principal || a.GetDistinguishedName() != dnOf(principal) ||
		a.GetStaticSecret().GetUsername() != principal || len(first) != 40 {
		t.Fatalf("artifact: mode %v, principal %s, DN %s, user %s, %d characters", a.GetMode(), a.GetPrincipalId(), a.GetDistinguishedName(), a.GetStaticSecret().GetUsername(), len(first))
	}
	self, err := ldapConn(t, dnOf(principal), first)
	if err != nil {
		t.Fatalf("the returned password does not bind: %v", err)
	}
	res, err := self.Search(ldap.NewSearchRequest(dnOf(principal), ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, "(objectClass=*)",
		[]string{"objectClass", "uid", "cn", "sn", "description", "userPassword"}, nil))
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("reading the account: %v", err)
	}
	e := res.Entries[0]
	if e.GetAttributeValue("uid") != principal || e.GetAttributeValue("cn") != principal || e.GetAttributeValue("sn") != principal ||
		e.GetAttributeValue("description") != "ligo:binding_id="+b.GetBindingId() {
		t.Errorf("entry: %s %s %s %s", e.GetAttributeValue("uid"), e.GetAttributeValue("cn"), e.GetAttributeValue("sn"), e.GetAttributeValue("description"))
	}
	if stored := e.GetAttributeValue("userPassword"); !strings.HasPrefix(stored, "{") || strings.Contains(stored, first) {
		t.Errorf("userPassword is not hashed: %d characters, scheme prefix %v", len(stored), strings.HasPrefix(stored, "{"))
	}

	// OL-3: no rotation, twice: no secret, the password still binds
	b.RotateStaticSecrets = false
	for range 2 {
		if a := ensure(b); a.GetStaticSecret() != nil || !a.GetSecretUnchanged() {
			t.Errorf("no rotation: secret %v, unchanged %v", a.GetStaticSecret() != nil, a.GetSecretUnchanged())
		}
	}
	if !binds(t, principal, first) {
		t.Error("no rotation changed the password")
	}

	// OL-4: rotation: the new one binds, the old one does not
	b.RotateStaticSecrets = true
	second := ensure(b).GetStaticSecret().GetPassword()
	if second == first || !binds(t, principal, second) || binds(t, principal, first) {
		t.Errorf("rotation: new binds %v, old binds %v", binds(t, principal, second), binds(t, principal, first))
	}

	// OL-8: removed with an empty artifact; a second cleanup succeeds
	for i := range 2 {
		r, err := c.Identity.CleanupIdentity(ctx, &pluginv1.CleanupIdentityRequest{Instance: "ldap-prod", Binding: b})
		if err != nil || r.GetSkippedNotOwner() {
			t.Fatalf("cleanup %d: %v %v", i, r, err)
		}
	}
	if binds(t, principal, second) {
		t.Error("the removed account still binds")
	}

	// OL-6: an account with no password, as a crash leaves it, gets one
	crashed := account(t, admin, true)
	seed(t, admin, crashed.GetDerivedPrincipalName(), "ligo:binding_id="+crashed.GetBindingId())
	if p := ensure(crashed).GetStaticSecret().GetPassword(); !binds(t, crashed.GetDerivedPrincipalName(), p) {
		t.Error("the crashed account did not get a password")
	}
}

// TestLabOpenLDAPForeign is OL-5: another binding's account and an untagged
// one are refused and left alone.
func TestLabOpenLDAPForeign(t *testing.T) {
	ctx := context.Background()
	c := startOpenLDAP(t, openldapConfig(t, labEnv(t, "LIGO_TEST_LDAP_URL"), "ldap.ligo.lab:636", "openldap"))
	admin := idp(t)
	for name, descriptions := range map[string][]string{"another binding": {"ligo:binding_id=" + uuid.NewV7().String()}, "untagged": nil} {
		t.Run(name, func(t *testing.T) {
			b := account(t, admin, true)
			seed(t, admin, b.GetDerivedPrincipalName(), descriptions...)
			_, err := c.Identity.EnsureIdentity(ctx, &pluginv1.EnsureIdentityRequest{Instance: "ldap-prod", Binding: b})
			if code(err) != "RESOURCE_OWNED_BY_OTHER_BINDING" {
				t.Errorf("ensure: %v", err)
			}
			r, err := c.Identity.CleanupIdentity(ctx, &pluginv1.CleanupIdentityRequest{Instance: "ldap-prod", Binding: b})
			if err != nil || !r.GetSkippedNotOwner() {
				t.Errorf("cleanup: %v %v", r, err)
			}
			res, err := admin.Search(ldap.NewSearchRequest(dnOf(b.GetDerivedPrincipalName()), ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false,
				"(objectClass=*)", []string{"description"}, nil))
			if err != nil || len(res.Entries) != 1 {
				t.Errorf("the foreign account is gone: %v", err)
			}
		})
	}
}

// TestLabOpenLDAPFailures is OL-9: the directory unreachable, the credential
// unreadable or refused: retryable codes, not serving, no secret or
// diagnostic in the error.
func TestLabOpenLDAPFailures(t *testing.T) {
	ctx := context.Background()
	admin := idp(t)
	check := func(t *testing.T, c *pluginmgr.Client, want string) {
		t.Helper()
		b := account(t, admin, true)
		_, err := c.Identity.EnsureIdentity(ctx, &pluginv1.EnsureIdentityRequest{Instance: "ldap-prod", Binding: b})
		_, detail := pluginsdk.FromError(err)
		if detail.GetCode() != want || !detail.GetRetryable() {
			t.Errorf("ensure: %s retryable=%v (%v)", detail.GetCode(), detail.GetRetryable(), err)
		}
		if strings.Contains(err.Error(), labEnv(t, "LIGO_TEST_LDAP_IDP_PASS")) || strings.Contains(err.Error(), "LDAP Result Code") {
			t.Errorf("the error says too much: %v", err)
		}
		if h, err := c.Control.Health(ctx, &pluginv1.HealthRequest{Instance: "ldap-prod"}); err != nil || h.GetServing() {
			t.Errorf("health: %v %v", h, err)
		}
	}
	t.Run("directory down", func(t *testing.T) {
		check(t, startOpenLDAP(t, openldapConfig(t, "ldaps://ldap.ligo.lab:1636", "ldap.ligo.lab:1636", "openldap")), "DIRECTORY_UNAVAILABLE")
	})
	t.Run("credential unreadable", func(t *testing.T) {
		check(t, startOpenLDAP(t, openldapConfig(t, labEnv(t, "LIGO_TEST_LDAP_URL"), "ldap.ligo.lab:636", "postgres")), "BOOTSTRAP_CREDENTIAL_UNAVAILABLE")
	})
	t.Run("credential refused", func(t *testing.T) {
		original := labEnv(t, "LIGO_TEST_LDAP_IDP_PASS")
		c := startOpenLDAP(t, openldapConfig(t, labEnv(t, "LIGO_TEST_LDAP_URL"), "ldap.ligo.lab:636", "openldap"))
		const temporary = "a-temporary-password-for-the-test"
		if _, err := admin.PasswordModify(ldap.NewPasswordModifyRequest(idpDN, "", temporary)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			restore, err := ldapConn(t, idpDN, temporary)
			if err != nil {
				t.Errorf("the service account cannot be restored: %v", err)
				return
			}
			if _, err := restore.PasswordModify(ldap.NewPasswordModifyRequest(idpDN, "", original)); err != nil {
				t.Errorf("the service account cannot be restored: %v", err)
			}
		})
		check(t, c, "BOOTSTRAP_CREDENTIAL_REJECTED")
	})
}
