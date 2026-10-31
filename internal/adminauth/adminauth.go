// Package adminauth authenticates administrators (§7.2.1): LDAP users with
// their group DNs (T-04), and SPIFFE principals by their X.509-SVID.
package adminauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/identity"
	"github.com/go-ldap/ldap/v3"
)

// ErrInvalidCredentials is a refused login, whatever the reason: the caller
// learns nothing about which part was wrong.
var ErrInvalidCredentials = errors.New("adminauth: invalid credentials")

// usernameRE keeps ':' out, so no username collides with system:* (§7.2.1).
var usernameRE = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// maxNesting bounds the walk through nested groups.
const maxNesting = 8

// directory is the part of an LDAP connection authentication uses.
type directory interface {
	Bind(username, password string) error
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAP authenticates users against the directory of admin_auth.ldap: the
// service account finds the user, the user binds, and the groups of the
// authorization bindings are checked for membership.
type LDAP struct {
	Config       config.LDAP
	BindPassword string         // from service_bind_password_env
	RootCAs      *x509.CertPool // from ca_cert_file; SetRootCAs replaces it while serving
	Groups       []string       // the ldap_group_dn of the authorization bindings
	Timeout      time.Duration  // per connection and request; default 10s

	mu   sync.RWMutex                                 // guards RootCAs
	dial func(ctx context.Context) (directory, error) // tests
}

// SetRootCAs replaces the CAs that verify the directory, for the next
// connections (a renewed ca_cert_file, reloaded on SIGHUP).
func (l *LDAP) SetRootCAs(roots *x509.CertPool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.RootCAs = roots
}

// Authenticate returns the principal of username with the groups among
// Groups it belongs to; a refused login is ErrInvalidCredentials, a
// directory failure another error.
func (l *LDAP) Authenticate(ctx context.Context, username, password string) (authz.Principal, error) {
	if password == "" {
		return authz.Principal{}, ErrInvalidCredentials // before dialing (T-04)
	}
	return l.principal(ctx, username, func(conn directory, userDN string) error {
		if err := conn.Bind(userDN, password); err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				return ErrInvalidCredentials
			}
			return fmt.Errorf("adminauth: user bind: %w", err)
		}
		return nil
	})
}

// Lookup returns the principal of username with its groups now, without
// its password: the UI re-checks a session's roles with it (§7.3 rule 3).
// A user the directory no longer has is ErrInvalidCredentials.
func (l *LDAP) Lookup(ctx context.Context, username string) (authz.Principal, error) {
	return l.principal(ctx, username, nil)
}

// principal finds exactly one user as the service, runs verify (the user's
// bind) if any, and reads the user's groups as the service.
func (l *LDAP) principal(ctx context.Context, username string, verify func(directory, string) error) (authz.Principal, error) {
	if !usernameRE.MatchString(username) {
		return authz.Principal{}, ErrInvalidCredentials // before dialing (T-04)
	}
	conn, err := l.connect(ctx)
	if err != nil {
		return authz.Principal{}, err
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Bind(l.Config.ServiceBindDN, l.BindPassword); err != nil {
		return authz.Principal{}, fmt.Errorf("adminauth: service bind: %w", err)
	}
	res, err := conn.Search(ldap.NewSearchRequest(l.Config.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, l.seconds(), false,
		fmt.Sprintf(l.Config.UserFilter, ldap.EscapeFilter(username)), []string{"dn"}, nil))
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
		return authz.Principal{}, fmt.Errorf("adminauth: user search: %w", err)
	}
	if err != nil || len(res.Entries) != 1 {
		return authz.Principal{}, ErrInvalidCredentials // none, or ambiguous
	}
	userDN := res.Entries[0].DN
	if verify != nil {
		if err := verify(conn, userDN); err != nil {
			return authz.Principal{}, err
		}
		if err := conn.Bind(l.Config.ServiceBindDN, l.BindPassword); err != nil { // groups are read as the service
			return authz.Principal{}, fmt.Errorf("adminauth: service bind: %w", err)
		}
	}
	p := authz.Principal{Name: username}
	for _, g := range l.Groups {
		ok, err := l.member(conn, g, userDN)
		if err != nil {
			return authz.Principal{}, err
		}
		if ok {
			p.Groups = append(p.Groups, g)
		}
	}
	return p, nil
}

// member reports whether userDN is in group. With nested_groups, the walk
// goes up from the user: each level is one search, under the group's
// parent, for the groups whose members include the previous level.
func (l *LDAP) member(conn directory, group, userDN string) (bool, error) {
	filter := l.Config.GroupMembershipFilter
	if filter == "" {
		filter = "(member=%s)"
	}
	res, err := conn.Search(ldap.NewSearchRequest(group, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, l.seconds(), false,
		fmt.Sprintf(filter, ldap.EscapeFilter(userDN)), []string{"dn"}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return false, nil // a configured group the directory does not have
	}
	if err != nil {
		return false, fmt.Errorf("adminauth: membership in %s: %w", group, err)
	}
	if len(res.Entries) > 0 || !l.Config.NestedGroups {
		return len(res.Entries) > 0, nil
	}
	dn, err := ldap.ParseDN(group)
	if err != nil || len(dn.RDNs) < 2 {
		return false, fmt.Errorf("adminauth: group %q: no parent to search under", group)
	}
	base := (&ldap.DN{RDNs: dn.RDNs[1:]}).String()
	seen := map[string]bool{strings.ToLower(userDN): true}
	frontier := []string{userDN}
	for depth := 0; depth < maxNesting && len(frontier) > 0; depth++ {
		var or strings.Builder
		or.WriteString("(|")
		for _, m := range frontier {
			fmt.Fprintf(&or, filter, ldap.EscapeFilter(m))
		}
		or.WriteString(")")
		res, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, l.seconds(), false,
			or.String(), []string{"dn"}, nil))
		if err != nil {
			return false, fmt.Errorf("adminauth: groups under %s: %w", base, err)
		}
		frontier = nil
		for _, e := range res.Entries {
			if strings.EqualFold(e.DN, group) {
				return true, nil
			}
			if !seen[strings.ToLower(e.DN)] {
				seen[strings.ToLower(e.DN)] = true
				frontier = append(frontier, e.DN)
			}
		}
	}
	return false, nil
}

func (l *LDAP) timeout() time.Duration {
	if l.Timeout == 0 {
		return 10 * time.Second
	}
	return l.Timeout
}

func (l *LDAP) seconds() int { return int(l.timeout().Seconds()) }

// connect dials ldaps only, verifying the server against RootCAs.
func (l *LDAP) connect(ctx context.Context) (directory, error) {
	if l.dial != nil {
		return l.dial(ctx)
	}
	if !strings.HasPrefix(l.Config.URL, "ldaps://") {
		return nil, fmt.Errorf("adminauth: %s: ldaps:// only", l.Config.URL)
	}
	dialer := &net.Dialer{Timeout: l.timeout()}
	l.mu.RLock()
	roots := l.RootCAs
	l.mu.RUnlock()
	conn, err := ldap.DialURL(l.Config.URL, ldap.DialWithDialer(dialer),
		ldap.DialWithTLSConfig(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}))
	if err != nil {
		return nil, fmt.Errorf("adminauth: %w", err)
	}
	conn.SetTimeout(l.timeout())
	return conn, nil
}

// SVID returns the SPIFFE principal of a TLS connection whose client
// certificate the listener verified against the accepted trust domains'
// bundles (§7.2.1); a principal of another trust domain is refused.
func SVID(cs *tls.ConnectionState, accepted []string) (authz.Principal, error) {
	id, err := identity.PeerID(cs, accepted)
	if err != nil {
		return authz.Principal{}, ErrInvalidCredentials
	}
	return authz.Principal{SPIFFEID: id.String()}, nil
}
