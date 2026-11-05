package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/go-ldap/ldap/v3"
)

// errCredential is a bootstrap credential that cannot be read or used.
var errCredential = errors.New("bootstrap credential")

// directory is what the plugin does on one bound connection.
type directory interface {
	read(dn string) (exists bool, descriptions []string, err error)
	add(dn, principal, tag string) error
	setPassword(dn, password string) error
	remove(dn string) error
	close()
}

// dialer connects and binds, for one call: calls are rare, and each uses the
// current credential.
func dialer(c *config, cred *pluginsdk.BootstrapCredential) func(context.Context) (directory, error) {
	return func(ctx context.Context) (directory, error) {
		bind, err := cred.Get(ctx)
		if err != nil {
			return nil, errCredential
		}
		if _, err := ldap.ParseDN(bind.Username); err != nil {
			return nil, errCredential
		}
		conn, err := ldap.DialURL(c.URL, ldap.DialWithDialer(&net.Dialer{Timeout: callTimeout}),
			ldap.DialWithTLSConfig(&tls.Config{RootCAs: c.roots, ServerName: c.host, MinVersion: tls.VersionTLS12}))
		if err != nil {
			return nil, err
		}
		conn.SetTimeout(callTimeout)
		if err := conn.Bind(bind.Username, bind.Password.Reveal()); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return &ldapDirectory{conn}, nil
	}
}

type ldapDirectory struct{ conn *ldap.Conn }

func (d *ldapDirectory) close() { _ = d.conn.Close() }

// read looks the entry up by its DN: no filter holds a request value.
func (d *ldapDirectory) read(dn string) (bool, []string, error) {
	res, err := d.conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, int(callTimeout.Seconds()), false,
		"(objectClass=*)", []string{"description"}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if len(res.Entries) == 0 {
		return false, nil, nil
	}
	return true, res.Entries[0].GetAttributeValues("description"), nil
}

// add creates the account with no password: nobody can bind to it until
// setPassword, and the directory hashes that (§4 of the plugin's spec).
func (d *ldapDirectory) add(dn, principal, tag string) error {
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	for _, attr := range []string{"uid", "cn", "sn"} {
		req.Attribute(attr, []string{principal})
	}
	req.Attribute("description", []string{tag})
	return d.conn.Add(req)
}

func (d *ldapDirectory) setPassword(dn, password string) error {
	_, err := d.conn.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", password))
	return err
}

func (d *ldapDirectory) remove(dn string) error {
	return d.conn.Del(ldap.NewDelRequest(dn, nil))
}
