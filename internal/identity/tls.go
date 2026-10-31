package identity

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"slices"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// ErrNoSVID means a connection presented no verified X.509-SVID of an
// accepted trust domain.
var ErrNoSVID = errors.New("identity: no verified X.509-SVID of an accepted trust domain")

// ServerTLS is a listener's TLS configuration: TLS 1.3, the server
// certificate from cert and, with bundles, client X.509-SVIDs verified
// against the accepted trust domains' current bundles at every handshake
// (§7.1). A client without a certificate still connects, for other
// authentication modes.
func ServerTLS(cert func(*tls.ClientHelloInfo) (*tls.Certificate, error), bundles x509bundle.Source, accepted []string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: cert,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			c := &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: cert}
			if bundles == nil {
				return c, nil
			}
			pool := x509.NewCertPool()
			for _, name := range accepted {
				td, err := spiffeid.TrustDomainFromString(name)
				if err != nil {
					return nil, err
				}
				if b, err := bundles.GetX509BundleForTrustDomain(td); err == nil {
					for _, a := range b.X509Authorities() {
						pool.AddCert(a)
					}
				}
			}
			c.ClientCAs, c.ClientAuth = pool, tls.VerifyClientCertIfGiven
			// the chain must also lead to the bundle of the SVID's own trust
			// domain; VerifyConnection runs on resumed sessions too
			c.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return nil
				}
				_, _, err := x509svid.Verify(cs.PeerCertificates, bundles)
				return err
			}
			return c, nil
		}}
}

// PeerID returns the SPIFFE ID of a connection's client certificate, which
// ServerTLS verified; an ID outside the accepted trust domains is refused.
func PeerID(cs *tls.ConnectionState, accepted []string) (spiffeid.ID, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 {
		return spiffeid.ID{}, ErrNoSVID
	}
	id, err := x509svid.IDFromCert(cs.VerifiedChains[0][0])
	if err != nil || !Accepted(id, accepted) {
		return spiffeid.ID{}, ErrNoSVID
	}
	return id, nil
}

// Accepted reports whether id is a member of one of the accepted trust
// domains.
func Accepted(id spiffeid.ID, accepted []string) bool {
	return slices.ContainsFunc(accepted, func(td string) bool {
		t, err := spiffeid.TrustDomainFromString(td)
		return err == nil && id.MemberOf(t)
	})
}
