// Package identity is ligo's side of SPIFFE (§7.1, §8.2 step 3): a
// Workload API client per realm, the composite bundle source that verifies
// client SVIDs, and ligo's own core identity.
package identity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/metrics"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// bundles is a realm's bundle stream: *workloadapi.BundleSource.
type bundles interface {
	x509bundle.Source
	jwtbundle.Source
}

// Realms holds the realms' Workload API connections.
type Realms struct {
	clients   []*workloadapi.Client
	names     []string // the realm of each client
	sources   []*workloadapi.BundleSource
	authority map[spiffeid.TrustDomain]bundles // the one source of each trust domain
	via       map[spiffeid.TrustDomain]string  // the realm of that source
	core      *workloadapi.X509Source
	coreRealm *workloadapi.Client
}

// Open connects to every realms[].spiffe_workload_socket, starts each
// realm's bundle stream and acquires the core identity; it fails if the
// core identity's selector does not match exactly one SVID of its realm.
func Open(ctx context.Context, cfg *config.Config) (_ *Realms, err error) {
	z := &Realms{authority: map[spiffeid.TrustDomain]bundles{}, via: map[spiffeid.TrustDomain]string{}}
	defer func() {
		if err != nil {
			_ = z.Close()
		}
	}()
	byRealm := map[string]*workloadapi.BundleSource{}
	for _, realm := range cfg.Realms {
		client, err := workloadapi.New(ctx, workloadapi.WithAddr(realm.SPIFFEWorkloadSocket))
		if err != nil {
			return nil, fmt.Errorf("identity: realm %s: %w", realm.Name, err)
		}
		z.clients, z.names = append(z.clients, client), append(z.names, realm.Name)
		src, err := workloadapi.NewBundleSource(ctx, workloadapi.WithClient(client))
		if err != nil {
			return nil, fmt.Errorf("identity: realm %s: bundles: %w", realm.Name, err)
		}
		z.sources = append(z.sources, src)
		byRealm[realm.Name] = src
		if realm.Name == cfg.CoreIdentity.Realm {
			z.coreRealm = client
		}
	}
	if err := z.route(cfg, func(realm string) bundles { return byRealm[realm] }); err != nil {
		return nil, err
	}
	realmTD := ""
	for _, realm := range cfg.Realms {
		if realm.Name == cfg.CoreIdentity.Realm {
			realmTD = realm.TrustDomain
		}
	}
	sel := cfg.CoreIdentity.SVIDSelector
	selector, err := pluginsdk.NewInstanceSVIDSelector(nil, "ligo", realmTD, pluginsdk.SelectorConfig{MatchExpr: sel.MatchExpr, JWTAudience: sel.JWTAudience})
	if err != nil {
		return nil, fmt.Errorf("identity: core_identity: %w", err)
	}
	svids, err := z.coreRealm.FetchX509SVIDs(ctx)
	if err == nil {
		_, err = selector.Pick(svids)
	}
	if err != nil {
		return nil, fmt.Errorf("identity: core_identity: %w", err)
	}
	// a later update the selector does not match leaves no SVID: TLS then
	// fails closed until the registration is fixed
	z.core, err = workloadapi.NewX509Source(ctx, workloadapi.WithClient(z.coreRealm),
		workloadapi.WithDefaultX509SVIDPicker(func(svids []*x509svid.SVID) *x509svid.SVID {
			svid, _ := selector.Pick(svids)
			return svid
		}))
	if err != nil {
		return nil, fmt.Errorf("identity: core_identity: %w", err)
	}
	return z, nil
}

// route maps every trust domain to its one authoritative source: a realm's
// own, or that of the realm a federated trust domain comes through (§7.1).
func (z *Realms) route(cfg *config.Config, realm func(name string) bundles) error {
	add := func(name, via string) error {
		td, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			return fmt.Errorf("identity: trust domain %q: %w", name, err)
		}
		z.authority[td], z.via[td] = realm(via), via
		return nil
	}
	for _, zn := range cfg.Realms {
		if err := add(zn.TrustDomain, zn.Name); err != nil {
			return err
		}
	}
	for _, f := range cfg.Server.WorkloadListener.FederatedTrustDomains {
		if err := add(f.TrustDomain, f.ViaRealm); err != nil {
			return err
		}
	}
	return nil
}

// conflicts are the trust domains a realm's socket publishes bundles for
// although that realm is not their authoritative source (§7.1): unknown
// trust domains, and those of other realms or federated through another.
func (z *Realms) conflicts(realm string, published []spiffeid.TrustDomain) []spiffeid.TrustDomain {
	var out []spiffeid.TrustDomain
	for _, td := range published {
		if z.via[td] != realm {
			out = append(out, td)
		}
	}
	return out
}

// WatchConflicts asks every realm's socket for all the bundles it publishes,
// at once and then every interval; a bundle no routing uses because another
// source is authoritative for its trust domain is logged at WARN and
// counted once (ligo_bundle_conflicts_total, T-24), when it first appears.
func (z *Realms) WatchConflicts(ctx context.Context, log *slog.Logger, interval time.Duration) {
	seen := map[string]bool{}
	for {
		for i, client := range z.clients {
			set, err := client.FetchX509Bundles(ctx)
			if err != nil {
				if ctx.Err() == nil {
					log.Warn("identity: bundles of a realm's socket", "realm", z.names[i], "error", err)
				}
				continue
			}
			var published []spiffeid.TrustDomain
			for _, b := range set.Bundles() {
				published = append(published, b.TrustDomain())
			}
			for _, td := range z.conflicts(z.names[i], published) {
				if key := z.names[i] + "/" + td.String(); !seen[key] {
					seen[key] = true
					log.Warn("a bundle from a socket that is not its trust domain's authoritative source is discarded",
						"trust_domain", td.String(), "socket_realm", z.names[i], "authoritative_realm", z.via[td])
					metrics.BundleConflicts.WithLabelValues(td.String(), z.names[i]).Inc()
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

// GetX509BundleForTrustDomain implements x509bundle.Source over the realms.
func (z *Realms) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	src, ok := z.authority[td]
	if !ok {
		return nil, fmt.Errorf("identity: no realm is authoritative for trust domain %s", td)
	}
	return src.GetX509BundleForTrustDomain(td)
}

// GetJWTBundleForTrustDomain implements jwtbundle.Source over the realms.
func (z *Realms) GetJWTBundleForTrustDomain(td spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	src, ok := z.authority[td]
	if !ok {
		return nil, fmt.Errorf("identity: no realm is authoritative for trust domain %s", td)
	}
	return src.GetJWTBundleForTrustDomain(td)
}

// GetX509SVID is ligo's core identity, for tls_source: spiffe.
func (z *Realms) GetX509SVID() (*x509svid.SVID, error) { return z.core.GetX509SVID() }

// FetchJWT returns a JWT-SVID of the core identity for audience: the
// sealer's login to Vault Transit (sealing.JWTFetcher).
func (z *Realms) FetchJWT(ctx context.Context, audience string) (string, error) {
	svid, err := z.core.GetX509SVID()
	if err != nil {
		return "", err
	}
	jwt, err := z.coreRealm.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience, Subject: svid.ID})
	if err != nil {
		return "", fmt.Errorf("identity: JWT-SVID for %s: %w", audience, err)
	}
	return jwt.Marshal(), nil
}

// Close closes the sources and the clients.
func (z *Realms) Close() error {
	var errs []error
	if z.core != nil {
		errs = append(errs, z.core.Close())
	}
	for _, s := range z.sources {
		errs = append(errs, s.Close())
	}
	for _, c := range z.clients {
		errs = append(errs, c.Close())
	}
	return errors.Join(errs...)
}
