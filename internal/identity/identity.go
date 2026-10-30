// Package identity is ligo's side of SPIFFE (§7.1, §8.2 step 3): a
// Workload API client per zone, the composite bundle source that verifies
// client SVIDs, and ligo's own core identity.
package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// bundles is a zone's bundle stream: *workloadapi.BundleSource.
type bundles interface {
	x509bundle.Source
	jwtbundle.Source
}

// Zones holds the zones' Workload API connections.
type Zones struct {
	clients   []*workloadapi.Client
	sources   []*workloadapi.BundleSource
	authority map[spiffeid.TrustDomain]bundles // the one source of each trust domain
	core      *workloadapi.X509Source
	coreZone  *workloadapi.Client
}

// Open connects to every zones[].spiffe_workload_socket, starts each
// zone's bundle stream and acquires the core identity; it fails if the
// core identity's selector does not match exactly one SVID of its zone.
func Open(ctx context.Context, cfg *config.Config) (_ *Zones, err error) {
	z := &Zones{authority: map[spiffeid.TrustDomain]bundles{}}
	defer func() {
		if err != nil {
			_ = z.Close()
		}
	}()
	byZone := map[string]*workloadapi.BundleSource{}
	for _, zone := range cfg.Zones {
		client, err := workloadapi.New(ctx, workloadapi.WithAddr(zone.SPIFFEWorkloadSocket))
		if err != nil {
			return nil, fmt.Errorf("identity: zone %s: %w", zone.Name, err)
		}
		z.clients = append(z.clients, client)
		src, err := workloadapi.NewBundleSource(ctx, workloadapi.WithClient(client))
		if err != nil {
			return nil, fmt.Errorf("identity: zone %s: bundles: %w", zone.Name, err)
		}
		z.sources = append(z.sources, src)
		byZone[zone.Name] = src
		if zone.Name == cfg.CoreIdentity.Zone {
			z.coreZone = client
		}
	}
	if err := z.route(cfg, func(zone string) bundles { return byZone[zone] }); err != nil {
		return nil, err
	}
	zoneTD := ""
	for _, zone := range cfg.Zones {
		if zone.Name == cfg.CoreIdentity.Zone {
			zoneTD = zone.TrustDomain
		}
	}
	sel := cfg.CoreIdentity.SVIDSelector
	selector, err := pluginsdk.NewInstanceSVIDSelector(nil, "ligo", zoneTD, pluginsdk.SelectorConfig{MatchExpr: sel.MatchExpr, JWTAudience: sel.JWTAudience})
	if err != nil {
		return nil, fmt.Errorf("identity: core_identity: %w", err)
	}
	svids, err := z.coreZone.FetchX509SVIDs(ctx)
	if err == nil {
		_, err = selector.Pick(svids)
	}
	if err != nil {
		return nil, fmt.Errorf("identity: core_identity: %w", err)
	}
	// a later update the selector does not match leaves no SVID: TLS then
	// fails closed until the registration is fixed
	z.core, err = workloadapi.NewX509Source(ctx, workloadapi.WithClient(z.coreZone),
		workloadapi.WithDefaultX509SVIDPicker(func(svids []*x509svid.SVID) *x509svid.SVID {
			svid, _ := selector.Pick(svids)
			return svid
		}))
	if err != nil {
		return nil, fmt.Errorf("identity: core_identity: %w", err)
	}
	return z, nil
}

// route maps every trust domain to its one authoritative source: a zone's
// own, or that of the zone a federated trust domain comes through (§7.1).
func (z *Zones) route(cfg *config.Config, zone func(name string) bundles) error {
	add := func(name string, src bundles) error {
		td, err := spiffeid.TrustDomainFromString(name)
		if err != nil {
			return fmt.Errorf("identity: trust domain %q: %w", name, err)
		}
		z.authority[td] = src
		return nil
	}
	for _, zn := range cfg.Zones {
		if err := add(zn.TrustDomain, zone(zn.Name)); err != nil {
			return err
		}
	}
	for _, f := range cfg.Server.WorkloadListener.FederatedTrustDomains {
		if err := add(f.TrustDomain, zone(f.ViaZone)); err != nil {
			return err
		}
	}
	return nil
}

// GetX509BundleForTrustDomain implements x509bundle.Source over the zones.
func (z *Zones) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	src, ok := z.authority[td]
	if !ok {
		return nil, fmt.Errorf("identity: no zone is authoritative for trust domain %s", td)
	}
	return src.GetX509BundleForTrustDomain(td)
}

// GetJWTBundleForTrustDomain implements jwtbundle.Source over the zones.
func (z *Zones) GetJWTBundleForTrustDomain(td spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	src, ok := z.authority[td]
	if !ok {
		return nil, fmt.Errorf("identity: no zone is authoritative for trust domain %s", td)
	}
	return src.GetJWTBundleForTrustDomain(td)
}

// GetX509SVID is ligo's core identity, for tls_source: spiffe.
func (z *Zones) GetX509SVID() (*x509svid.SVID, error) { return z.core.GetX509SVID() }

// FetchJWT returns a JWT-SVID of the core identity for audience: the
// sealer's login to Vault Transit (sealing.JWTFetcher).
func (z *Zones) FetchJWT(ctx context.Context, audience string) (string, error) {
	svid, err := z.core.GetX509SVID()
	if err != nil {
		return "", err
	}
	jwt, err := z.coreZone.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience, Subject: svid.ID})
	if err != nil {
		return "", fmt.Errorf("identity: JWT-SVID for %s: %w", audience, err)
	}
	return jwt.Marshal(), nil
}

// Close closes the sources and the clients.
func (z *Zones) Close() error {
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
