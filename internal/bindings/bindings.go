// Package bindings files and applies the change requests of bindings
// (§3.5, §7.2.3, §6.2.2): their validation pipeline, with the
// interconnection policy (ADR-14) and the platform's ValidateBinding, and
// the transaction that starts a binding's revision.
package bindings

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/internal/regexpolicy"
)

// Binding is the desired state of a binding (§7.2.3); normalized, it is
// the payload of its change requests.
type Binding struct {
	Kind           string            `json:"kind,omitempty"` // "Binding" once normalized
	Name           string            `json:"name"`
	Source         string            `json:"source"`
	SourceRevision int64             `json:"sourceRevision,omitempty"`
	Target         string            `json:"target"`
	TargetRevision int64             `json:"targetRevision,omitempty"`
	AccessLevel    string            `json:"accessLevel"`
	Parameters     json.RawMessage   `json:"parameters,omitempty"`
	RequestedSpec  json.RawMessage   `json:"requestedSpec,omitempty"` // from ValidateBinding
	Purpose        string            `json:"purpose,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	ExpiresAt      *time.Time        `json:"expiresAt"`
}

// ValidateBinding calls PlatformProvider.ValidateBinding on the platform
// the request names (§5.9).
type ValidateBinding func(ctx context.Context, req *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error)

// Plugins calls ValidateBinding through the plugin manager.
func Plugins(m *pluginmgr.Manager) ValidateBinding {
	return func(ctx context.Context, req *pluginv1.ValidateBindingRequest) (resp *pluginv1.ValidateBindingResponse, err error) {
		err = m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, req.GetInstance(), false, func(ctx context.Context, c *pluginmgr.Client) error {
			resp, err = c.Platform.ValidateBinding(ctx, req)
			return err
		})
		return resp, err
	}
}

// Platform is what bindings need of a configured platform (§8.1).
type Platform struct {
	Name, Type, Zone, Scope                        string
	AllowedTrustDomains                            []string
	IdentityProviderType, IdentityProviderInstance string
	SecretStoreType, SecretStoreInstance           string
	SecretStorageStrategy                          string // as configured; startup defaults an omitted one (§5.6)
	PrincipalPrefix                                string
}

// Rules are the parts of the configuration that validate bindings.
type Rules struct {
	Platforms    map[string]Platform
	NamePrefixes []governance.NamePrefix
	Regex        regexpolicy.Policy
	MaxExpiry    time.Duration
	// the flows declared by platforms and secret store instances, and
	// ligo's own (ADR-16), for the effective flows of a binding
	PlatformFlows, StoreFlows map[string][]flows.Flow
	Ligo                      flows.Flow
}

// NewRules extracts the rules from a validated configuration.
func NewRules(cfg *config.Config) (*Rules, error) {
	wa := cfg.Service.WorkloadAdvertise
	r := &Rules{Platforms: map[string]Platform{}, NamePrefixes: cfg.Governance.NamePrefixes, Regex: cfg.RegexPolicy,
		MaxExpiry: cfg.Bindings.MaxExpiry, PlatformFlows: map[string][]flows.Flow{}, StoreFlows: map[string][]flows.Flow{},
		Ligo: flows.LigoFlow(wa.Destination, wa.Port, wa.ServerName)}
	for _, ss := range cfg.SecretStores {
		for _, in := range ss.Instances {
			r.StoreFlows[in.Name] = in.NetworkFlows
		}
	}
	for _, pp := range cfg.PlatformProviders {
		for _, p := range pp.Platforms {
			r.PlatformFlows[p.Name] = p.NetworkFlows
			r.Platforms[p.Name] = Platform{Name: p.Name, Type: pp.Type, Zone: p.Zone, Scope: p.Scope,
				AllowedTrustDomains: p.AllowedSourceTrustDomains, PrincipalPrefix: p.PrincipalPrefix,
				IdentityProviderType: p.IdentityProvider.Type, IdentityProviderInstance: p.IdentityProvider.Instance,
				SecretStoreType: p.SecretStore.Type, SecretStoreInstance: p.SecretStore.Instance,
				SecretStorageStrategy: p.SecretStore.SecretStorageStrategy}
		}
	}
	return r, nil
}

func refuse(status int, slug, format string, args ...any) *changerequests.Error {
	return &changerequests.Error{Status: status, Slug: slug, Detail: fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) *changerequests.Error {
	return refuse(422, "validation-failed", format, args...)
}

// checkExpiry: an expiry is at least an hour and at most max_expiry ahead
// (§3.5).
func (r *Rules) checkExpiry(e *time.Time, now time.Time) error {
	if e != nil && (e.Before(now.Add(time.Hour)) || e.After(now.Add(r.MaxExpiry))) {
		return invalid("expiresAt must be between 1 hour and %s from now", r.MaxExpiry)
	}
	return nil
}

// Recheck fails a cross-scope request with consent ALL that the policy now
// in force denies, or that lacks a party it now requires (ADR-14 rule 5).
// Parties the policy no longer requires do not let it pass more easily:
// their sides were stored and still need their decisions.
func (s *Service) Recheck(r *changerequests.Request, p *governance.Policy) error {
	if r.Consent != changerequests.ConsentAll || r.SourceScope == r.TargetScope {
		return nil
	}
	d := p.Evaluate(r.SourceScope, r.TargetScope)
	if !d.Allowed {
		return refuse(409, "governance-policy-changed", "the interconnection policy now denies this pair (%s): file the change again", d.Rule)
	}
	for _, a := range d.AdditionalApprovals {
		if !slices.ContainsFunc(r.Sides, func(sd changerequests.Side) bool { return sd.Name == "PARTY:"+a.Name }) {
			return refuse(409, "governance-policy-changed", "the policy now requires the party %s: file the change again", a.Name)
		}
	}
	return nil
}
