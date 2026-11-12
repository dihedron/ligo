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
	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/instances"
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
	Name, Type, Realm, Jurisdiction                string
	AllowedTrustDomains                            []string
	IdentityProviderType, IdentityProviderInstance string
	SecretStoreType, SecretStoreInstance           string
	SecretStorageStrategy                          string // as filed; an omitted one is defaulted at filing (§5.6)
	PrincipalPrefix                                string
}

// Rules are the parts of the configuration, and the platforms in force,
// that validate bindings.
type Rules struct {
	Instances    instances.Source
	NamePrefixes []charter.NamePrefix
	Regex        regexpolicy.Policy
	MaxExpiry    time.Duration
	// Ligo is ligo's own flow (ADR-16), for the effective flows of a binding.
	Ligo flows.Flow
}

// NewRules extracts the rules from a validated configuration.
func NewRules(cfg *config.Config, in instances.Source) (*Rules, error) {
	wa := cfg.Service.WorkloadAdvertise
	return &Rules{Instances: in, NamePrefixes: cfg.Charter.NamePrefixes, Regex: cfg.RegexPolicy, MaxExpiry: cfg.Bindings.MaxExpiry,
		Ligo: flows.LigoFlow(wa.Destination, wa.Port, wa.ServerName)}, nil
}

// Platform is the platform in force called name.
func (r *Rules) Platform(name string) (Platform, bool) {
	p, ok := r.Instances.Current().Platform(name)
	if !ok {
		return Platform{}, false
	}
	out := Platform{Name: p.Metadata.Name, Type: p.Type, Realm: p.Metadata.Realm, Jurisdiction: p.Metadata.Jurisdiction,
		AllowedTrustDomains: p.AllowedSourceTrustDomains, PrincipalPrefix: p.PrincipalPrefix}
	if w := p.IdentityProvider; w != nil {
		out.IdentityProviderType, out.IdentityProviderInstance = w.Type, w.Instance
	}
	if w := p.SecretStore; w != nil {
		out.SecretStoreType, out.SecretStoreInstance, out.SecretStorageStrategy = w.Type, w.Instance, w.SecretStorageStrategy
	}
	return out, true
}

// Allow is a platform's allowed_endpoints: target flows outside it are left
// out of effective flows (§8.2 rule 19).
func (r *Rules) Allow(platform string) flows.Allowlist { return r.Instances.Current().Allow(platform) }

// PlatformFlows are the flows a platform declares.
func (r *Rules) PlatformFlows(platform string) []flows.Flow {
	return r.Instances.Current().Flows(instances.Platform, platform)
}

// StoreFlows are the flows a secret store instance declares.
func (r *Rules) StoreFlows(store string) []flows.Flow {
	return r.Instances.Current().Flows(instances.SecretStore, store)
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

// Recheck fails a cross-jurisdiction request with consent ALL that the policy now
// in force denies, or that lacks a party it now requires (ADR-14 rule 5).
// Parties the policy no longer requires do not let it pass more easily:
// their sides were stored and still need their decisions.
func (s *Service) Recheck(r *changerequests.Request, p *charter.Policy) error {
	if r.Consent != changerequests.ConsentAll || r.SourceJurisdiction == r.TargetJurisdiction {
		return nil
	}
	d := p.Evaluate(r.SourceJurisdiction, r.TargetJurisdiction)
	if !d.Allowed {
		return refuse(409, "charter-changed", "the interconnection policy now denies this pair (%s): file the change again", d.Rule)
	}
	for _, a := range d.AdditionalApprovals {
		if !slices.ContainsFunc(r.Sides, func(sd changerequests.Side) bool { return sd.Name == "PARTY:"+a.Name }) {
			return refuse(409, "charter-changed", "the policy now requires the party %s: file the change again", a.Name)
		}
	}
	return nil
}
