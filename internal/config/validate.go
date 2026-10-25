package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Options are the command-line settings that change validation.
type Options struct {
	// InsecureDev allows the local-kek sealer (§8.2 rule 9).
	InsecureDev bool
	// LookupEnv reads the environment; nil means os.LookupEnv.
	LookupEnv func(string) (string, bool)
}

var (
	sha256RE        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ruleNameRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)
	partyNameRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	knownRoles      = []string{RoleViewer, RoleOperator, RoleApprover, RoleBreakGlass, RoleTrustedAutomation, RoleFullAccess}
	knownKinds      = []engine.Kind{engine.KindSource, engine.KindTarget, engine.KindBinding}
	maxPlatformFlow = 32
)

// checker collects the failures of every rule, so that one run reports them
// all.
type checker struct {
	errs []error
}

func (c *checker) failf(rule int, format string, args ...any) {
	c.errs = append(c.errs, fmt.Errorf("rule %d: %s", rule, fmt.Sprintf(format, args...)))
}

// Validate applies the static rules of §8.2: 1, 2, 5, 6, 7 (format), 9, 12,
// 13, 14, 16 and the static part of 19. Rule 15 (theme) is checked with the
// UI; rules 3, 4, 8 and the rest of 19 once plugins run; rules 10, 11, 17
// and 18 once the database is connected.
func Validate(cfg *Config, opts Options) error {
	if opts.LookupEnv == nil {
		opts.LookupEnv = os.LookupEnv
	}
	c := &checker{}
	zones := c.zones(cfg)
	c.instances(cfg, zones)
	c.trustDomains(cfg, zones)
	c.sealing(cfg, opts)
	c.authorization(cfg)
	c.breakGlass(cfg, opts)
	c.governance(cfg)
	c.platformFlows(cfg)
	return errors.Join(c.errs...)
}

// zones checks rule 1 for zones and returns them by name.
func (c *checker) zones(cfg *Config) map[string]Zone {
	zones := map[string]Zone{}
	for _, z := range cfg.Zones {
		if _, dup := zones[z.Name]; dup {
			c.failf(1, "zone %q is defined twice", z.Name)
		}
		if _, err := spiffeid.TrustDomainFromString(z.TrustDomain); err != nil {
			c.failf(2, "zone %q: invalid trust domain %q", z.Name, z.TrustDomain)
		}
		zones[z.Name] = z
	}
	if _, ok := zones[cfg.CoreIdentity.Zone]; !ok {
		c.failf(2, "core_identity.zone %q is not a configured zone", cfg.CoreIdentity.Zone)
	}
	return zones
}

// instances checks rules 1, 2, 5 and 7 for plugin types, instances and
// platforms.
func (c *checker) instances(cfg *Config, zones map[string]Zone) {
	// instance zones by type, then name
	zoneOf := map[string]map[string]string{}
	providers := func(kind string, list []InstanceProvider) {
		names := map[string]bool{}
		for _, p := range list {
			c.binary(kind, p.Type, p.Builtin, p.Binary, p.SHA256)
			if zoneOf[p.Type] != nil {
				c.failf(1, "%s type %q is declared twice", kind, p.Type)
			}
			zoneOf[p.Type] = map[string]string{}
			for _, in := range p.Instances {
				if names[in.Name] {
					c.failf(1, "%s instance %q is defined twice", kind, in.Name)
				}
				names[in.Name] = true
				zoneOf[p.Type][in.Name] = in.Zone
				if _, ok := zones[in.Zone]; !ok {
					c.failf(2, "%s instance %q: zone %q does not exist", kind, in.Name, in.Zone)
				}
				c.plugin(kind+" instance "+in.Name, p.Builtin, in.SVIDSelector, &in)
			}
		}
	}
	providers("identity provider", cfg.IdentityProviders)
	providers("secret store", cfg.SecretStores)

	platforms := map[string]bool{}
	for _, tp := range cfg.TargetProviders {
		c.binary("target provider", tp.Type, tp.Builtin, tp.Binary, tp.SHA256)
		for _, p := range tp.Platforms {
			if platforms[p.Name] {
				c.failf(1, "platform %q is defined twice", p.Name)
			}
			platforms[p.Name] = true
			if _, ok := zones[p.Zone]; !ok {
				c.failf(2, "platform %q: zone %q does not exist", p.Name, p.Zone)
			}
			for role, w := range map[string]Wiring{"identity_provider": p.IdentityProvider, "secret_store": p.SecretStore} {
				z, ok := zoneOf[w.Type][w.Instance]
				switch {
				case !ok:
					c.failf(2, "platform %q: %s %s/%s does not exist", p.Name, role, w.Type, w.Instance)
				case z != p.Zone:
					c.failf(2, "platform %q (zone %s): %s %q is in zone %s", p.Name, p.Zone, role, w.Instance, z)
				}
			}
			c.plugin("platform "+p.Name, tp.Builtin, p.SVIDSelector, &Instance{Config: p.Config})
		}
	}
}

// binary checks rule 7 (format only: the file checks need the plugin
// manager).
func (c *checker) binary(kind, typ string, builtin bool, binary, sum string) {
	switch {
	case builtin && (binary != "" || sum != ""):
		c.failf(7, "%s %q is builtin and must not name a binary", kind, typ)
	case !builtin && (binary == "" || strings.Contains(binary, "/")):
		c.failf(7, "%s %q: binary must be a file name in plugins.directory", kind, typ)
	case !builtin && !sha256RE.MatchString(sum):
		c.failf(7, "%s %q: sha256 must be 64 lowercase hex characters", kind, typ)
	}
}

// plugin checks rule 5, and that external instances have a selector.
func (c *checker) plugin(what string, builtin bool, sel *SVIDSelector, in *Instance) {
	if !builtin && (sel == nil || sel.MatchExpr == "") {
		c.failf(4, "%s: svid_selector.match_expr is required", what)
	}
	pc, err := hostKeys(&in.Config)
	if err != nil {
		c.failf(8, "%s: config: %v", what, err)
		return
	}
	if pc.BootstrapCredential != nil && (sel == nil || !slices.Contains(sel.JWTAudience, pc.BootstrapCredential.JWTAudience)) {
		c.failf(5, "%s: bootstrap_credential.jwt_audience %q is not in svid_selector.jwt_audience", what, pc.BootstrapCredential.JWTAudience)
	}
}

// trustDomains checks rules 6 and 12.
func (c *checker) trustDomains(cfg *Config, zones map[string]Zone) {
	zoneDomains := map[string]int{}
	for _, z := range zones {
		zoneDomains[z.TrustDomain]++
	}
	federated := map[string]int{}
	wl := cfg.Server.WorkloadListener
	for _, f := range wl.FederatedTrustDomains {
		federated[f.TrustDomain]++
		if _, ok := zones[f.ViaZone]; !ok {
			c.failf(12, "federated trust domain %q: via_zone %q is not a configured zone", f.TrustDomain, f.ViaZone)
		}
	}
	check := func(where string, domains []string) {
		for _, td := range domains {
			z, f := zoneDomains[td], federated[td]
			if z+f != 1 {
				c.failf(12, "%s: trust domain %q must be the trust domain of exactly one zone or listed once in federated_trust_domains, not both", where, td)
			}
		}
	}
	check("workload_listener.accepted_trust_domains", wl.AcceptedTrustDomains)
	check("admin_listener.client_svid_auth.accepted_trust_domains", cfg.Server.AdminListener.ClientSVIDAuth.AcceptedTrustDomains)
	for _, tp := range cfg.TargetProviders {
		for _, p := range tp.Platforms {
			for _, td := range p.AllowedSourceTrustDomains {
				if !slices.Contains(wl.AcceptedTrustDomains, td) {
					c.failf(6, "platform %q: allowed source trust domain %q is not in workload_listener.accepted_trust_domains", p.Name, td)
				}
			}
		}
	}
}

// sealing checks rule 9.
func (c *checker) sealing(cfg *Config, opts Options) {
	switch cfg.SecretSealing.Provider {
	case "vault-transit":
	case "local-kek":
		if !opts.InsecureDev {
			c.failf(9, "secret_sealing.provider local-kek requires --insecure-dev")
		}
		if cfg.SecretSealing.LocalKEKFile == "" {
			c.failf(9, "secret_sealing.local_kek_file is required with local-kek")
		}
	default:
		c.failf(9, "secret_sealing.provider must be vault-transit or local-kek, not %q", cfg.SecretSealing.Provider)
	}
}

// authorization checks rules 13 and 14 (bindings) and the scope patterns of
// rule 16.
func (c *checker) authorization(cfg *Config) {
	platforms := map[string]bool{}
	for _, tp := range cfg.TargetProviders {
		for _, p := range tp.Platforms {
			platforms[p.Name] = true
		}
	}
	for i, b := range cfg.Authorization.Bindings {
		who := b.LDAPGroupDN + b.SPIFFEID
		if (b.LDAPGroupDN == "") == (b.SPIFFEID == "") {
			c.failf(16, "authorization binding %d: exactly one of ldap_group_dn and spiffe_id is required", i)
		}
		if b.SPIFFEID != "" {
			if _, err := spiffeid.FromString(b.SPIFFEID); err != nil {
				c.failf(16, "authorization binding %d: invalid spiffe_id %q", i, b.SPIFFEID)
			}
		}
		if !slices.Contains(knownRoles, b.Role) {
			c.failf(16, "authorization binding %q: unknown role %q", who, b.Role)
		}
		if len(b.Scopes) == 0 {
			c.failf(16, "authorization binding %q: scopes is required", who)
		}
		c.patterns(16, "authorization binding "+who, b.Scopes)
		if b.Role != RoleTrustedAutomation && (len(b.Platforms) > 0 || b.ApprovalReferencePattern != "") {
			c.failf(13, "authorization binding %q: platforms and approval_reference_pattern are only for trusted_automation", who)
		}
		switch b.Role {
		case RoleTrustedAutomation:
			if b.SPIFFEID == "" {
				c.failf(13, "trusted_automation must be bound to a spiffe_id, never to an LDAP group (%q)", who)
			}
			for _, p := range b.Platforms {
				if !platforms[p] {
					c.failf(13, "trusted_automation %q: platform %q does not exist", who, p)
				}
			}
			if b.ApprovalReferencePattern != "" {
				c.anchored(13, "trusted_automation "+who+" approval_reference_pattern", b.ApprovalReferencePattern)
			}
		case RoleBreakGlass:
			if b.LDAPGroupDN == "" {
				c.failf(14, "break_glass must be bound to an ldap_group_dn, never to a SPIFFE ID (%q)", who)
			}
			for _, s := range b.Scopes {
				if !slices.ContainsFunc(cfg.BreakGlass.Policies, func(p BreakGlassPolicy) bool { return slices.Contains(p.Scopes, s) }) {
					c.failf(14, "break_glass binding %q: scope pattern %q appears in no break_glass.policies entry", who, s)
				}
			}
		}
	}
	c.patterns(16, "approval.required_scopes", cfg.Authorization.Approval.RequiredScopes)
}

// breakGlass checks rule 14 (policies and webhooks).
func (c *checker) breakGlass(cfg *Config, opts Options) {
	bg := cfg.BreakGlass
	if bg.MinJustificationLength < 20 {
		c.failf(14, "break_glass.min_justification_length must be at least 20")
	}
	if bg.IncidentReferencePattern != "" {
		c.anchored(14, "break_glass.incident_reference_pattern", bg.IncidentReferencePattern)
	}
	for i, p := range bg.Policies {
		if p.DefaultTTL < 5*time.Minute || p.DefaultTTL > p.MaxTTL || p.MaxTTL > 24*time.Hour {
			c.failf(14, "break_glass.policies[%d]: need 5m <= default_ttl <= max_ttl <= 24h", i)
		}
		if p.MaxOpen < 1 {
			c.failf(14, "break_glass.policies[%d]: max_open must be at least 1", i)
		}
		c.patterns(16, fmt.Sprintf("break_glass.policies[%d]", i), p.Scopes)
	}
	for _, w := range cfg.Notifications.Webhooks {
		if u, err := url.Parse(w.URL); err != nil || u.Scheme != "https" || u.Host == "" {
			c.failf(14, "webhook %q: url must be https://", w.Name)
		}
		if v, ok := opts.LookupEnv(w.HMACSecretEnv); w.HMACSecretEnv == "" || !ok || v == "" {
			c.failf(14, "webhook %q: hmac_secret_env %q is not set", w.Name, w.HMACSecretEnv)
		}
		c.patterns(14, "webhook "+w.Name+" scopes", w.Scopes)
	}
}

// governance checks rule 16.
func (c *checker) governance(cfg *Config) {
	sourceDomains := map[string]bool{}
	for _, tp := range cfg.TargetProviders {
		for _, p := range tp.Platforms {
			if !governance.ValidScopePath(p.Scope) {
				c.failf(16, "platform %q: scope %q must be a valid scope path", p.Name, p.Scope)
			}
			c.patterns(16, "platform "+p.Name+" target_scopes", p.TargetScopes)
			for _, td := range p.AllowedSourceTrustDomains {
				sourceDomains[td] = true
			}
		}
	}
	seen := map[string]bool{}
	for _, s := range cfg.Governance.SourceScopes {
		if seen[s.TrustDomain] {
			c.failf(16, "governance.source_scopes: trust domain %q has more than one entry", s.TrustDomain)
		}
		seen[s.TrustDomain] = true
		if !sourceDomains[s.TrustDomain] {
			c.failf(16, "governance.source_scopes: trust domain %q is not accepted by any platform", s.TrustDomain)
		}
		if _, err := s.Extractor(); err != nil {
			c.failf(16, "governance.source_scopes[%s]: %v", s.TrustDomain, err)
		}
	}
	for td := range sourceDomains {
		if !seen[td] {
			c.failf(16, "governance.source_scopes: no entry for trust domain %q", td)
		}
	}
	for i, p := range cfg.Governance.NamePrefixes {
		c.patterns(16, fmt.Sprintf("governance.name_prefixes[%d]", i), p.Scopes)
		for _, k := range p.Resources {
			if !slices.Contains(knownKinds, k) {
				c.failf(16, "governance.name_prefixes[%d]: unknown resource %q", i, k)
			}
		}
	}
	ic := cfg.Governance.Interconnects
	if ic.DefaultCrossScope != "allow" && ic.DefaultCrossScope != "deny" {
		c.failf(16, "interconnects.default_cross_scope must be allow or deny")
	}
	names := map[string]bool{}
	for _, r := range ic.Rules {
		if !ruleNameRE.MatchString(r.Name) || r.Name == "default" || names[r.Name] {
			c.failf(16, "interconnect rule %q: names must be unique, match %s and not be \"default\"", r.Name, ruleNameRE)
		}
		names[r.Name] = true
		if r.Action != "allow" && r.Action != "deny" {
			c.failf(16, "interconnect rule %q: action must be allow or deny", r.Name)
		}
		c.patterns(16, "interconnect rule "+r.Name+" from", r.From)
		c.patterns(16, "interconnect rule "+r.Name+" to", r.To)
		if r.Action != "allow" && (len(r.AdditionalApprovals) > 0 || r.DistinctApprovers != nil) {
			c.failf(16, "interconnect rule %q: additional_approvals and distinct_approvers are only for allow rules", r.Name)
		}
		parties := map[string]bool{}
		for _, a := range r.AdditionalApprovals {
			if !partyNameRE.MatchString(a.Name) || parties[a.Name] || !governance.ValidScopePath(a.Scope) {
				c.failf(16, "interconnect rule %q: additional approval %q needs a unique name matching %s and a valid scope path", r.Name, a.Name, partyNameRE)
			}
			parties[a.Name] = true
		}
	}
}

// Extractor returns the scope extractor of a source_scopes entry.
func (s SourceScope) Extractor() (*governance.Extractor, error) {
	switch s.Mode {
	case "static":
		return governance.NewStaticExtractor(s.Scope)
	case "path_template":
		return governance.NewPathTemplateExtractor(s.PathRegex, s.ScopeTemplate)
	}
	return nil, fmt.Errorf("mode must be static or path_template, not %q", s.Mode)
}

// platformFlows checks the static part of rule 19.
func (c *checker) platformFlows(cfg *Config) {
	check := func(what string, declared []flows.Flow, config *Instance) {
		pc, err := hostKeys(&config.Config)
		if err != nil {
			return // reported by plugin()
		}
		if err := flows.ValidateList(declared, maxPlatformFlow); err != nil {
			c.failf(19, "%s: %v", what, err)
			return
		}
		allow, err := flows.ParseAllowlist(pc.AllowedEndpoints)
		if err != nil {
			c.failf(19, "%s: %v", what, err)
			return
		}
		for _, f := range declared {
			if err := allow.CheckFlow(f); err != nil {
				c.failf(19, "%s: %v", what, err)
			}
		}
	}
	for _, tp := range cfg.TargetProviders {
		for _, p := range tp.Platforms {
			check("platform "+p.Name, p.NetworkFlows, &Instance{Config: p.Config})
		}
	}
	for _, sp := range cfg.SecretStores {
		for _, in := range sp.Instances {
			check("secret store "+in.Name, in.NetworkFlows, &in)
		}
	}
	for _, ip := range cfg.IdentityProviders {
		for _, in := range ip.Instances {
			if len(in.NetworkFlows) > 0 {
				c.failf(19, "identity provider %q: network_flows are declared by platforms and secret stores only", in.Name)
			}
		}
	}
	wa := cfg.Service.WorkloadAdvertise
	ligo := flows.LigoFlow(wa.Destination, wa.Port, wa.ServerName)
	if wa.Destination == "" || wa.Port == 0 {
		c.failf(19, "service.workload_advertise must be set")
	} else if err := ligo.Validate(); err != nil {
		c.failf(19, "service.workload_advertise: %v", err)
	}
}

// patterns checks that each entry is a valid scope pattern.
func (c *checker) patterns(rule int, where string, patterns []string) {
	for _, p := range patterns {
		if !governance.ValidScopePattern(p) {
			c.failf(rule, "%s: %q is not a valid scope pattern", where, p)
		}
	}
}

// anchored checks that a pattern is a fully anchored RE2.
func (c *checker) anchored(rule int, where, pattern string) {
	if _, err := regexp.Compile(pattern); err != nil || !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
		c.failf(rule, "%s must be an RE2 starting with ^ and ending with $", where)
	}
}
