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
	"uuid"

	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/theme"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"go.yaml.in/yaml/v3"
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
	knownRoles      = []string{RoleViewer, RoleOperator, RoleApprover, RoleBreakGlass, RoleTrustedAutomation, RoleFullAccess, RoleAccountAdmin}
	knownKinds      = []string{string(engine.KindSource), string(engine.KindTarget), string(engine.KindBinding)}
	maxPlatformFlow = 32
	// instanceIDRE leaves room for "ligo/" in the 63 bytes of application_name
	instanceIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,58}$`)
)

// accountRoles are the roles a group of an account may give: people's roles
// on the account's jurisdictions, never trusted_automation or a global one.
var accountRoles = []string{RoleViewer, RoleOperator, RoleApprover, RoleBreakGlass}

// checker collects the failures of every rule, so that one run reports them
// all.
type checker struct {
	errs []error
}

func (c *checker) failf(rule int, format string, args ...any) {
	c.errs = append(c.errs, fmt.Errorf("rule %d: %s", rule, fmt.Sprintf(format, args...)))
}

// Validate applies the static rules of §8.2: 1, 2, 5, 6, 7 (format), 9, 12,
// 13, 14, 16, the static parts of 15 and 19. Rule 15's files are checked by
// theme.Load; rules 3, 4, 8 and the rest of 19 once plugins run; rules 10,
// 11, 17 and 18 once the database is connected.
func Validate(cfg *Config, opts Options) error {
	if opts.LookupEnv == nil {
		opts.LookupEnv = os.LookupEnv
	}
	c := &checker{}
	if id, _ := opts.LookupEnv(cfg.Service.InstanceIDEnv); !instanceIDRE.MatchString(id) {
		c.failf(1, "service.instance_id_env %q: the instance ID %q must match %s", cfg.Service.InstanceIDEnv, id, instanceIDRE)
	}
	realms := c.realms(cfg)
	c.instances(cfg, realms)
	c.trustDomains(cfg, realms)
	c.sealing(cfg, opts)
	c.authorization(cfg)
	c.breakGlass(cfg, opts)
	c.charter(cfg)
	c.platformFlows(cfg)
	c.theme(cfg)
	return errors.Join(c.errs...)
}

// theme checks the static part of rule 15: the default mode, and every
// color a known token with a CSS hex value (§7.6).
func (c *checker) theme(cfg *Config) {
	th := cfg.UI.Theme
	if !slices.Contains(theme.Modes, th.DefaultMode) {
		c.failf(15, "ui.theme.default_mode %q is not one of %v", th.DefaultMode, theme.Modes)
	}
	for mode, colors := range th.Colors {
		if mode != "light" && mode != "dark" {
			c.failf(15, "ui.theme.colors: unknown mode %q", mode)
		}
		for name, value := range colors {
			if !slices.Contains(theme.Tokens, name) {
				c.failf(15, "ui.theme.colors.%s: unknown token %q", mode, name)
			}
			if !theme.ValidColor(value) {
				c.failf(15, "ui.theme.colors.%s.%s: %q is not a CSS hex color", mode, name, value)
			}
		}
	}
}

// realms checks rule 1 for realms and returns them by name.
func (c *checker) realms(cfg *Config) map[string]Realm {
	realms := map[string]Realm{}
	for _, z := range cfg.Realms {
		if _, dup := realms[z.Name]; dup {
			c.failf(1, "realm %q is defined twice", z.Name)
		}
		if _, err := spiffeid.TrustDomainFromString(z.TrustDomain); err != nil {
			c.failf(2, "realm %q: invalid trust domain %q", z.Name, z.TrustDomain)
		}
		realms[z.Name] = z
	}
	if _, ok := realms[cfg.CoreIdentity.Realm]; !ok {
		c.failf(2, "core_identity.realm %q is not a configured realm", cfg.CoreIdentity.Realm)
	}
	return realms
}

const (
	platformPrefix = "platform "
	whatErr        = "%s: %v"
)

// allPlatforms returns the platforms of every platform provider, with their
// provider.
func allPlatforms(cfg *Config) []providedPlatform {
	var out []providedPlatform
	for _, tp := range cfg.PlatformProviders {
		for _, p := range tp.Platforms {
			out = append(out, providedPlatform{p, tp.Builtin})
		}
	}
	return out
}

type providedPlatform struct {
	Platform
	builtin bool
}

// instances checks rules 1, 2, 5 and 7 for plugin types, instances and
// platforms.
func (c *checker) instances(cfg *Config, realms map[string]Realm) {
	// instance realms by type, then name
	realmOf := map[string]map[string]string{}
	c.instanceProviders("identity provider", cfg.IdentityProviders, realms, realmOf)
	c.instanceProviders("secret store", cfg.SecretStores, realms, realmOf)
	for _, tp := range cfg.PlatformProviders {
		c.binary("platform provider", tp.Type, tp.Builtin, tp.Binary, tp.SHA256)
		if realmOf[tp.Type] != nil {
			c.failf(1, "platform provider type %q is declared twice", tp.Type)
			continue
		}
		realmOf[tp.Type] = map[string]string{} // a platform provider has no instances to wire
	}
	names := map[string]bool{}
	for _, p := range allPlatforms(cfg) {
		if names[p.Name] {
			c.failf(1, "platform %q is defined twice", p.Name)
		}
		names[p.Name] = true
		if _, ok := realms[p.Realm]; !ok {
			c.failf(2, "platform %q: realm %q does not exist", p.Name, p.Realm)
		}
		c.wiring(p.Platform, "identity_provider", p.IdentityProvider, realmOf)
		c.wiring(p.Platform, "secret_store", p.SecretStore, realmOf)
		c.plugin(platformPrefix+p.Name, p.builtin, p.SVIDSelector, &Instance{Config: p.Config})
	}
}

// instanceProviders checks the plugin types of one kind and their instances,
// recording the realm of each instance in realmOf.
func (c *checker) instanceProviders(kind string, list []InstanceProvider, realms map[string]Realm, realmOf map[string]map[string]string) {
	names := map[string]bool{}
	for _, p := range list {
		c.binary(kind, p.Type, p.Builtin, p.Binary, p.SHA256)
		if realmOf[p.Type] != nil {
			c.failf(1, "%s type %q is declared twice", kind, p.Type)
		}
		realmOf[p.Type] = map[string]string{}
		for _, in := range p.Instances {
			if names[in.Name] {
				c.failf(1, "%s instance %q is defined twice", kind, in.Name)
			}
			if !ruleNameRE.MatchString(in.Name) {
				c.failf(1, "%s instance %q: the name must match %s", kind, in.Name, ruleNameRE)
			}
			names[in.Name] = true
			realmOf[p.Type][in.Name] = in.Realm
			if _, ok := realms[in.Realm]; !ok {
				c.failf(2, "%s instance %q: realm %q does not exist", kind, in.Name, in.Realm)
			}
			c.plugin(kind+" instance "+in.Name, p.Builtin, in.SVIDSelector, &in)
		}
	}
}

// wiring checks that a platform's instance exists in the platform's realm.
func (c *checker) wiring(p Platform, role string, w Wiring, realmOf map[string]map[string]string) {
	z, ok := realmOf[w.Type][w.Instance]
	switch {
	case !ok:
		c.failf(2, "platform %q: %s %s/%s does not exist", p.Name, role, w.Type, w.Instance)
	case z != p.Realm:
		c.failf(2, "platform %q (realm %s): %s %q is in realm %s", p.Name, p.Realm, role, w.Instance, z)
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

// plugin checks rule 5, and that external instances have a selector that
// compiles (§5.4).
func (c *checker) plugin(what string, builtin bool, sel *SVIDSelector, in *Instance) {
	if !builtin && (sel == nil || sel.MatchExpr == "") {
		c.failf(4, "%s: svid_selector.match_expr is required", what)
	} else if sel != nil && sel.MatchExpr != "" {
		if _, err := pluginsdk.CompileSelector(sel.MatchExpr); err != nil {
			c.failf(4, "%s: svid_selector.match_expr: %v", what, err)
		}
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
func (c *checker) trustDomains(cfg *Config, realms map[string]Realm) {
	realmDomains := map[string]int{}
	for _, z := range realms {
		realmDomains[z.TrustDomain]++
	}
	federated := map[string]int{}
	wl := cfg.Server.WorkloadListener
	for _, f := range wl.FederatedTrustDomains {
		federated[f.TrustDomain]++
		if _, ok := realms[f.ViaRealm]; !ok {
			c.failf(12, "federated trust domain %q: via_realm %q is not a configured realm", f.TrustDomain, f.ViaRealm)
		}
	}
	check := func(where string, domains []string) {
		for _, td := range domains {
			if realmDomains[td]+federated[td] != 1 {
				c.failf(12, "%s: trust domain %q must be the trust domain of exactly one realm or listed once in federated_trust_domains, not both", where, td)
			}
		}
	}
	check("workload_listener.accepted_trust_domains", wl.AcceptedTrustDomains)
	if len(wl.AuthModes) == 0 {
		c.failf(12, "workload_listener.auth_modes is empty")
	}
	for _, m := range wl.AuthModes {
		switch {
		case m != AuthX509SVID && m != AuthJWTSVID:
			c.failf(12, "workload_listener.auth_modes: unknown mode %q", m)
		case m == AuthJWTSVID && wl.ExpectedJWTAudience == "":
			c.failf(12, "workload_listener.auth_modes: jwt_svid needs expected_jwt_audience")
		}
	}
	check("admin_listener.client_svid_auth.accepted_trust_domains", cfg.Server.AdminListener.ClientSVIDAuth.AcceptedTrustDomains)
	for _, p := range allPlatforms(cfg) {
		for _, td := range p.AllowedSourceTrustDomains {
			if !slices.Contains(wl.AcceptedTrustDomains, td) {
				c.failf(6, "platform %q: allowed source trust domain %q is not in workload_listener.accepted_trust_domains", p.Name, td)
			}
		}
		if _, err := engine.DerivedPrincipalName(uuid.UUID{}, p.PrincipalPrefix); err != nil {
			c.failf(6, "platform %q: %v", p.Name, err)
		}
	}
}

// sealing checks rule 9, and the deadline for SPIRE and the sealer to be
// ready at startup.
func (c *checker) sealing(cfg *Config, opts Options) {
	if t := cfg.Service.StartupTimeout; t < 5*time.Second || t > 10*time.Minute {
		c.failf(9, "service.startup_timeout %s: between 5s and 10m", t)
	}
	if n := cfg.Server.AdminListener.RateLimit.MaxTrackedKeys; n < 10_000 || n > 10_000_000 {
		c.failf(9, "admin_listener.rate_limit.max_tracked_keys %d: between 10000 and 10000000", n)
	}
	if pg := cfg.Storage.Postgres; pg.MaxConns < 0 || pg.MaxConns > 1000 {
		c.failf(9, "storage.postgres.max_conns %d: between 1 and 1000", pg.MaxConns)
	}
	for k, t := range map[string]time.Duration{"app_statement_timeout": cfg.Storage.Postgres.AppStatementTimeout,
		"reader_statement_timeout": cfg.Storage.Postgres.ReaderStatementTimeout} {
		if t != 0 && (t < 100*time.Millisecond || t > 5*time.Minute) {
			c.failf(9, "storage.postgres.%s %s: between 100ms and 5m", k, t)
		}
	}
	if r := cfg.Observability.Tracing.SampleRatio; r != nil && (*r < 0 || *r > 1) {
		c.failf(9, "observability.tracing.sample_ratio %v: between 0 and 1", *r)
	}
	if t := cfg.Observability.Tracing; t.Insecure && t.CACertFile != "" {
		c.failf(9, "observability.tracing: ca_cert_file with insecure: a collector without TLS has no certificate to verify")
	}
	switch cfg.SecretSealing.Provider {
	case "vault-transit":
		if a := cfg.SecretSealing.VaultTransit.JWTAudience; !slices.Contains(cfg.CoreIdentity.SVIDSelector.JWTAudience, a) {
			c.failf(9, "secret_sealing.vault_transit.jwt_audience %q is not in core_identity.svid_selector.jwt_audience", a)
		}
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

// authorization checks rules 13 and 14 (bindings) and the jurisdiction patterns of
// rule 16.
func (c *checker) authorization(cfg *Config) {
	platforms := map[string]bool{}
	for _, p := range allPlatforms(cfg) {
		platforms[p.Name] = true
	}
	for i, b := range cfg.Authorization.Bindings {
		c.roleBinding(i, b)
		switch b.Role {
		case RoleTrustedAutomation:
			c.trustedAutomation(b, platforms)
		case RoleBreakGlass:
			c.breakGlassBinding(b, cfg.BreakGlass.Policies)
		}
	}
	c.patterns(16, "approval.required_jurisdictions", cfg.Authorization.Approval.RequiredJurisdictions)
}

// roleBinding checks the rules common to every authorization binding.
func (c *checker) roleBinding(i int, b RoleBinding) {
	who := b.LDAPGroupDN + b.SPIFFEID
	if (b.LDAPGroupDN == "") == (b.SPIFFEID == "") {
		c.failf(16, "authorization binding %d: exactly one of ldap_group_dn and spiffe_id is required", i)
	}
	if _, err := spiffeid.FromString(b.SPIFFEID); b.SPIFFEID != "" && err != nil {
		c.failf(16, "authorization binding %d: invalid spiffe_id %q", i, b.SPIFFEID)
	}
	if !slices.Contains(knownRoles, b.Role) {
		c.failf(16, "authorization binding %q: unknown role %q", who, b.Role)
	}
	switch {
	case b.Role == RoleAccountAdmin && len(b.Jurisdictions) > 0:
		c.failf(16, "authorization binding %q: account_admin is global and takes no jurisdictions", who)
	case b.Role != RoleAccountAdmin && len(b.Jurisdictions) == 0:
		c.failf(16, "authorization binding %q: jurisdictions is required", who)
	}
	c.patterns(16, "authorization binding "+who, b.Jurisdictions)
	if b.Role != RoleTrustedAutomation && (len(b.Platforms) > 0 || b.ApprovalReferencePattern != "") {
		c.failf(13, "authorization binding %q: platforms and approval_reference_pattern are only for trusted_automation", who)
	}
}

// trustedAutomation checks rule 13.
func (c *checker) trustedAutomation(b RoleBinding, platforms map[string]bool) {
	who := b.LDAPGroupDN + b.SPIFFEID
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
}

// breakGlassBinding checks rule 14 for a break_glass binding.
func (c *checker) breakGlassBinding(b RoleBinding, policies []charter.BreakGlassPolicy) {
	who := b.LDAPGroupDN + b.SPIFFEID
	if b.LDAPGroupDN == "" {
		c.failf(14, "break_glass must be bound to an ldap_group_dn, never to a SPIFFE ID (%q)", who)
	}
	for _, s := range b.Jurisdictions {
		if !slices.ContainsFunc(policies, func(p charter.BreakGlassPolicy) bool { return slices.Contains(p.Jurisdictions, s) }) {
			c.failf(14, "break_glass binding %q: jurisdiction pattern %q appears in no break_glass.policies entry", who, s)
		}
	}
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
		c.patterns(16, fmt.Sprintf("break_glass.policies[%d]", i), p.Jurisdictions)
	}
	if n := cfg.Notifications; *n.DeliveredRetention < 0 || *n.AbandonedRetention < 0 {
		c.failf(14, "notifications: delivered_retention and abandoned_retention must not be negative")
	}
	for _, w := range cfg.Notifications.Webhooks {
		if u, err := url.Parse(w.URL); err != nil || u.Scheme != "https" || u.Host == "" {
			c.failf(14, "webhook %q: url must be https://", w.Name)
		}
		if v, ok := opts.LookupEnv(w.HMACSecretEnv); w.HMACSecretEnv == "" || !ok || v == "" {
			c.failf(14, "webhook %q: hmac_secret_env %q is not set", w.Name, w.HMACSecretEnv)
		}
		c.patterns(14, "webhook "+w.Name+" jurisdictions", w.Jurisdictions)
	}
}

// charter checks rule 16.
func (c *checker) charter(cfg *Config) {
	sourceDomains := map[string]bool{}
	for _, p := range allPlatforms(cfg) {
		if !charter.ValidJurisdictionPath(p.Jurisdiction) {
			c.failf(16, "platform %q: jurisdiction %q must be a valid jurisdiction path", p.Name, p.Jurisdiction)
		}
		c.patterns(16, platformPrefix+p.Name+" target_jurisdictions", p.TargetJurisdictions)
		for _, td := range p.AllowedSourceTrustDomains {
			sourceDomains[td] = true
		}
	}
	c.sourceJurisdictions(cfg.Charter.SourceJurisdictions, sourceDomains)
	c.namePrefixes(cfg.Charter.NamePrefixes)
	ic := cfg.Charter.Interconnects
	if ic.DefaultCrossJurisdiction != "allow" && ic.DefaultCrossJurisdiction != "deny" {
		c.failf(16, "interconnects.default_cross_jurisdiction must be allow or deny")
	}
	names := map[string]bool{}
	for _, r := range ic.Rules {
		if !ruleNameRE.MatchString(r.Name) || r.Name == "default" || names[r.Name] {
			c.failf(16, "interconnect rule %q: names must be unique, match %s and not be \"default\"", r.Name, ruleNameRE)
		}
		names[r.Name] = true
		c.interconnectRule(r)
	}
	c.accounts(cfg)
}

// accounts checks charter.accounts, when present (.specs/ligo-tenancy.md
// §4, §9.1): without approval on every account, an account operator's own
// sides would be approved automatically.
func (c *checker) accounts(cfg *Config) {
	a := cfg.Charter.Accounts
	if a == nil {
		for _, p := range allPlatforms(cfg) {
			if p.NamespaceTemplate != "" {
				c.failf(16, "platform %q: namespace_template needs charter.accounts", p.Name)
			}
		}
		return
	}
	if err := a.Validate(); err != nil {
		c.failf(16, "charter.accounts: %v", err)
		return
	}
	for _, p := range allPlatforms(cfg) {
		if p.NamespaceTemplate != "" {
			if err := a.CheckNamespaceTemplate(p.NamespaceTemplate); err != nil {
				c.failf(16, "platform %q: %v", p.Name, err)
			}
		}
	}
	for i, r := range a.LDAPGroups.Roles {
		if !slices.Contains(accountRoles, r.Role) {
			c.failf(16, "charter.accounts.ldap_groups.roles[%d]: role %q must be one of %v", i, r.Role, accountRoles)
		}
	}
	if !slices.ContainsFunc(cfg.Authorization.Approval.RequiredJurisdictions, func(p string) bool { return charter.JurisdictionMatches(p, a.SampleJurisdiction()) }) {
		c.failf(16, "charter.accounts: approval.required_jurisdictions must cover every account of %q", a.Jurisdiction)
	}
}

// namePrefixes checks the patterns and resource kinds of name_prefixes.
func (c *checker) namePrefixes(prefixes []charter.NamePrefix) {
	for i, p := range prefixes {
		c.patterns(16, fmt.Sprintf("charter.name_prefixes[%d]", i), p.Jurisdictions)
		for _, k := range p.Resources {
			if !slices.Contains(knownKinds, k) {
				c.failf(16, "charter.name_prefixes[%d]: unknown resource %q", i, k)
			}
		}
	}
}

// sourceJurisdictions checks that source_jurisdictions has exactly one valid entry for
// each trust domain that platforms accept.
func (c *checker) sourceJurisdictions(entries []charter.SourceJurisdiction, sourceDomains map[string]bool) {
	seen := map[string]bool{}
	for _, s := range entries {
		if seen[s.TrustDomain] {
			c.failf(16, "charter.source_jurisdictions: trust domain %q has more than one entry", s.TrustDomain)
		}
		seen[s.TrustDomain] = true
		if !sourceDomains[s.TrustDomain] {
			c.failf(16, "charter.source_jurisdictions: trust domain %q is not accepted by any platform", s.TrustDomain)
		}
		if _, err := s.Extractor(); err != nil {
			c.failf(16, "charter.source_jurisdictions[%s]: %v", s.TrustDomain, err)
		}
	}
	for td := range sourceDomains {
		if !seen[td] {
			c.failf(16, "charter.source_jurisdictions: no entry for trust domain %q", td)
		}
	}
}

// interconnectRule checks one rule of the interconnection policy.
func (c *checker) interconnectRule(r charter.InterconnectRule) {
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
		if !partyNameRE.MatchString(a.Name) || parties[a.Name] || !charter.ValidJurisdictionPath(a.Jurisdiction) {
			c.failf(16, "interconnect rule %q: additional approval %q needs a unique name matching %s and a valid jurisdiction path", r.Name, a.Name, partyNameRE)
		}
		parties[a.Name] = true
	}
}

// platformFlows checks the static part of rule 19.
func (c *checker) platformFlows(cfg *Config) {
	for _, p := range allPlatforms(cfg) {
		c.declaredFlows(platformPrefix+p.Name, p.NetworkFlows, &p.Config)
	}
	for _, sp := range cfg.SecretStores {
		for _, in := range sp.Instances {
			c.declaredFlows("secret store "+in.Name, in.NetworkFlows, &in.Config)
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

// declaredFlows checks a platform's or store's flows against its
// allowed_endpoints.
func (c *checker) declaredFlows(what string, declared []flows.Flow, config *yaml.Node) {
	pc, err := hostKeys(config)
	if err != nil {
		return // reported by plugin()
	}
	if err := flows.ValidateList(declared, maxPlatformFlow); err != nil {
		c.failf(19, whatErr, what, err)
		return
	}
	allow, err := flows.ParseAllowlist(pc.AllowedEndpoints)
	if err != nil {
		c.failf(19, whatErr, what, err)
		return
	}
	for _, f := range declared {
		if err := allow.CheckFlow(f); err != nil {
			c.failf(19, whatErr, what, err)
		}
	}
}

// patterns checks that each entry is a valid jurisdiction pattern.
func (c *checker) patterns(rule int, where string, patterns []string) {
	for _, p := range patterns {
		if !charter.ValidJurisdictionPattern(p) {
			c.failf(rule, "%s: %q is not a valid jurisdiction pattern", where, p)
		}
	}
}

// anchored checks that a pattern is a fully anchored RE2.
func (c *checker) anchored(rule int, where, pattern string) {
	if _, err := regexp.Compile(pattern); err != nil || !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
		c.failf(rule, "%s must be an RE2 starting with ^ and ending with $", where)
	}
}
