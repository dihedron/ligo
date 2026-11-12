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

	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/theme"
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
	sha256RE    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ruleNameRE  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)
	partyNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)
	knownRoles  = []string{RoleViewer, RoleOperator, RoleApprover, RoleBreakGlass, RoleTrustedAutomation, RoleFullAccess, RoleAccountAdmin}
	knownKinds  = []string{string(engine.KindSource), string(engine.KindTarget), string(engine.KindBinding)}
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

// instances checks rules 1 and 7 for plugin types: their instances are
// checked when filed (.specs/ligo-instances.md §6).
func (c *checker) instances(cfg *Config, _ map[string]Realm) {
	seen := map[string]bool{}
	for kind, types := range map[string][]PluginType{"identity provider": cfg.IdentityProviders, "secret store": cfg.SecretStores, "platform provider": cfg.PlatformProviders} {
		for _, t := range types {
			c.binary(kind, t.Type, t.Builtin, t.Binary, t.SHA256)
			if seen[t.Type] {
				c.failf(1, "plugin type %q is declared twice", t.Type)
			}
			seen[t.Type] = true
			switch {
			case !t.Builtin && t.InstanceBounds == nil:
				c.failf(1, "%s %q: instance_bounds is required ([] allows no endpoint)", kind, t.Type)
			case t.InstanceBounds != nil:
				if _, err := flows.ParseAllowlist(t.InstanceBounds.AllowedEndpoints); err != nil {
					c.failf(1, "%s %q: instance_bounds: %v", kind, t.Type, err)
				}
			}
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
	if r := cfg.Storage.Audit.Retention; r < 0 || (r > 0 && r < 24*time.Hour) {
		c.failf(9, "storage.audit.retention %s: 0 (keep every entry) or at least 24h", r)
	}
	if r := cfg.Storage.ChangeRequests.Retention; r < 0 || (r > 0 && r < 24*time.Hour) {
		c.failf(9, "storage.change_requests.retention %s: 0 (keep every request) or at least 24h", r)
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
	for i, b := range cfg.Authorization.Bindings {
		c.roleBinding(i, b)
		switch b.Role {
		case RoleTrustedAutomation:
			c.trustedAutomation(b)
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
// The platforms it names are not checked: platforms come and go at run time,
// and startup warns of a name no platform has (.specs/ligo-instances.md §3).
func (c *checker) trustedAutomation(b RoleBinding) {
	who := b.LDAPGroupDN + b.SPIFFEID
	if b.SPIFFEID == "" {
		c.failf(13, "trusted_automation must be bound to a spiffe_id, never to an LDAP group (%q)", who)
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
	c.sourceJurisdictions(cfg.Charter.SourceJurisdictions)
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
		return
	}
	if err := a.Validate(); err != nil {
		c.failf(16, "charter.accounts: %v", err)
		return
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

// sourceJurisdictions checks that source_jurisdictions has at most one valid
// entry per trust domain; a platform that accepts a trust domain needs its
// entry, checked when the platform is filed (.specs/ligo-instances.md §6).
func (c *checker) sourceJurisdictions(entries []charter.SourceJurisdiction) {
	seen := map[string]bool{}
	for _, s := range entries {
		if seen[s.TrustDomain] {
			c.failf(16, "charter.source_jurisdictions: trust domain %q has more than one entry", s.TrustDomain)
		}
		seen[s.TrustDomain] = true
		if _, err := s.Extractor(); err != nil {
			c.failf(16, "charter.source_jurisdictions[%s]: %v", s.TrustDomain, err)
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

// platformFlows checks the static part of rule 19 left in server.yaml:
// ligo's own flow; instances' flows are checked when filed.
func (c *checker) platformFlows(cfg *Config) {
	wa := cfg.Service.WorkloadAdvertise
	ligo := flows.LigoFlow(wa.Destination, wa.Port, wa.ServerName)
	if wa.Destination == "" || wa.Port == 0 {
		c.failf(19, "service.workload_advertise must be set")
	} else if err := ligo.Validate(); err != nil {
		c.failf(19, "service.workload_advertise: %v", err)
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
