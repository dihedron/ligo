// Package config loads and checks server.yaml (§8.1, §8.2).
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/regexpolicy"
	"github.com/dihedron/ligo/internal/sealing"
	"go.yaml.in/yaml/v3"
)

// Config is server.yaml.
type Config struct {
	Service           Service            `yaml:"service"`
	Zones             []Zone             `yaml:"zones"`
	CoreIdentity      CoreIdentity       `yaml:"core_identity"`
	Server            Server             `yaml:"server"`
	AdminAuth         AdminAuth          `yaml:"admin_auth"`
	Authorization     Authorization      `yaml:"authorization"`
	Governance        Governance         `yaml:"governance"`
	RegexPolicy       regexpolicy.Policy `yaml:"regex_policy"`
	Bindings          BindingsPolicy     `yaml:"bindings"`
	Propagation       Propagation        `yaml:"propagation"`
	Storage           Storage            `yaml:"storage"`
	SecretSealing     SecretSealing      `yaml:"secret_sealing"`
	Plugins           Plugins            `yaml:"plugins"`
	UI                UI                 `yaml:"ui"`
	BreakGlass        BreakGlass         `yaml:"break_glass"`
	Notifications     Notifications      `yaml:"notifications"`
	Reconciliation    Reconciliation     `yaml:"reconciliation"`
	IdentityProviders []InstanceProvider `yaml:"identity_providers"`
	SecretStores      []InstanceProvider `yaml:"secret_stores"`
	PlatformProviders []PlatformProvider `yaml:"platform_providers"`
}

type Service struct {
	ApplicationVersion string            `yaml:"application_version"`
	InstanceIDEnv      string            `yaml:"instance_id_env"`
	WorkloadAdvertise  WorkloadAdvertise `yaml:"workload_advertise"`
}

// WorkloadAdvertise is served as the "ligo" flow (ADR-16).
type WorkloadAdvertise struct {
	Destination string `yaml:"destination"`
	Port        int    `yaml:"port"`
	ServerName  string `yaml:"server_name"`
}

type Zone struct {
	Name                 string `yaml:"name"`
	TrustDomain          string `yaml:"trust_domain"`
	SPIFFEWorkloadSocket string `yaml:"spiffe_workload_socket"`
}

type SVIDSelector struct {
	MatchExpr       string   `yaml:"match_expr"`
	JWTAudience     []string `yaml:"jwt_audience"`
	AllowSharedSVID bool     `yaml:"allow_shared_svid"`
}

type CoreIdentity struct {
	Zone         string       `yaml:"zone"`
	SVIDSelector SVIDSelector `yaml:"svid_selector"`
}

type Server struct {
	WorkloadListener WorkloadListener `yaml:"workload_listener"`
	AdminListener    AdminListener    `yaml:"admin_listener"`
}

type WorkloadListener struct {
	ListenAddress         string            `yaml:"listen_address"`
	TLSSource             string            `yaml:"tls_source"`
	TLSCertFile           string            `yaml:"tls_cert_file"`
	TLSKeyFile            string            `yaml:"tls_key_file"`
	AuthModes             []string          `yaml:"auth_modes"`
	AcceptedTrustDomains  []string          `yaml:"accepted_trust_domains"`
	FederatedTrustDomains []FederatedDomain `yaml:"federated_trust_domains"`
	ExpectedJWTAudience   string            `yaml:"expected_jwt_audience"`
	MaxTokenTTL           time.Duration     `yaml:"max_token_ttl"`
	ClockSkew             time.Duration     `yaml:"clock_skew"`
	RateLimit             WorkloadRateLimit `yaml:"rate_limit"`
	ResolutionCache       ResolutionCache   `yaml:"resolution_cache"`
}

type FederatedDomain struct {
	TrustDomain string `yaml:"trust_domain"`
	ViaZone     string `yaml:"via_zone"`
}

type WorkloadRateLimit struct {
	PerSVIDRPS float64 `yaml:"per_svid_rps"`
	Burst      int     `yaml:"burst"`
}

type ResolutionCache struct {
	FullReloadInterval time.Duration `yaml:"full_reload_interval"`
	MaxStaleness       time.Duration `yaml:"max_staleness"`
}

type AdminListener struct {
	ListenAddress  string         `yaml:"listen_address"`
	ExternalOrigin string         `yaml:"external_origin"`
	TLSSource      string         `yaml:"tls_source"`
	TLSCertFile    string         `yaml:"tls_cert_file"`
	TLSKeyFile     string         `yaml:"tls_key_file"`
	ClientSVIDAuth ClientSVIDAuth `yaml:"client_svid_auth"`
	AllowBasicAuth bool           `yaml:"allow_basic_auth"`
	Session        Session        `yaml:"session"`
	RateLimit      AdminRateLimit `yaml:"rate_limit"`
}

type ClientSVIDAuth struct {
	Enabled              bool     `yaml:"enabled"`
	AcceptedTrustDomains []string `yaml:"accepted_trust_domains"`
}

type Session struct {
	IdleTimeout          time.Duration `yaml:"idle_timeout"`
	AbsoluteTimeout      time.Duration `yaml:"absolute_timeout"`
	AuthzRecheckInterval time.Duration `yaml:"authz_recheck_interval"`
}

type AdminRateLimit struct {
	LoginPerIPPerMin   int     `yaml:"login_per_ip_per_min"`
	LoginPerUserPerMin int     `yaml:"login_per_user_per_min"`
	APIPerPrincipalRPS float64 `yaml:"api_per_principal_rps"`
}

type AdminAuth struct {
	LDAP LDAP `yaml:"ldap"`
}

type LDAP struct {
	URL                    string `yaml:"url"`
	CACertFile             string `yaml:"ca_cert_file"`
	ServiceBindDN          string `yaml:"service_bind_dn"`
	ServiceBindPasswordEnv string `yaml:"service_bind_password_env"`
	UserBaseDN             string `yaml:"user_base_dn"`
	UserFilter             string `yaml:"user_filter"`
	GroupMembershipFilter  string `yaml:"group_membership_filter"`
	NestedGroups           bool   `yaml:"nested_groups"`
}

type Authorization struct {
	Bindings []RoleBinding `yaml:"bindings"`
	Approval Approval      `yaml:"approval"`
}

// Roles of §7.2.2.
const (
	RoleViewer            = "viewer"
	RoleOperator          = "operator"
	RoleApprover          = "approver"
	RoleBreakGlass        = "break_glass"
	RoleTrustedAutomation = "trusted_automation"
	RoleFullAccess        = "admin.full_access"
)

// RoleBinding grants a role on scope patterns to an LDAP group or a SPIFFE
// ID.
type RoleBinding struct {
	LDAPGroupDN              string        `yaml:"ldap_group_dn"`
	SPIFFEID                 string        `yaml:"spiffe_id"`
	Role                     string        `yaml:"role"`
	Scopes                   []string      `yaml:"scopes"`
	Platforms                []string      `yaml:"platforms"`
	ApprovalReferencePattern string        `yaml:"approval_reference_pattern"`
	RateLimit                *APIRateLimit `yaml:"rate_limit"`
}

type APIRateLimit struct {
	APIRPS float64 `yaml:"api_rps"`
	Burst  int     `yaml:"burst"`
}

type Approval struct {
	RequiredScopes                       []string      `yaml:"required_scopes"`
	RequireDistinctApproversAcrossScopes *bool         `yaml:"require_distinct_approvers_across_scopes"`
	ChangeRequestTTL                     time.Duration `yaml:"change_request_ttl"`
}

type Governance struct {
	SourceScopes  []governance.SourceScope `yaml:"source_scopes"`
	NamePrefixes  []governance.NamePrefix  `yaml:"name_prefixes"`
	Interconnects governance.Interconnects `yaml:"interconnects"`
}

type BindingsPolicy struct {
	MaxExpiry     time.Duration `yaml:"max_expiry"`
	ExpiryWarning time.Duration `yaml:"expiry_warning"`
}

type Propagation struct {
	Interval      time.Duration `yaml:"interval"`
	MaxConcurrent int           `yaml:"max_concurrent"`
}

type Storage struct {
	Postgres Postgres `yaml:"postgres"`
	DBOS     DBOS     `yaml:"dbos"`
}

type Postgres struct {
	AppDSNEnv              string        `yaml:"app_dsn_env"`
	ReaderDSNEnv           string        `yaml:"reader_dsn_env"`
	DBOSDSNEnv             string        `yaml:"dbos_dsn_env"`
	MaxConns               int           `yaml:"max_conns"`
	AppStatementTimeout    time.Duration `yaml:"app_statement_timeout"`
	ReaderStatementTimeout time.Duration `yaml:"reader_statement_timeout"`
	SSLMode                string        `yaml:"sslmode"`
}

type DBOS struct {
	WorkflowRetention time.Duration `yaml:"workflow_retention"`
}

type SecretSealing struct {
	Provider     string                `yaml:"provider"`
	VaultTransit sealing.TransitConfig `yaml:"vault_transit"`
	LocalKEKFile string                `yaml:"local_kek_file"`
}

type Plugins struct {
	Directory                    string        `yaml:"directory"`
	RPCTimeout                   time.Duration `yaml:"rpc_timeout"`
	Retry                        Retry         `yaml:"retry"`
	MaxConcurrentRPCsPerInstance int           `yaml:"max_concurrent_rpcs_per_instance"`
	RestartBackoff               Backoff       `yaml:"restart_backoff"`
}

type Retry struct {
	MaxAttempts    int           `yaml:"max_attempts"`
	InitialBackoff time.Duration `yaml:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff"`
}

type Backoff struct {
	Initial time.Duration `yaml:"initial"`
	Max     time.Duration `yaml:"max"`
}

// UI is checked in phase 9 (§7.6, §8.2 rule 15).
type UI struct {
	Theme Theme `yaml:"theme"`
}

type Theme struct {
	DefaultMode  string                       `yaml:"default_mode"`
	ProductName  string                       `yaml:"product_name"`
	Directory    string                       `yaml:"directory"`
	CSSFile      string                       `yaml:"css_file"`
	LogoFile     string                       `yaml:"logo_file"`
	LogoDarkFile string                       `yaml:"logo_dark_file"`
	FaviconFile  string                       `yaml:"favicon_file"`
	FontsDir     string                       `yaml:"fonts_dir"`
	Colors       map[string]map[string]string `yaml:"colors"`
}

type BreakGlass struct {
	MinJustificationLength   int                           `yaml:"min_justification_length"`
	IncidentReferencePattern string                        `yaml:"incident_reference_pattern"`
	Policies                 []governance.BreakGlassPolicy `yaml:"policies"`
}

type Notifications struct {
	Webhooks []Webhook `yaml:"webhooks"`
}

type Webhook struct {
	Name          string        `yaml:"name"`
	URL           string        `yaml:"url"`
	CACertFile    string        `yaml:"ca_cert_file"`
	HMACSecretEnv string        `yaml:"hmac_secret_env"`
	Timeout       time.Duration `yaml:"timeout"`
	Scopes        []string      `yaml:"scopes"`
	Events        []string      `yaml:"events"`
}

type Reconciliation struct {
	Enabled       bool          `yaml:"enabled"`
	Interval      time.Duration `yaml:"interval"`
	Jitter        time.Duration `yaml:"jitter"`
	MaxConcurrent int           `yaml:"max_concurrent"`
}

// InstanceProvider is a plugin type of identity providers or secret stores,
// with its instances.
type InstanceProvider struct {
	Type      string     `yaml:"type"`
	Builtin   bool       `yaml:"builtin"`
	Binary    string     `yaml:"binary"`
	SHA256    string     `yaml:"sha256"`
	Instances []Instance `yaml:"instances"`
}

type Instance struct {
	Name         string        `yaml:"name"`
	Zone         string        `yaml:"zone"`
	SVIDSelector *SVIDSelector `yaml:"svid_selector"`
	// Config is plugin-specific: it is validated against the plugin's schema
	// (§8.2 rule 8).
	Config       yaml.Node    `yaml:"config"`
	NetworkFlows []flows.Flow `yaml:"network_flows"`
}

// PlatformProvider is a target plugin type with its platforms.
type PlatformProvider struct {
	Type      string     `yaml:"type"`
	Builtin   bool       `yaml:"builtin"`
	Binary    string     `yaml:"binary"`
	SHA256    string     `yaml:"sha256"`
	Platforms []Platform `yaml:"platforms"`
}

type Platform struct {
	Name                      string        `yaml:"name"`
	Zone                      string        `yaml:"zone"`
	Scope                     string        `yaml:"scope"`
	TargetScopes              []string      `yaml:"target_scopes"`
	DisplayName               string        `yaml:"display_name"`
	Description               string        `yaml:"description"`
	Contacts                  []Contact     `yaml:"contacts"`
	CheckExistence            *bool         `yaml:"check_existence"` // default true (§7.2.3)
	NetworkFlows              []flows.Flow  `yaml:"network_flows"`
	IdentityProvider          Wiring        `yaml:"identity_provider"`
	SecretStore               Wiring        `yaml:"secret_store"`
	PrincipalPrefix           string        `yaml:"principal_prefix"`
	AllowedSourceTrustDomains []string      `yaml:"allowed_source_trust_domains"`
	RotationInterval          time.Duration `yaml:"rotation_interval"`
	SVIDSelector              *SVIDSelector `yaml:"svid_selector"`
	Config                    yaml.Node     `yaml:"config"`
}

type Contact struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email"`
}

// Wiring names an instance of a plugin type.
type Wiring struct {
	Type                  string `yaml:"type"`
	Instance              string `yaml:"instance"`
	SecretStorageStrategy string `yaml:"secret_storage_strategy"` // secret_store only (§5.6)
}

// pluginConfig holds the keys ligo itself reads from a plugin's config.
type pluginConfig struct {
	AllowedEndpoints    []string `yaml:"allowed_endpoints"`
	BootstrapCredential *struct {
		JWTAudience string `yaml:"jwt_audience"`
	} `yaml:"bootstrap_credential"`
}

// AllowedEndpoints returns the platform's allowed_endpoints (§5.7).
func (p *Platform) AllowedEndpoints() []string {
	pc, _ := hostKeys(&p.Config) // validated at load
	return pc.AllowedEndpoints
}

// PrivilegeBounds returns the platform's privilege bounds in the plugin's
// terms (§3.4), or nil.
// shortcut: grantable_roles is the only bound the database plugins know;
// read others here when a plugin type declares them
func (p *Platform) PrivilegeBounds() map[string]any {
	var b struct {
		GrantableRoles []string `yaml:"grantable_roles"`
	}
	if p.Config.Kind == 0 || p.Config.Decode(&b) != nil || b.GrantableRoles == nil {
		return nil
	}
	return map[string]any{"grantableRoles": b.GrantableRoles}
}

// hostKeys decodes the keys ligo reads from a plugin's config node.
func hostKeys(n *yaml.Node) (pluginConfig, error) {
	var pc pluginConfig
	if n.Kind == 0 {
		return pc, nil
	}
	err := n.Decode(&pc)
	return pc, err
}

// Load reads server.yaml strictly: unknown keys are errors. It returns the
// configuration with defaults applied, and the SHA-256 of the file.
func Load(path string) (*Config, string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is the operator's --config
	if err != nil {
		return nil, "", fmt.Errorf("config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, "", fmt.Errorf("config %s: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return cfg, hex.EncodeToString(sum[:]), nil
}

// Parse decodes server.yaml strictly and applies defaults.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	cfg := &Config{RegexPolicy: regexpolicy.DefaultPolicy()}
	if err := dec.Decode(cfg); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	cfg.applyDefaults()
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Authorization.Approval.RequireDistinctApproversAcrossScopes == nil {
		c.Authorization.Approval.RequireDistinctApproversAcrossScopes = new(bool)
		*c.Authorization.Approval.RequireDistinctApproversAcrossScopes = true
	}
	if c.Governance.Interconnects.DefaultCrossScope == "" {
		c.Governance.Interconnects.DefaultCrossScope = "deny"
	}
	for i := range c.PlatformProviders {
		for j := range c.PlatformProviders[i].Platforms {
			if p := &c.PlatformProviders[i].Platforms[j]; len(p.TargetScopes) == 0 && p.Scope != "" {
				p.TargetScopes = []string{p.Scope + "/*"}
			}
		}
	}
	if c.Bindings.MaxExpiry == 0 {
		c.Bindings.MaxExpiry = 8760 * time.Hour
	}
	if c.Bindings.ExpiryWarning == 0 {
		c.Bindings.ExpiryWarning = 168 * time.Hour
	}
}

// Policy returns the governance policy of the configuration (§8.2 rule 16).
func (c *Config) Policy() *governance.Policy {
	p := &governance.Policy{
		RequiredScopes:           c.Authorization.Approval.RequiredScopes,
		RequireDistinctApprovers: *c.Authorization.Approval.RequireDistinctApproversAcrossScopes,
		SourceScopes:             c.Governance.SourceScopes,
		NamePrefixes:             c.Governance.NamePrefixes,
		Interconnects:            c.Governance.Interconnects,
		BreakGlassPolicies:       c.BreakGlass.Policies,
	}
	for _, tp := range c.PlatformProviders {
		for _, pl := range tp.Platforms {
			p.Platforms = append(p.Platforms, governance.PlatformScopes{Platform: pl.Name, Scope: pl.Scope, TargetScopes: pl.TargetScopes})
		}
	}
	return p
}
