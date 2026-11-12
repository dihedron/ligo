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

	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/regexpolicy"
	"github.com/dihedron/ligo/internal/sealing"
	"go.yaml.in/yaml/v3"
)

// Config is server.yaml.
type Config struct {
	Service           Service            `yaml:"service"`
	Realms            []Realm            `yaml:"realms"`
	CoreIdentity      CoreIdentity       `yaml:"core_identity"`
	Server            Server             `yaml:"server"`
	AdminAuth         AdminAuth          `yaml:"admin_auth"`
	Authorization     Authorization      `yaml:"authorization"`
	Charter           Charter            `yaml:"charter"`
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
	IdentityProviders []PluginType       `yaml:"identity_providers"`
	SecretStores      []PluginType       `yaml:"secret_stores"`
	PlatformProviders []PluginType       `yaml:"platform_providers"`
	Observability     Observability      `yaml:"observability"`
}

type Service struct {
	ApplicationVersion string            `yaml:"application_version"`
	InstanceIDEnv      string            `yaml:"instance_id_env"`
	WorkloadAdvertise  WorkloadAdvertise `yaml:"workload_advertise"`
	// StartupTimeout bounds the wait for SPIRE and the sealer at startup:
	// past it ligo exits, for its supervisor to restart it (§8.2).
	StartupTimeout time.Duration `yaml:"startup_timeout"`
}

// Observability configures traces (§10.1); metrics have their listener.
type Observability struct {
	Tracing Tracing `yaml:"tracing"`
}

// Tracing exports OpenTelemetry spans to an OTLP/gRPC collector; an empty
// endpoint turns tracing off.
type Tracing struct {
	OTLPEndpoint string   `yaml:"otlp_endpoint"`
	SampleRatio  *float64 `yaml:"sample_ratio"` // default 0.1
	Insecure     bool     `yaml:"insecure"`     // a collector without TLS
	CACertFile   string   `yaml:"ca_cert_file"` // CAs trusted for the collector; default the system roots
}

// MetricsListener serves GET /metrics (Prometheus, §10.1) in plain HTTP,
// without authentication: bind it to a loopback or management address.
type MetricsListener struct {
	ListenAddress string `yaml:"listen_address"`
}

// WorkloadAdvertise is served as the "ligo" flow (ADR-16).
type WorkloadAdvertise struct {
	Destination string `yaml:"destination"`
	Port        int    `yaml:"port"`
	ServerName  string `yaml:"server_name"`
}

type Realm struct {
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
	Realm        string       `yaml:"realm"`
	SVIDSelector SVIDSelector `yaml:"svid_selector"`
}

type Server struct {
	WorkloadListener WorkloadListener `yaml:"workload_listener"`
	AdminListener    AdminListener    `yaml:"admin_listener"`
	MetricsListener  MetricsListener  `yaml:"metrics_listener"`
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

// Workload authentication modes (§7.1), in the order they are evaluated.
const (
	AuthX509SVID = "x509_svid"
	AuthJWTSVID  = "jwt_svid"
)

type FederatedDomain struct {
	TrustDomain string `yaml:"trust_domain"`
	ViaRealm    string `yaml:"via_realm"`
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
	LoginPerIPPerMin         int     `yaml:"login_per_ip_per_min"`
	LoginPerUserPerMin       int     `yaml:"login_per_user_per_min"`
	LoginPerUserGlobalPerMin int     `yaml:"login_per_user_global_per_min"`
	APIPerPrincipalRPS       float64 `yaml:"api_per_principal_rps"`
	MaxTrackedKeys           int     `yaml:"max_tracked_keys"` // addresses, users and principals whose buckets are kept; default 1000000
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
	RoleAccountAdmin      = "account_admin"
)

// RoleBinding grants a role on jurisdiction patterns to an LDAP group or a SPIFFE
// ID.
type RoleBinding struct {
	LDAPGroupDN              string        `yaml:"ldap_group_dn"`
	SPIFFEID                 string        `yaml:"spiffe_id"`
	Role                     string        `yaml:"role"`
	Jurisdictions            []string      `yaml:"jurisdictions"`
	Platforms                []string      `yaml:"platforms"`
	ApprovalReferencePattern string        `yaml:"approval_reference_pattern"`
	RateLimit                *APIRateLimit `yaml:"rate_limit"`
}

type APIRateLimit struct {
	APIRPS float64 `yaml:"api_rps"`
	Burst  int     `yaml:"burst"`
}

type Approval struct {
	RequiredJurisdictions                       []string      `yaml:"required_jurisdictions"`
	RequireDistinctApproversAcrossJurisdictions *bool         `yaml:"require_distinct_approvers_across_jurisdictions"`
	ChangeRequestTTL                            time.Duration `yaml:"change_request_ttl"`
}

type Charter struct {
	SourceJurisdictions []charter.SourceJurisdiction `yaml:"source_jurisdictions"`
	NamePrefixes        []charter.NamePrefix         `yaml:"name_prefixes"`
	Interconnects       charter.Interconnects        `yaml:"interconnects"`
	Accounts            *charter.Accounts            `yaml:"accounts"`
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
	Audit    Audit    `yaml:"audit"`
	// ChangeRequests is change request pruning (.specs/ligo-cr-pruning.md):
	// closed requests decided longer ago than Retention, which no audit
	// entry names, are pruned; 0 keeps every request.
	ChangeRequests struct {
		Retention time.Duration `yaml:"retention"`
	} `yaml:"change_requests"`
}

// Audit is audit log pruning (.specs/ligo-pruning.md §3.1).
type Audit struct {
	// Retention: entries older than this, and exported, are pruned; 0
	// keeps every entry.
	Retention time.Duration `yaml:"retention"`
}

type Postgres struct {
	AppDSNEnv              string        `yaml:"app_dsn_env"`
	ReaderDSNEnv           string        `yaml:"reader_dsn_env"`
	DBOSDSNEnv             string        `yaml:"dbos_dsn_env"`
	MaxConns               int           `yaml:"max_conns"`                // per pool; default pgx's
	AppStatementTimeout    time.Duration `yaml:"app_statement_timeout"`    // default 5s
	ReaderStatementTimeout time.Duration `yaml:"reader_statement_timeout"` // default 500ms
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

// UI is the admin UI's appearance (§7.6, §8.2 rule 15).
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
	MinJustificationLength   int                        `yaml:"min_justification_length"`
	IncidentReferencePattern string                     `yaml:"incident_reference_pattern"`
	Policies                 []charter.BreakGlassPolicy `yaml:"policies"`
}

type Notifications struct {
	// How long delivered and abandoned rows stay in notification_outbox;
	// pointers, as 0 is a valid choice: purge at once.
	DeliveredRetention *time.Duration `yaml:"delivered_retention"` // default 24h
	AbandonedRetention *time.Duration `yaml:"abandoned_retention"` // default 720h
	Webhooks           []Webhook      `yaml:"webhooks"`
}

type Webhook struct {
	Name          string        `yaml:"name"`
	URL           string        `yaml:"url"`
	CACertFile    string        `yaml:"ca_cert_file"`
	HMACSecretEnv string        `yaml:"hmac_secret_env"`
	Timeout       time.Duration `yaml:"timeout"`
	Jurisdictions []string      `yaml:"jurisdictions"`
	Events        []string      `yaml:"events"`
}

type Reconciliation struct {
	Enabled       bool          `yaml:"enabled"`
	Interval      time.Duration `yaml:"interval"`
	Jitter        time.Duration `yaml:"jitter"`
	MaxConcurrent int           `yaml:"max_concurrent"`
}

// PluginType is a plugin type of one kind; its instances live in the
// database (.specs/ligo-instances.md §3).
type PluginType struct {
	Type    string `yaml:"type"`
	Builtin bool   `yaml:"builtin"`
	Binary  string `yaml:"binary"`
	SHA256  string `yaml:"sha256"`
	// InstanceBounds is REQUIRED for a non-builtin type: the platform
	// team's limit on where its instances may connect (T-22a).
	InstanceBounds *InstanceBounds `yaml:"instance_bounds"`
}

type InstanceBounds struct {
	AllowedEndpoints []string `yaml:"allowed_endpoints"` // the syntax of §5.7; empty allows none
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
		return nil, movedInstances(data, err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	cfg.applyDefaults()
	return cfg, nil
}

// movedInstances explains the error of a file that still holds instances:
// they live in the database since v0.4.0.
func movedInstances(data []byte, err error) error {
	var doc map[string]any
	if yaml.Unmarshal(data, &doc) != nil {
		return err
	}
	for _, section := range []string{"identity_providers", "secret_stores", "platform_providers"} {
		types, _ := doc[section].([]any)
		for _, t := range types {
			m, _ := t.(map[string]any)
			for _, key := range []string{"instances", "platforms"} {
				if _, ok := m[key]; ok {
					return fmt.Errorf("%s[].%s: instances are no longer configured in server.yaml; create them with ligo apply (.specs/ligo-instances.md): %w", section, key, err)
				}
			}
		}
	}
	return err
}

func (c *Config) applyDefaults() {
	if c.Observability.Tracing.SampleRatio == nil {
		r := 0.1
		c.Observability.Tracing.SampleRatio = &r
	}
	if c.Server.MetricsListener.ListenAddress == "" {
		c.Server.MetricsListener.ListenAddress = "127.0.0.1:9090"
	}
	if c.Service.StartupTimeout == 0 {
		c.Service.StartupTimeout = time.Minute
	}
	if c.Server.AdminListener.RateLimit.MaxTrackedKeys == 0 {
		c.Server.AdminListener.RateLimit.MaxTrackedKeys = 1_000_000
	}
	if c.Plugins.RPCTimeout == 0 {
		c.Plugins.RPCTimeout = 60 * time.Second // §5.3 rule 6
	}
	if c.Plugins.MaxConcurrentRPCsPerInstance == 0 {
		c.Plugins.MaxConcurrentRPCsPerInstance = 4 // §5.3 rule 7
	}
	if c.Authorization.Approval.RequireDistinctApproversAcrossJurisdictions == nil {
		c.Authorization.Approval.RequireDistinctApproversAcrossJurisdictions = new(bool)
		*c.Authorization.Approval.RequireDistinctApproversAcrossJurisdictions = true
	}
	if c.Charter.Interconnects.DefaultCrossJurisdiction == "" {
		c.Charter.Interconnects.DefaultCrossJurisdiction = "deny"
	}
	wl := &c.Server.WorkloadListener
	if wl.MaxTokenTTL == 0 {
		wl.MaxTokenTTL = 15 * time.Minute // §7.1
	}
	if wl.ClockSkew == 0 {
		wl.ClockSkew = 30 * time.Second
	}
	if wl.RateLimit.PerSVIDRPS == 0 {
		wl.RateLimit.PerSVIDRPS = 5
	}
	if wl.RateLimit.Burst == 0 {
		wl.RateLimit.Burst = 20
	}
	if wl.ResolutionCache.FullReloadInterval == 0 {
		wl.ResolutionCache.FullReloadInterval = 30 * time.Second // §4.5
	}
	if wl.ResolutionCache.MaxStaleness == 0 {
		wl.ResolutionCache.MaxStaleness = 5 * time.Minute
	}
	if ss := &c.Server.AdminListener.Session; ss.IdleTimeout == 0 {
		ss.IdleTimeout = 30 * time.Minute // §7.3 rule 3
	}
	if ss := &c.Server.AdminListener.Session; ss.AbsoluteTimeout == 0 {
		ss.AbsoluteTimeout = 8 * time.Hour
	}
	if ss := &c.Server.AdminListener.Session; ss.AuthzRecheckInterval == 0 {
		ss.AuthzRecheckInterval = 5 * time.Minute
	}
	if c.UI.Theme.DefaultMode == "" {
		c.UI.Theme.DefaultMode = "system" // §7.6
	}
	if c.UI.Theme.ProductName == "" {
		c.UI.Theme.ProductName = "ligo"
	}
	if c.UI.Theme.Directory == "" {
		c.UI.Theme.Directory = "/etc/ligo/theme"
	}
	if c.Bindings.MaxExpiry == 0 {
		c.Bindings.MaxExpiry = 8760 * time.Hour
	}
	if c.Bindings.ExpiryWarning == 0 {
		c.Bindings.ExpiryWarning = 168 * time.Hour
	}
	if c.Notifications.DeliveredRetention == nil {
		c.Notifications.DeliveredRetention = new(24 * time.Hour)
	}
	if c.Notifications.AbandonedRetention == nil {
		c.Notifications.AbandonedRetention = new(720 * time.Hour)
	}
}

// Policy returns the charter of the configuration (§8.2 rule 16).
func (c *Config) Policy() *charter.Policy {
	p := &charter.Policy{
		RequiredJurisdictions:    c.Authorization.Approval.RequiredJurisdictions,
		RequireDistinctApprovers: *c.Authorization.Approval.RequireDistinctApproversAcrossJurisdictions,
		SourceJurisdictions:      c.Charter.SourceJurisdictions,
		NamePrefixes:             c.Charter.NamePrefixes,
		Interconnects:            c.Charter.Interconnects,
		BreakGlassPolicies:       c.BreakGlass.Policies,
	}
	return p
}
