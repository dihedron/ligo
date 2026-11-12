package instances

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/flows"
)

// nameRE is the grammar of instance names (startup rule 1).
var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$`)

// Type is a plugin type of server.yaml.
type Type struct {
	Kind    Kind
	Builtin bool
	Bounds  flows.Allowlist // instance_bounds.allowed_endpoints
}

// Env is the part of server.yaml that instances are checked against.
type Env struct {
	Types                map[string]Type
	Realms               map[string]bool
	AcceptedTrustDomains []string        // workload_listener.accepted_trust_domains
	SourceTrustDomains   map[string]bool // with a charter.source_jurisdictions entry
	Accounts             *charter.Accounts
}

// NewEnv extracts the Env of a validated configuration.
func NewEnv(cfg *config.Config) (*Env, error) {
	env := &Env{Types: map[string]Type{}, Realms: map[string]bool{}, SourceTrustDomains: map[string]bool{},
		AcceptedTrustDomains: cfg.Server.WorkloadListener.AcceptedTrustDomains, Accounts: cfg.Charter.Accounts}
	for _, r := range cfg.Realms {
		env.Realms[r.Name] = true
	}
	for _, s := range cfg.Charter.SourceJurisdictions {
		env.SourceTrustDomains[s.TrustDomain] = true
	}
	for kind, types := range map[Kind][]config.PluginType{IdentityProvider: cfg.IdentityProviders, SecretStore: cfg.SecretStores, Platform: cfg.PlatformProviders} {
		for _, t := range types {
			var bounds flows.Allowlist // a builtin's: none, it connects nowhere
			if t.InstanceBounds != nil {
				var err error
				if bounds, err = flows.ParseAllowlist(t.InstanceBounds.AllowedEndpoints); err != nil {
					return nil, fmt.Errorf("type %s: instance_bounds: %w", t.Type, err)
				}
			}
			env.Types[t.Type] = Type{Kind: kind, Builtin: t.Builtin, Bounds: bounds}
		}
	}
	return env, nil
}

// splitEndpoint reads host:port.
func splitEndpoint(e string) (string, int, error) {
	host, p, err := net.SplitHostPort(e)
	if err != nil {
		return "", 0, errors.New("want host:port")
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, errors.New("the port must be within 1..65535")
	}
	return host, port, nil
}
