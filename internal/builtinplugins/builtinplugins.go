// Package builtinplugins are the plugins compiled into ligo (§5.1): the
// identity strategy markers svid.v1, target-local.v1 and delegated-dynamic.v1,
// and the secret store none.v1. They implement the same services as external
// plugins, and pluginmgr serves them in-process over the same gRPC contract.
package builtinplugins

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
)

// emptyConfig is the instance configuration schema of the builtins that take
// no settings.
const emptyConfig = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false}`

// minPasswordLength is §5.8 rule 3's minimum.
const minPasswordLength = 32

// Lookup returns a fresh builtin plugin of type typ, or false.
func Lookup(typ string) (pluginsdk.Plugins, bool) {
	switch typ {
	case "svid.v1":
		return identityPlugin(&marker{typ: typ, mode: pluginv2.IdentityMode_IDENTITY_MODE_SVID, schema: emptyConfig}), true
	case "target-local.v1":
		return identityPlugin(&marker{typ: typ, mode: pluginv2.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, schema: targetLocalConfig}), true
	case "delegated-dynamic.v1":
		return identityPlugin(&marker{typ: typ, mode: pluginv2.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC, schema: emptyConfig}), true
	case "none.v1":
		n := &none{}
		return pluginsdk.Plugins{Control: n, Store: n}, true
	}
	return pluginsdk.Plugins{}, false
}

func identityPlugin(m *marker) pluginsdk.Plugins { return pluginsdk.Plugins{Control: m, Identity: m} }

// targetLocalConfig: the length of the password the target generates.
const targetLocalConfig = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
"properties":{"password_length":{"type":"integer","minimum":32,"maximum":128}}}`

// marker is an identity strategy marker (ADR-01): it creates no principal.
// Its artifact names the binding's derived principal in its mode; the target
// (Stage 2) creates it. svid.v1 adds the SVIDs the principal stands for;
// target-local.v1 the length of the password the target generates.
type marker struct {
	pluginv2.UnimplementedPluginControlServer
	pluginv2.UnimplementedIdentityProviderPluginServer
	typ    string
	mode   pluginv2.IdentityMode
	schema string

	mu        sync.Mutex
	passwords map[string]int // target-local.v1: password_length per instance
}

func (m *marker) Describe(context.Context, *pluginv2.DescribeRequest) (*pluginv2.DescribeResponse, error) {
	return &pluginv2.DescribeResponse{
		PluginType: m.typ, Kind: pluginv2.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, PluginProtocolVersion: 1,
		PluginVersion: "builtin", SupportedIdentityModes: []pluginv2.IdentityMode{m.mode}, InstanceConfigSchemaJson: m.schema,
	}, nil
}

// ConfigureInstances resolves no SVID: builtins run inside ligo and
// authenticate to nothing.
func (m *marker) ConfigureInstances(_ context.Context, r *pluginv2.ConfigureInstancesRequest) (*pluginv2.ConfigureInstancesResponse, error) {
	passwords := map[string]int{}
	for _, in := range r.GetInstances() {
		if m.mode != pluginv2.IdentityMode_IDENTITY_MODE_TARGET_LOCAL {
			continue
		}
		var cfg struct {
			PasswordLength int `json:"password_length"`
		}
		if in.GetConfigJson() != "" {
			if err := json.Unmarshal([]byte(in.GetConfigJson()), &cfg); err != nil {
				return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", fmt.Sprintf("instance %s: config: %v", in.GetName(), err), false)
			}
		}
		switch {
		case cfg.PasswordLength == 0:
			cfg.PasswordLength = minPasswordLength
		case cfg.PasswordLength < minPasswordLength:
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", fmt.Sprintf("instance %s: password_length below %d", in.GetName(), minPasswordLength), false)
		}
		passwords[in.GetName()] = cfg.PasswordLength
	}
	m.mu.Lock()
	m.passwords = passwords
	m.mu.Unlock()
	return &pluginv2.ConfigureInstancesResponse{}, nil
}

func (m *marker) Health(context.Context, *pluginv2.HealthRequest) (*pluginv2.HealthResponse, error) {
	return &pluginv2.HealthResponse{Serving: true}, nil
}

func (m *marker) EnsureIdentity(_ context.Context, r *pluginv2.EnsureIdentityRequest) (*pluginv2.EnsureIdentityResponse, error) {
	b := r.GetBinding()
	if b.GetDerivedPrincipalName() == "" {
		return nil, pluginsdk.Error(codes.InvalidArgument, "MISSING_PRINCIPAL_NAME", "the binding context has no derived principal name", false)
	}
	a := &pluginv2.IdentityArtifact{Mode: m.mode, PrincipalId: b.GetDerivedPrincipalName()}
	switch m.mode {
	case pluginv2.IdentityMode_IDENTITY_MODE_SVID:
		a.Metadata = map[string]string{"source_svid_regex": b.GetSourceSvidRegex(), "source_trust_domain": b.GetSourceTrustDomain()}
	case pluginv2.IdentityMode_IDENTITY_MODE_TARGET_LOCAL:
		m.mu.Lock()
		n, ok := m.passwords[r.GetInstance()]
		m.mu.Unlock()
		if !ok {
			n = minPasswordLength
		}
		a.Metadata = map[string]string{"password_length": strconv.Itoa(n)}
	}
	return &pluginv2.EnsureIdentityResponse{Artifact: a}, nil
}

// CleanupIdentity: a marker created nothing, so there is nothing to remove.
func (m *marker) CleanupIdentity(context.Context, *pluginv2.CleanupIdentityRequest) (*pluginv2.CleanupIdentityResponse, error) {
	return &pluginv2.CleanupIdentityResponse{}, nil
}

// noneOutput is none.v1's finalized_client_auth_json: the client
// authenticates with its own SVID.
const noneOutput = `{"mode":"SVID"}`

const noneOutputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
"required":["mode"],"properties":{"mode":{"const":"SVID"}}}`

// none is the secret store of SVID mode (§5.6): there is no secret to store.
type none struct {
	pluginv2.UnimplementedPluginControlServer
	pluginv2.UnimplementedSecretStoreProviderPluginServer
}

func (*none) Describe(context.Context, *pluginv2.DescribeRequest) (*pluginv2.DescribeResponse, error) {
	return &pluginv2.DescribeResponse{
		PluginType: "none.v1", Kind: pluginv2.PluginKind_PLUGIN_KIND_SECRET_STORE_PROVIDER, PluginProtocolVersion: 1,
		PluginVersion: "builtin", SupportedIdentityModes: []pluginv2.IdentityMode{pluginv2.IdentityMode_IDENTITY_MODE_SVID},
		InstanceConfigSchemaJson: emptyConfig, ClientOutputSchemaJson: noneOutputSchema,
	}, nil
}

func (*none) ConfigureInstances(context.Context, *pluginv2.ConfigureInstancesRequest) (*pluginv2.ConfigureInstancesResponse, error) {
	return &pluginv2.ConfigureInstancesResponse{}, nil
}

func (*none) Health(context.Context, *pluginv2.HealthRequest) (*pluginv2.HealthResponse, error) {
	return &pluginv2.HealthResponse{Serving: true}, nil
}

func (*none) EnsureSecretStore(_ context.Context, r *pluginv2.EnsureSecretStoreRequest) (*pluginv2.EnsureSecretStoreResponse, error) {
	p := r.GetSecretPayload()
	if p.GetMode() != pluginv2.IdentityMode_IDENTITY_MODE_SVID || p.GetPayload() != nil {
		return nil, pluginsdk.Error(codes.FailedPrecondition, "INCOMPATIBLE_IDENTITY_MODE", "none.v1 serves SVID mode only, without a secret", false)
	}
	return &pluginv2.EnsureSecretStoreResponse{FinalizedClientAuthJson: []byte(noneOutput)}, nil
}

func (*none) CleanupSecretStore(context.Context, *pluginv2.CleanupSecretStoreRequest) (*pluginv2.CleanupSecretStoreResponse, error) {
	return &pluginv2.CleanupSecretStoreResponse{}, nil
}
