package pluginmgr

import (
	"context"
	"fmt"
	"maps"
	"strings"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/instances"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/grpc/codes"
)

// kindOf is the plugin kind of an instance kind.
var kindOf = map[instances.Kind]pluginv1.PluginKind{
	instances.IdentityProvider: pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER,
	instances.SecretStore:      pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE,
	instances.Platform:         pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER,
}

// Instances is the manager as the instances service needs it
// (.specs/ligo-instances.md §6 rules 4, 6, 7, 8).
func Instances(m *Manager) instances.Plugins { return instanceChecks{m} }

type instanceChecks struct{ m *Manager }

func refuse(status int, slug, format string, args ...any) *changerequests.Error {
	return &changerequests.Error{Status: status, Slug: slug, Detail: fmt.Sprintf(format, args...)}
}

// process is the process of a type in a realm, or nil.
func (m *Manager) process(typ, realm string) *process {
	for _, p := range m.procs {
		if p.spec.Type == typ && p.spec.Realm.Name == realm {
			return p
		}
	}
	return nil
}

// described is what a type described, whatever the realm, or nil.
func (m *Manager) described(typ string) *pluginv1.DescribeResponse {
	for _, p := range m.procs {
		if p.spec.Type == typ {
			return p.described
		}
	}
	return nil
}

// Validate checks the config against the plugin's schema (rule 4), then asks
// the plugin (rule 8).
// shortcut: needs a process of the type in the realm already; chunk 3 of
// .specs/ligo-instances.md starts one for the first instance
func (c instanceChecks) Validate(ctx context.Context, k instances.Kind, d *instances.Definition) (string, []string, error) {
	p := c.m.process(d.Type, d.Metadata.Realm)
	if p == nil {
		return "", nil, refuse(503, "dependency-unavailable", "no process of plugin %s runs in realm %s", d.Type, d.Metadata.Realm)
	}
	in, err := Descriptor(d)
	if err != nil {
		return "", nil, refuse(422, "validation-failed", "%v", err)
	}
	in.Realm, in.TrustDomain = p.spec.Realm.Name, p.spec.Realm.TrustDomain
	if err := checkConfig(p.described, in); err != nil {
		return "", nil, refuse(422, "validation-failed", "%v", err)
	}
	var resp *pluginv1.ValidateInstanceResponse
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()
	if client == nil {
		return "", nil, refuse(503, "dependency-unavailable", "plugin %s in realm %s is down", d.Type, d.Metadata.Realm)
	}
	rctx, cancel := context.WithTimeout(ctx, c.m.opts.RPCTimeout)
	defer cancel()
	resp, err = client.Control.ValidateInstance(rctx, &pluginv1.ValidateInstanceRequest{Realm: p.spec.Realm.Name,
		SpiffeWorkloadSocket: p.spec.Realm.SPIFFEWorkloadSocket, Instance: in})
	if err != nil {
		code, detail := pluginsdk.FromError(err)
		if code == codes.Unavailable {
			return "", nil, refuse(503, "dependency-unavailable", "plugin %s: %s", d.Type, detail.GetPublicMessage())
		}
		return "", nil, refuse(422, "validation-failed", "plugin %s: %s: %s", d.Type, detail.GetCode(), detail.GetPublicMessage())
	}
	if id := resp.GetSpiffeId(); id != "" && !strings.HasPrefix(id, "spiffe://"+p.spec.Realm.TrustDomain+"/") {
		return "", nil, refuse(422, "validation-failed", "svidSelector resolves %s, outside the realm's trust domain %s", id, p.spec.Realm.TrustDomain)
	}
	return resp.GetSpiffeId(), resp.GetEndpoints(), nil
}

// Resolved are the SPIFFE IDs the running instances of a type in a realm
// resolved.
func (c instanceChecks) Resolved(typ, realm string) map[string]string {
	p := c.m.process(typ, realm)
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return maps.Clone(p.resolved)
}

// Wire checks a platform's wiring as startup rule 3 does, and fills an
// omitted secretStorageStrategy (§5.6).
func (c instanceChecks) Wire(_ context.Context, d *instances.Definition) error {
	platform := c.m.described(d.Type)
	if platform == nil {
		return refuse(503, "dependency-unavailable", "plugin %s has not described itself yet", d.Type)
	}
	described := map[key]*pluginv1.DescribeResponse{}
	for _, p := range c.m.procs {
		described[key{p.spec.Kind, p.spec.Type}] = p.described
	}
	in, err := Descriptor(d)
	if err != nil {
		return err
	}
	if err := wirePlatform(in, platform.GetPlatformProvider(), described); err != nil {
		return refuse(422, "validation-failed", "%v", err)
	}
	d.SecretStore.SecretStorageStrategy = in.GetSecretStorageStrategy()
	return nil
}

// checkConfig validates one instance's config against its plugin's schema
// (startup rule 8).
func checkConfig(d *pluginv1.DescribeResponse, in *pluginv1.InstanceDescriptor) error {
	schema, err := compileSchema(d.GetInstanceConfigSchemaJson())
	if err != nil {
		return fmt.Errorf("instance configuration schema: %w", err)
	}
	cfg, err := jsonschema.UnmarshalJSON(strings.NewReader(in.GetConfigJson()))
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := schema.Validate(cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}
