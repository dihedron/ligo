package pluginmgr

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/dihedron/ligo/internal/config"
	"go.yaml.in/yaml/v3"
)

// Specs groups the configuration's plugin instances into one process per
// (type, zone) (ADR-03); builtin types are served inside ligo.
func Specs(cfg *config.Config) ([]Spec, error) {
	zones := map[string]config.Zone{}
	for _, z := range cfg.Zones {
		zones[z.Name] = z
	}
	var specs []Spec
	index := map[string]int{}
	add := func(kind pluginv2.PluginKind, typ string, builtin bool, binary, sum, zone string, in *pluginv2.InstanceDescriptor) error {
		z, ok := zones[zone]
		if !ok {
			return fmt.Errorf("instance %q: unknown zone %q", in.GetName(), zone)
		}
		k := typ + "\x00" + zone
		if i, ok := index[k]; ok {
			specs[i].Instances = append(specs[i].Instances, in)
			return nil
		}
		spec := Spec{Type: typ, Kind: kind, Builtin: builtin, Zone: z, Instances: []*pluginv2.InstanceDescriptor{in}}
		if !builtin {
			checksum, err := hex.DecodeString(sum)
			if err != nil || len(checksum) != 32 {
				return fmt.Errorf("plugin %s: sha256 %q", typ, sum)
			}
			spec.Binary, spec.SHA256 = binary, checksum
		}
		index[k] = len(specs)
		specs = append(specs, spec)
		return nil
	}
	for kind, providers := range map[pluginv2.PluginKind][]config.InstanceProvider{
		pluginv2.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER: cfg.IdentityProviders,
		pluginv2.PluginKind_PLUGIN_KIND_SECRET_STORE:      cfg.SecretStores,
	} {
		for _, p := range providers {
			for _, inst := range p.Instances {
				in, err := descriptor(inst.Name, inst.SVIDSelector, &inst.Config)
				if err != nil {
					return nil, err
				}
				if err := add(kind, p.Type, p.Builtin, p.Binary, p.SHA256, inst.Zone, in); err != nil {
					return nil, err
				}
			}
		}
	}
	for _, p := range cfg.PlatformProviders {
		for _, pl := range p.Platforms {
			in, err := descriptor(pl.Name, pl.SVIDSelector, &pl.Config)
			if err != nil {
				return nil, err
			}
			in.IdentityProviderType, in.IdentityProviderInstance = pl.IdentityProvider.Type, pl.IdentityProvider.Instance
			// an omitted secret storage strategy stays empty here: startup defaults it from the store's Describe (§5.6)
			in.SecretStoreType, in.SecretStoreInstance, in.SecretStorageStrategy = pl.SecretStore.Type, pl.SecretStore.Instance, pl.SecretStore.SecretStorageStrategy
			if err := add(pluginv2.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, p.Type, p.Builtin, p.Binary, p.SHA256, pl.Zone, in); err != nil {
				return nil, err
			}
		}
	}
	return specs, nil
}

// descriptor is an instance's InstanceDescriptor, its config as JSON.
func descriptor(name string, sel *config.SVIDSelector, node *yaml.Node) (*pluginv2.InstanceDescriptor, error) {
	var cfg any = map[string]any{}
	if node.Kind != 0 {
		if err := node.Decode(&cfg); err != nil {
			return nil, fmt.Errorf("instance %q: config: %w", name, err)
		}
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("instance %q: config: %w", name, err)
	}
	in := &pluginv2.InstanceDescriptor{Name: name, ConfigJson: string(data)}
	if sel != nil {
		in.SvidSelector = &pluginv2.SVIDSelectorConfig{MatchExpr: sel.MatchExpr, JwtAudience: sel.JWTAudience}
		in.AllowSharedSvid = sel.AllowSharedSVID
	}
	return in, nil
}
