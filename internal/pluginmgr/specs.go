package pluginmgr

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/instances"
)

// Templates are the configuration's plugin types, by type, and its realms,
// by name: what a process can be started from (Options.Templates).
func Templates(cfg *config.Config) (map[string]Spec, map[string]config.Realm, error) {
	realms := map[string]config.Realm{}
	for _, z := range cfg.Realms {
		realms[z.Name] = z
	}
	templates := map[string]Spec{}
	for k, group := range map[instances.Kind][]config.PluginType{instances.IdentityProvider: cfg.IdentityProviders,
		instances.SecretStore: cfg.SecretStores, instances.Platform: cfg.PlatformProviders} {
		for _, t := range group {
			s := Spec{Type: t.Type, Kind: kindOf[k], Builtin: t.Builtin, SharedSVIDs: map[string]bool{}}
			if t.InstanceBounds != nil {
				for _, id := range t.InstanceBounds.SharedSVIDs {
					s.SharedSVIDs[id] = true
				}
			}
			if !t.Builtin {
				checksum, err := hex.DecodeString(t.SHA256)
				if err != nil || len(checksum) != 32 {
					return nil, nil, fmt.Errorf("plugin %s: sha256 %q", t.Type, t.SHA256)
				}
				s.Binary, s.SHA256 = t.Binary, checksum
			}
			templates[t.Type] = s
		}
	}
	return templates, realms, nil
}

// Specs groups the instances in force into one process per (type, realm)
// (ADR-03), with the types and realms of the configuration; builtin types
// are served inside ligo.
func Specs(cfg *config.Config, set *instances.Set) ([]Spec, error) {
	templates, realms, err := Templates(cfg)
	if err != nil {
		return nil, err
	}
	var specs []Spec
	index := map[string]int{}
	for _, d := range set.All() {
		t, ok := templates[d.Type]
		if !ok {
			return nil, fmt.Errorf("instance %q: plugin type %q is not in the configuration", d.Metadata.Name, d.Type)
		}
		z, ok := realms[d.Metadata.Realm]
		if !ok {
			return nil, fmt.Errorf("instance %q: unknown realm %q", d.Metadata.Name, d.Metadata.Realm)
		}
		in, err := Descriptor(d)
		if err != nil {
			return nil, err
		}
		key := d.Type + "\x00" + z.Name
		if i, ok := index[key]; ok {
			specs[i].Instances = append(specs[i].Instances, in)
			specs[i].Jurisdictions[d.Metadata.Name] = d.Metadata.Jurisdiction
			continue
		}
		spec := t
		spec.Realm, spec.Instances = z, []*pluginv1.InstanceDescriptor{in}
		spec.Jurisdictions = map[string]string{d.Metadata.Name: d.Metadata.Jurisdiction}
		index[key] = len(specs)
		specs = append(specs, spec)
	}
	return specs, nil
}

// Descriptor is an instance's InstanceDescriptor; a platform's carries its
// wiring (an omitted secret storage strategy stays empty: Wire defaults it,
// §5.6).
func Descriptor(d *instances.Definition) (*pluginv1.InstanceDescriptor, error) {
	config := d.Config
	if len(config) == 0 {
		config = json.RawMessage(`{}`)
	}
	in := &pluginv1.InstanceDescriptor{Name: d.Metadata.Name, ConfigJson: string(config)}
	if sel := d.SVIDSelector; sel != nil {
		in.SvidSelector = &pluginv1.SVIDSelectorConfig{MatchExpr: sel.MatchExpr, JwtAudience: sel.JWTAudience}
		in.AllowSharedSvid = sel.AllowSharedSVID
	}
	if w := d.IdentityProvider; w != nil {
		in.IdentityProviderType, in.IdentityProviderInstance = w.Type, w.Instance
	}
	if w := d.SecretStore; w != nil {
		in.SecretStoreType, in.SecretStoreInstance, in.SecretStorageStrategy = w.Type, w.Instance, w.SecretStorageStrategy
	}
	return in, nil
}
