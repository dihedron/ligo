package adminhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/pluginmgr"
	"github.com/dihedron/ligo/internal/sources"
	"google.golang.org/protobuf/encoding/protojson"
)

// Plugins calls the platform providers: PlatformPlugins(m).
type Plugins interface {
	Health(ctx context.Context, platform string) (*pluginv1.HealthResponse, error)
	UISchemas(ctx context.Context, platform string) (*pluginv1.GetUISchemasResponse, error)
}

// PlatformPlugins calls the platforms' plugins through the manager.
func PlatformPlugins(m *pluginmgr.Manager) Plugins { return managed{m} }

type managed struct{ m *pluginmgr.Manager }

func (p managed) Health(ctx context.Context, platform string) (resp *pluginv1.HealthResponse, err error) {
	err = p.m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, platform, false, func(ctx context.Context, c *pluginmgr.Client) error {
		resp, err = c.Control.Health(ctx, &pluginv1.HealthRequest{Instance: platform})
		return err
	})
	return resp, err
}

func (p managed) UISchemas(ctx context.Context, platform string) (resp *pluginv1.GetUISchemasResponse, err error) {
	err = p.m.Call(ctx, pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, platform, false, func(ctx context.Context, c *pluginmgr.Client) error {
		resp, err = c.Platform.GetUISchemas(ctx, &pluginv1.GetUISchemasRequest{Instance: platform})
		return err
	})
	return resp, err
}

func (s *Server) platformRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/admin/platforms", s.listPlatforms)
	mux.HandleFunc("GET /v1/admin/platforms/{name}", s.getPlatform)
}

type wiringDTO struct {
	Type     string `json:"type"`
	Instance string `json:"instance"`
}

type healthDTO struct {
	Serving bool   `json:"serving"`
	Message string `json:"message,omitempty"`
}

// platformDTO is a platform as §3.4 shows it: no credentials, no plugin
// configuration beyond the privilege bounds.
type platformDTO struct {
	APIVersion                string            `json:"apiVersion"`
	Kind                      string            `json:"kind"`
	Name                      string            `json:"name"`
	Type                      string            `json:"type"`
	Zone                      string            `json:"zone"`
	Scope                     string            `json:"scope"`
	TargetScopes              []string          `json:"targetScopes"`
	DisplayName               string            `json:"displayName,omitempty"`
	Description               string            `json:"description,omitempty"`
	Contacts                  []sources.Contact `json:"contacts,omitempty"`
	AllowedSourceTrustDomains []string          `json:"allowedSourceTrustDomains"`
	PrivilegeBounds           map[string]any    `json:"privilegeBounds,omitempty"`
	NetworkFlows              []flows.Flow      `json:"networkFlows"`
	IdentityProvider          wiringDTO         `json:"identityProvider"`
	SecretStore               wiringDTO         `json:"secretStore"`
	Health                    *healthDTO        `json:"health,omitempty"`
	UISchemas                 json.RawMessage   `json:"uiSchemas,omitempty"`
}

func platformOf(typ string, p *config.Platform) platformDTO {
	d := platformDTO{APIVersion: sources.APIVersion, Kind: "Platform", Name: p.Name, Type: typ, Zone: p.Zone, Scope: p.Scope,
		TargetScopes: p.TargetScopes, DisplayName: p.DisplayName, Description: p.Description,
		AllowedSourceTrustDomains: p.AllowedSourceTrustDomains, NetworkFlows: p.NetworkFlows,
		IdentityProvider: wiringDTO{p.IdentityProvider.Type, p.IdentityProvider.Instance},
		SecretStore:      wiringDTO{p.SecretStore.Type, p.SecretStore.Instance}}
	for _, c := range p.Contacts {
		d.Contacts = append(d.Contacts, sources.Contact{Name: c.Name, Email: c.Email})
	}
	// shortcut: grantable_roles is the only privilege bound the database
	// plugins know; read others here when a plugin type declares them
	var bounds struct {
		GrantableRoles []string `yaml:"grantable_roles"`
	}
	if p.Config.Decode(&bounds) == nil && bounds.GrantableRoles != nil {
		d.PrivilegeBounds = map[string]any{"grantableRoles": bounds.GrantableRoles}
	}
	if d.AllowedSourceTrustDomains == nil {
		d.AllowedSourceTrustDomains = []string{}
	}
	if d.NetworkFlows == nil {
		d.NetworkFlows = []flows.Flow{}
	}
	return d
}

// health asks the platform's plugin, within 2s; an unreachable plugin is
// not serving.
func (s *Server) health(ctx context.Context, platform string) *healthDTO {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	h, err := s.Plugins.Health(ctx, platform)
	if err != nil {
		return &healthDTO{Message: "the plugin cannot be reached"}
	}
	return &healthDTO{Serving: h.GetServing(), Message: h.GetPublicMessage()}
}

// listPlatforms: every configured platform with its health, sorted as in
// server.yaml; platforms are visible to every viewer (§3.4).
func (s *Server) listPlatforms(w http.ResponseWriter, r *http.Request) {
	if !viewer(caller(r)) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	items := []platformDTO{}
	for _, pp := range s.Config.PlatformProviders {
		for i := range pp.Platforms {
			d := platformOf(pp.Type, &pp.Platforms[i])
			d.Health = s.health(r.Context(), d.Name) // shortcut: one platform after another; call in parallel if lists grow long
			items = append(items, d)
		}
	}
	reply(w, http.StatusOK, map[string]any{"items": items})
}

// getPlatform: one platform with its health and the forms of its plugin.
func (s *Server) getPlatform(w http.ResponseWriter, r *http.Request) {
	if !viewer(caller(r)) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	name := r.PathValue("name")
	for _, pp := range s.Config.PlatformProviders {
		for i := range pp.Platforms {
			if pp.Platforms[i].Name != name {
				continue
			}
			d := platformOf(pp.Type, &pp.Platforms[i])
			d.Health = s.health(r.Context(), name)
			ui, err := s.Plugins.UISchemas(r.Context(), name)
			if err != nil {
				s.Logger.Error("ui schemas", "platform", name, "error", err)
				problem(w, http.StatusServiceUnavailable, "unavailable", "the platform's plugin cannot be reached")
				return
			}
			ui.PluginType, ui.Instance = "", ""
			if d.UISchemas, err = protojson.Marshal(ui); err != nil {
				s.fail(w, r, err)
				return
			}
			reply(w, http.StatusOK, d)
			return
		}
	}
	problem(w, http.StatusNotFound, "not-found", "platform "+name)
}
