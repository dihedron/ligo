// Package instances holds the platforms, identity provider instances and
// secret store instances managed at run time (.specs/ligo-instances.md).
package instances

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/charter"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/pkg/pluginsdk"
)

// Kind is one of the three kinds of instance; its values are the
// resource_type of their change requests.
type Kind string

const (
	Platform         Kind = "PLATFORM"
	IdentityProvider Kind = "IDENTITY_PROVIDER"
	SecretStore      Kind = "SECRET_STORE"
)

// Kinds are the three kinds, in the order a platform's wiring needs them.
var Kinds = []Kind{IdentityProvider, SecretStore, Platform}

// manifestKinds name the kinds in manifests and definitions (§4).
var manifestKinds = map[string]Kind{"IdentityProvider": IdentityProvider, "SecretStore": SecretStore, "Platform": Platform}

// ManifestKind is k's name in manifests.
func (k Kind) ManifestKind() string {
	for name, kind := range manifestKinds {
		if kind == k {
			return name
		}
	}
	return ""
}

// KindOf reads a manifest kind.
func KindOf(manifest string) (Kind, bool) {
	k, ok := manifestKinds[manifest]
	return k, ok
}

type Contact struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

type Metadata struct {
	Name         string    `json:"name"`         // immutable
	Jurisdiction string    `json:"jurisdiction"` // immutable
	Realm        string    `json:"realm"`        // immutable
	DisplayName  string    `json:"displayName,omitempty"`
	Description  string    `json:"description,omitempty"`
	Contacts     []Contact `json:"contacts,omitempty"`
}

type SVIDSelector struct {
	MatchExpr       string   `json:"matchExpr"`
	JWTAudience     []string `json:"jwtAudience,omitempty"`
	AllowSharedSVID bool     `json:"allowSharedSvid,omitempty"`
}

// Wiring names an instance of a plugin type (§3.4).
type Wiring struct {
	Type                  string `json:"type"`
	Instance              string `json:"instance"`
	SecretStorageStrategy string `json:"secretStorageStrategy,omitempty"` // secret store only (§5.6)
}

// Duration is a time.Duration written as "24h".
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.New("a duration is a string such as \"24h\"")
	}
	v, err := time.ParseDuration(s)
	*d = Duration(v)
	return err
}

// Definition is an instance of any kind (§4): the platform-only fields are
// empty for the other two.
type Definition struct {
	Kind         string          `json:"kind"`
	Metadata     Metadata        `json:"metadata"`
	Type         string          `json:"type"` // immutable
	SVIDSelector *SVIDSelector   `json:"svidSelector,omitempty"`
	Config       json.RawMessage `json:"config,omitempty"` // plugin-specific
	NetworkFlows []flows.Flow    `json:"networkFlows,omitempty"`

	// platforms only (§4.2)
	TargetJurisdictions       []string  `json:"targetJurisdictions,omitempty"`
	NamespaceTemplate         string    `json:"namespaceTemplate,omitempty"`
	CheckExistence            *bool     `json:"checkExistence,omitempty"` // default true (§7.2.3)
	PrincipalPrefix           string    `json:"principalPrefix,omitempty"`
	AllowedSourceTrustDomains []string  `json:"allowedSourceTrustDomains,omitempty"`
	RotationInterval          *Duration `json:"rotationInterval,omitempty"`
	IdentityProvider          *Wiring   `json:"identityProvider,omitempty"`
	SecretStore               *Wiring   `json:"secretStore,omitempty"`
}

// Decode reads a definition strictly: unknown fields are errors.
func Decode(data []byte) (*Definition, error) {
	var d Definition
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("definition: %w", err)
	}
	if dec.More() {
		return nil, errors.New("definition: trailing data")
	}
	return &d, nil
}

// KindOf is the definition's kind.
func (d *Definition) KindOf() (Kind, error) {
	k, ok := KindOf(d.Kind)
	if !ok {
		return "", fmt.Errorf("kind must be IdentityProvider, SecretStore or Platform, not %q", d.Kind)
	}
	return k, nil
}

// Normalize fills the defaults (§4.2): a platform's target jurisdictions are
// its own and below, and it checks targets' existence.
func (d *Definition) Normalize() {
	if k, _ := d.KindOf(); k != Platform {
		return
	}
	if len(d.TargetJurisdictions) == 0 && d.Metadata.Jurisdiction != "" {
		d.TargetJurisdictions = []string{d.Metadata.Jurisdiction + "/*"}
	}
	if d.CheckExistence == nil {
		d.CheckExistence = new(true)
	}
	if len(d.Config) == 0 {
		d.Config = json.RawMessage(`{}`)
	}
}

// Normalized is the definition's canonical JSON payload and its SHA-256
// (RFC 8785): what a change request carries and the table holds.
func (d *Definition) Normalized() (json.RawMessage, string, error) {
	data, err := json.Marshal(d)
	if err != nil {
		return nil, "", err
	}
	sum, err := changerequests.Hash(data)
	return data, sum, err
}

// HostKeys are the keys of a config that ligo itself reads (§5.5, §5.7).
type HostKeys struct {
	AllowedEndpoints    []string `json:"allowed_endpoints"`
	BootstrapCredential *struct {
		JWTAudience string `json:"jwt_audience"`
	} `json:"bootstrap_credential"`
	GrantableRoles     []string `json:"grantable_roles"`
	GrantableTemplates []string `json:"grantable_role_templates"`
}

// Keys decodes the config's host keys, ignoring the plugin's own.
func (d *Definition) Keys() (HostKeys, error) {
	var k HostKeys
	if len(d.Config) == 0 {
		return k, nil
	}
	if err := json.Unmarshal(d.Config, &k); err != nil {
		return k, fmt.Errorf("config: %w", err)
	}
	return k, nil
}

// AllowedEndpoints is the config's allowed_endpoints (§5.7).
func (d *Definition) AllowedEndpoints() []string {
	k, _ := d.Keys() // checked at filing
	return k.AllowedEndpoints
}

// PrivilegeBounds are the platform's privilege bounds in the plugin's terms
// (§3.4), or nil.
// shortcut: grantable_roles is the only bound the database plugins know;
// read others here when a plugin type declares them
func (d *Definition) PrivilegeBounds() map[string]any {
	k, err := d.Keys()
	if err != nil || (k.GrantableRoles == nil && k.GrantableTemplates == nil) {
		return nil
	}
	bounds := map[string]any{}
	if k.GrantableRoles != nil {
		bounds["grantableRoles"] = k.GrantableRoles
	}
	if k.GrantableTemplates != nil {
		bounds["grantableRoleTemplates"] = k.GrantableTemplates
	}
	return bounds
}

// ChecksExistence reports whether targets on the platform must exist
// (§7.2.3), true by default.
func (d *Definition) ChecksExistence() bool { return d.CheckExistence == nil || *d.CheckExistence }

// Rotation is the platform's rotation interval, 0 for none.
func (d *Definition) Rotation() time.Duration {
	if d.RotationInterval == nil {
		return 0
	}
	return time.Duration(*d.RotationInterval)
}

// Immutable refuses a change of a field fixed at creation (§4.3).
func Immutable(cur, d *Definition) error {
	for field, same := range map[string]bool{
		"kind": cur.Kind == d.Kind, "metadata.name": cur.Metadata.Name == d.Metadata.Name, "type": cur.Type == d.Type,
		"metadata.jurisdiction": cur.Metadata.Jurisdiction == d.Metadata.Jurisdiction, "metadata.realm": cur.Metadata.Realm == d.Metadata.Realm,
	} {
		if !same {
			return &changerequests.Error{Status: 422, Slug: "immutable-field", Detail: field + " cannot change: retire the instance and create another"}
		}
	}
	return nil
}

// maxFlows bounds the flows an instance declares, as for platforms in
// server.yaml (§3.3).
const maxFlows = 32

// Check runs the checks of §6 that need neither the database nor the
// plugin: rules 1, 2, 4 and 4a, the flows of rule 5, and the platform's
// fields. env is the configuration's part.
func (env *Env) Check(d *Definition) error {
	k, err := d.KindOf()
	if err != nil {
		return err
	}
	t, ok := env.Types[d.Type]
	switch {
	case !ok:
		return fmt.Errorf("type %q is not a plugin type of server.yaml", d.Type)
	case t.Kind != k:
		return fmt.Errorf("type %q is a %s type, not a %s one", d.Type, t.Kind, k)
	case !nameRE.MatchString(d.Metadata.Name):
		return fmt.Errorf("metadata.name %q must match %s", d.Metadata.Name, nameRE)
	case !env.Realms[d.Metadata.Realm]:
		return fmt.Errorf("metadata.realm %q is not a realm of server.yaml", d.Metadata.Realm)
	case !charter.ValidJurisdictionPath(d.Metadata.Jurisdiction):
		return fmt.Errorf("metadata.jurisdiction %q must be a valid jurisdiction path", d.Metadata.Jurisdiction)
	}
	if err := env.selector(d, t.Builtin); err != nil {
		return err
	}
	if err := env.declaredFlows(d, k); err != nil {
		return err
	}
	if k == Platform {
		return env.platform(d)
	}
	for field, set := range map[string]bool{"targetJurisdictions": len(d.TargetJurisdictions) > 0, "namespaceTemplate": d.NamespaceTemplate != "",
		"checkExistence": d.CheckExistence != nil, "principalPrefix": d.PrincipalPrefix != "", "allowedSourceTrustDomains": len(d.AllowedSourceTrustDomains) > 0,
		"rotationInterval": d.RotationInterval != nil, "identityProvider": d.IdentityProvider != nil, "secretStore": d.SecretStore != nil} {
		if set {
			return fmt.Errorf("%s is a field of platforms only", field)
		}
	}
	return nil
}

// selector checks startup rules 4 and 5 for one instance.
func (env *Env) selector(d *Definition, builtin bool) error {
	sel := d.SVIDSelector
	if !builtin && (sel == nil || sel.MatchExpr == "") {
		return errors.New("svidSelector.matchExpr is required")
	}
	if sel != nil && sel.MatchExpr != "" {
		if _, err := pluginsdk.CompileSelector(sel.MatchExpr); err != nil {
			return fmt.Errorf("svidSelector.matchExpr: %w", err)
		}
	}
	keys, err := d.Keys()
	if err != nil {
		return err
	}
	if b := keys.BootstrapCredential; b != nil && (sel == nil || !slices.Contains(sel.JWTAudience, b.JWTAudience)) {
		return fmt.Errorf("config.bootstrap_credential.jwt_audience %q is not in svidSelector.jwtAudience", b.JWTAudience)
	}
	return nil
}

// declaredFlows checks the flows of startup rule 19: identity providers
// declare none, and the others' lie within their allowed_endpoints.
func (env *Env) declaredFlows(d *Definition, k Kind) error {
	if k == IdentityProvider {
		if len(d.NetworkFlows) > 0 {
			return errors.New("networkFlows are declared by platforms and secret stores only")
		}
		return nil
	}
	if err := flows.ValidateList(d.NetworkFlows, maxFlows); err != nil {
		return fmt.Errorf("networkFlows: %w", err)
	}
	allow, err := flows.ParseAllowlist(d.AllowedEndpoints())
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	for _, f := range d.NetworkFlows {
		if err := allow.CheckFlow(f); err != nil {
			return fmt.Errorf("networkFlows: %w", err)
		}
	}
	return nil
}

// platform checks a platform's own fields (startup rules 6 and 16).
func (env *Env) platform(d *Definition) error {
	for _, td := range d.AllowedSourceTrustDomains {
		if !slices.Contains(env.AcceptedTrustDomains, td) {
			return fmt.Errorf("allowedSourceTrustDomains: %q is not in workload_listener.accepted_trust_domains", td)
		}
		if !env.SourceTrustDomains[td] {
			return fmt.Errorf("allowedSourceTrustDomains: %q has no charter.source_jurisdictions entry", td)
		}
	}
	if _, err := engine.DerivedPrincipalName(uuid.UUID{}, d.PrincipalPrefix); err != nil {
		return fmt.Errorf("principalPrefix: %w", err)
	}
	for _, p := range d.TargetJurisdictions {
		if !charter.ValidJurisdictionPattern(p) {
			return fmt.Errorf("targetJurisdictions: %q is not a valid jurisdiction pattern", p)
		}
	}
	if d.NamespaceTemplate != "" {
		if env.Accounts == nil {
			return errors.New("namespaceTemplate needs charter.accounts")
		}
		if err := env.Accounts.CheckNamespaceTemplate(d.NamespaceTemplate); err != nil {
			return fmt.Errorf("namespaceTemplate: %w", err)
		}
	}
	if d.Rotation() < 0 {
		return errors.New("rotationInterval must not be negative")
	}
	for role, w := range map[string]*Wiring{"identityProvider": d.IdentityProvider, "secretStore": d.SecretStore} {
		if w == nil || w.Type == "" || w.Instance == "" {
			return fmt.Errorf("%s.type and %s.instance are required", role, role)
		}
	}
	return nil
}

// Bounded checks rule 5: every endpoint the instance names, in its config,
// its flows and what its plugin reports, lies within its type's
// instance_bounds.
func (env *Env) Bounded(d *Definition, reported []string) error {
	bounds := env.Types[d.Type].Bounds
	var endpoints []string
	endpoints = append(endpoints, d.AllowedEndpoints()...)
	endpoints = append(endpoints, reported...)
	for _, e := range endpoints {
		host, port, err := splitEndpoint(e)
		if err != nil {
			return fmt.Errorf("endpoint %q: %w", e, err)
		}
		if err := bounds.CheckEndpoint(host, port); err != nil {
			return fmt.Errorf("%w, outside the instance_bounds of type %s", err, d.Type)
		}
	}
	for _, f := range d.NetworkFlows {
		if err := bounds.CheckFlow(f); err != nil {
			return fmt.Errorf("networkFlows: %w, outside the instance_bounds of type %s", err, d.Type)
		}
	}
	return nil
}
