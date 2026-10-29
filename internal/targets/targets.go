// Package targets publishes and changes targets through change requests
// (§3.3, §7.2.3, §6.2.1): their validation pipeline, which asks the
// platform's plugin to normalize them, and the apply of approved changes.
package targets

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/sources"
)

// Target is the desired state of a target (§3.3) without the fields ligo
// maintains; normalized, it is the payload of its change requests.
type Target struct {
	Kind             string             `json:"kind,omitempty"` // "Target" once normalized
	Metadata         Metadata           `json:"metadata"`
	Definition       json.RawMessage    `json:"definition"`
	AccessLevels     []AccessLevel      `json:"accessLevels"`
	NetworkFlows     []flows.Flow       `json:"networkFlows"`
	DisplayName      string             `json:"displayName,omitempty"`
	Description      string             `json:"description,omitempty"`
	Labels           map[string]string  `json:"labels,omitempty"`
	DocumentationURL string             `json:"documentationUrl,omitempty"`
	Contacts         []sources.Contact  `json:"contacts,omitempty"`
	Visibility       sources.Visibility `json:"visibility"`
}

type Metadata struct {
	Name     string `json:"name"`
	Scope    string `json:"scope"`
	Platform string `json:"platform"`
	// copied from the platform
	PlatformType  string `json:"platformType,omitempty"`
	PlatformScope string `json:"platformScope,omitempty"`
	Zone          string `json:"zone,omitempty"`
	State         string `json:"state,omitempty"`
}

type AccessLevel struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Grants      json.RawMessage `json:"grants"`
	Privileges  []string        `json:"privileges,omitempty"` // output of ValidateTarget
	State       string          `json:"state,omitempty"`
}

// ValidateTarget calls PlatformProvider.ValidateTarget on the platform the
// request names (§5.9).
type ValidateTarget func(ctx context.Context, req *pluginv1.ValidateTargetRequest) (*pluginv1.ValidateTargetResponse, error)

// Platform is what targets need of a configured platform (§8.1).
type Platform struct {
	Name, Type, Zone, Scope string
	TargetScopes            []string
	CheckExistence          bool
	Allow                   flows.Allowlist
}

// Rules are the parts of the configuration that validate targets.
type Rules struct {
	Platforms    map[string]Platform
	NamePrefixes []governance.NamePrefix
}

// NewRules extracts the rules from a validated configuration.
func NewRules(cfg *config.Config) (*Rules, error) {
	r := &Rules{Platforms: map[string]Platform{}, NamePrefixes: cfg.Governance.NamePrefixes}
	for _, pp := range cfg.PlatformProviders {
		for _, p := range pp.Platforms {
			var pc struct {
				AllowedEndpoints []string `yaml:"allowed_endpoints"`
			}
			if err := p.Config.Decode(&pc); err != nil && p.Config.Kind != 0 {
				return nil, fmt.Errorf("platform %s: config: %w", p.Name, err)
			}
			allow, err := flows.ParseAllowlist(pc.AllowedEndpoints)
			if err != nil {
				return nil, fmt.Errorf("platform %s: %w", p.Name, err)
			}
			pl := Platform{Name: p.Name, Type: pp.Type, Zone: p.Zone, Scope: p.Scope, TargetScopes: p.TargetScopes,
				CheckExistence: p.CheckExistence == nil || *p.CheckExistence, Allow: allow}
			if len(pl.TargetScopes) == 0 {
				pl.TargetScopes = []string{p.Scope + "/*"} // the platform's scope and below
			}
			r.Platforms[p.Name] = pl
		}
	}
	return r, nil
}

func refuse(status int, slug, format string, args ...any) *changerequests.Error {
	return &changerequests.Error{Status: status, Slug: slug, Detail: fmt.Sprintf(format, args...)}
}

func invalid(format string, args ...any) *changerequests.Error {
	return refuse(422, "validation-failed", format, args...)
}

var levelNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// validate runs the pipeline of a new target (§7.2.3 steps 1 to 3 and 5)
// and normalizes t. authorize, if set, runs before the plugin is called
// (step 4).
func (r *Rules) validate(ctx context.Context, call ValidateTarget, t *Target, authorize func(*Target) error) error {
	if t.Kind != "" && t.Kind != "Target" {
		return invalid("kind %q is not Target", t.Kind)
	}
	t.Kind = "Target"
	m := &t.Metadata
	if m.PlatformType != "" || m.PlatformScope != "" || m.Zone != "" || m.State != "" {
		return invalid("metadata.platformType, platformScope, zone and state are set by ligo")
	}
	if !governance.ValidScopePath(m.Scope) {
		return invalid("metadata.scope %q is not a scope", m.Scope)
	}
	if err := engine.CheckName(engine.KindTarget, m.Name, m.Scope, r.NamePrefixes); err != nil {
		return invalid("metadata.name: %v", err)
	}
	p, ok := r.Platforms[m.Platform]
	if !ok {
		return invalid("metadata.platform %q is not a configured platform", m.Platform)
	}
	if !slices.ContainsFunc(p.TargetScopes, func(pat string) bool { return governance.ScopeMatches(pat, m.Scope) }) {
		return invalid("metadata.scope %s is not in the target_scopes of %s", m.Scope, p.Name)
	}
	m.PlatformType, m.PlatformScope, m.Zone, m.State = p.Type, p.Scope, p.Zone, "ACTIVE"
	if err := checkLevels(t.AccessLevels); err != nil {
		return err
	}
	if t.NetworkFlows == nil {
		t.NetworkFlows = []flows.Flow{}
	}
	if err := flows.ValidateList(t.NetworkFlows, 32); err != nil {
		return invalid("networkFlows: %v", err)
	}
	for _, f := range t.NetworkFlows {
		if err := p.Allow.CheckFlow(f); err != nil {
			return refuse(422, "flow-destination-not-allowed", "networkFlows: %v", err)
		}
	}
	if err := checkMetadata(t); err != nil {
		return err
	}
	if authorize != nil {
		if err := authorize(t); err != nil {
			return err
		}
	}
	return normalize(ctx, call, p, t)
}

func checkLevels(levels []AccessLevel) error {
	if len(levels) < 1 || len(levels) > 16 {
		return invalid("accessLevels: 1 to 16")
	}
	seen := map[string]bool{}
	for i := range levels {
		l := &levels[i]
		switch {
		case !levelNameRE.MatchString(l.Name):
			return invalid("accessLevels: name %q must match %s", l.Name, levelNameRE)
		case seen[l.Name]:
			return invalid("accessLevels: %q is defined twice", l.Name)
		case utf8.RuneCountInString(l.Description) > 1024:
			return invalid("accessLevels.%s.description: at most 1024 characters", l.Name)
		case len(l.Privileges) > 0:
			return invalid("accessLevels.%s.privileges is set by ligo", l.Name)
		case l.State != "" && l.State != "ACTIVE":
			return invalid("accessLevels.%s: a new level is ACTIVE", l.Name)
		}
		seen[l.Name], l.State = true, "ACTIVE"
	}
	return nil
}

func checkMetadata(t *Target) error {
	switch {
	case utf8.RuneCountInString(t.DisplayName) > 128:
		return invalid("displayName: at most 128 characters")
	case utf8.RuneCountInString(t.Description) > 4096:
		return invalid("description: at most 4096 characters")
	case len(t.DocumentationURL) > 512:
		return invalid("documentationUrl: at most 512 characters")
	}
	if t.DocumentationURL != "" {
		if u, err := url.Parse(t.DocumentationURL); err != nil || !u.IsAbs() {
			return invalid("documentationUrl: an absolute URL")
		}
	}
	return t.Visibility.Normalize()
}

// normalize asks the platform's plugin to validate t and takes its
// normalized definition, grants and privileges (§7.2.3 step 5).
func normalize(ctx context.Context, call ValidateTarget, p Platform, t *Target) error {
	req := &pluginv1.ValidateTargetRequest{Instance: p.Name, DefinitionJson: t.Definition, CheckExistence: p.CheckExistence}
	for _, l := range t.AccessLevels {
		req.AccessLevels = append(req.AccessLevels, &pluginv1.AccessLevelInput{Name: l.Name, GrantsJson: l.Grants})
	}
	for _, f := range t.NetworkFlows {
		req.NetworkFlows = append(req.NetworkFlows, toProto(f))
	}
	resp, err := call(ctx, req)
	if err != nil {
		return fmt.Errorf("targets: ValidateTarget on %s: %w", p.Name, err)
	}
	if !resp.GetValid() {
		return invalid("%s", strings.Join(resp.GetErrors(), "; "))
	}
	if len(resp.GetAccessLevels()) != len(t.AccessLevels) {
		return invalid("the plugin of %s returned %d access levels for %d", p.Name, len(resp.GetAccessLevels()), len(t.AccessLevels))
	}
	for i, nl := range resp.GetAccessLevels() {
		l := &t.AccessLevels[i]
		pr := nl.GetPrivileges()
		if nl.GetName() != l.Name || !slices.IsSorted(pr) || len(slices.Compact(slices.Clone(pr))) != len(pr) {
			return invalid("the plugin of %s returned level %q with non-canonical privileges (§5.8 rule 9)", p.Name, nl.GetName())
		}
		l.Grants, l.Privileges = nl.GetGrantsJson(), pr
	}
	t.Definition = resp.GetNormalizedDefinitionJson()
	return nil
}

func toProto(f flows.Flow) *pluginv1.NetworkFlow {
	nf := &pluginv1.NetworkFlow{Name: f.Name, Destination: f.Destination, Tls: f.TLS, ServerName: f.ServerName,
		Purpose:  pluginv1.FlowPurpose(pluginv1.FlowPurpose_value["FLOW_PURPOSE_"+f.Purpose]),
		Protocol: pluginv1.FlowProtocol(pluginv1.FlowProtocol_value["FLOW_PROTOCOL_"+f.Protocol])}
	for _, p := range f.Ports {
		nf.Ports = append(nf.Ports, &pluginv1.PortRange{Low: uint32(p.Low), High: uint32(p.High)}) // #nosec G115 -- 1..65535
	}
	return nf
}
