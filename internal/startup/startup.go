// Package startup runs the startup checks that need the database (§8.2
// step 2): the CONFIG_LOADED audit and the governance policy's changes,
// references to platforms and plugins that no longer exist (rules 10 and
// 11), names of existing resources (rule 16), jurisdiction drift and transfer
// (rule 17), and interconnection violations (rule 18); after the plugins
// start (step 5), the store strategies (rule 10) and the platforms' current
// bounds (rule 19).
package startup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"uuid"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/accounts"
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/governance"
	"github.com/dihedron/ligo/internal/metrics"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/targets"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// actor is the audit actor of every startup entry.
const actor = "system:startup"

// Checks are the startup checks of one configuration.
type Checks struct {
	DB           *pgxpool.Pool // the app pool
	Config       *config.Config
	ConfigSHA256 string
	ThemeSHA256  map[string]string                // the theme files in use and tokens.css (theme.Theme.Hashes)
	Extractors   map[string]*governance.Extractor // the source jurisdiction extractors, by trust domain (sources.Rules)
	// AllowOrphanedBindings and AcceptJurisdictionChanges are the flags of
	// ligo serve (§8.2 rules 10 and 17).
	AllowOrphanedBindings     bool
	AcceptJurisdictionChanges bool
	Logger                    *slog.Logger

	policy *governance.Policy
}

// Run runs the checks in the order of §8.2 step 2; the first that fails
// stops startup.
func (c *Checks) Run(ctx context.Context) error {
	c.policy = c.Config.Policy()
	for _, check := range []func(context.Context) error{c.configLoaded, c.orphans, c.wiring, c.names, c.jurisdictions, c.interconnects, c.breakGlassParties} {
		if err := check(ctx); err != nil {
			return err
		}
	}
	return nil
}

func appendTx(ctx context.Context, db *pgxpool.Pool, entries ...audit.Entry) error {
	return pgx.BeginFunc(ctx, db, func(tx pgx.Tx) error {
		for _, e := range entries {
			if _, err := audit.Append(ctx, tx, e); err != nil {
				return err
			}
		}
		return nil
	})
}

func snapshot(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

// configLoaded audits CONFIG_LOADED and, against the previous entry's
// policy, CONFIG_GOVERNANCE_POLICY_CHANGED and
// CONFIG_APPROVAL_POLICY_WEAKENED.
func (c *Checks) configLoaded(ctx context.Context) error {
	canonical, err := c.policy.Canonical()
	if err != nil {
		return err
	}
	var previous struct {
		Policy       json.RawMessage           `json:"policy"`
		PolicySHA256 string                    `json:"policySha256"`
		Platforms    map[string]platformBounds `json:"platforms"`
	}
	var prev json.RawMessage
	err = c.DB.QueryRow(ctx, "SELECT snapshot FROM audit_log WHERE action = 'CONFIG_LOADED' ORDER BY id DESC LIMIT 1").Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if prev != nil {
		if err := json.Unmarshal(prev, &previous); err != nil {
			return fmt.Errorf("startup: the previous CONFIG_LOADED entry: %w", err)
		}
	}
	sha := c.policy.SHA256()
	platforms := map[string]platformBounds{}
	for _, pp := range c.Config.PlatformProviders {
		for i := range pp.Platforms {
			p := &pp.Platforms[i]
			platforms[p.Name] = platformBounds{PrivilegeBounds: p.PrivilegeBounds(), AllowedEndpoints: p.AllowedEndpoints(), NetworkFlows: p.NetworkFlows}
		}
	}
	entries := []audit.Entry{{Action: "CONFIG_LOADED", Actor: actor, Snapshot: snapshot(map[string]any{"configSha256": c.ConfigSHA256,
		"policy": json.RawMessage(canonical), "policySha256": sha, "platforms": platforms, "themeSha256": c.ThemeSHA256})}}
	changed, err := platformChanges(previous.Platforms, platforms)
	if err != nil {
		return err
	}
	entries = append(entries, changed...)
	if previous.Policy != nil && previous.PolicySHA256 != sha {
		changes, err := changerequests.Diff(previous.Policy, canonical)
		if err != nil {
			return err
		}
		entries = append(entries, audit.Entry{Action: "CONFIG_GOVERNANCE_POLICY_CHANGED", Actor: actor,
			Snapshot: snapshot(map[string]any{"previousSha256": previous.PolicySHA256, "policySha256": sha, "changes": changes})})
		var old governance.Policy
		if err := json.Unmarshal(previous.Policy, &old); err != nil {
			return fmt.Errorf("startup: the previous policy: %w", err)
		}
		if loose := governance.Loosening(&old, c.policy); len(loose) > 0 {
			c.Logger.Warn("the governance policy is weaker than at the previous start", "changes", loose)
			entries = append(entries, audit.Entry{Action: "CONFIG_APPROVAL_POLICY_WEAKENED", Actor: actor,
				Snapshot: snapshot(map[string]any{"changes": loose})})
		}
	}
	c.Logger.Info("configuration loaded", "config_sha256", c.ConfigSHA256, "policy_sha256", sha)
	return appendTx(ctx, c.DB, entries...)
}

// platformBounds is what rule 19 compares between starts.
type platformBounds struct {
	PrivilegeBounds  map[string]any `json:"privilegeBounds"`
	AllowedEndpoints []string       `json:"allowedEndpoints"`
	NetworkFlows     []flows.Flow   `json:"networkFlows"`
}

// platformChanges audits CONFIG_PLATFORM_CHANGED for each platform whose
// bounds, endpoints or flows differ from the previous start's (rule 19);
// new platforms are no change.
func platformChanges(previous, current map[string]platformBounds) ([]audit.Entry, error) {
	var entries []audit.Entry
	for _, name := range slices.Sorted(maps.Keys(current)) {
		old, ok := previous[name]
		if !ok {
			continue
		}
		a, err := json.Marshal(old)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(current[name])
		if err != nil {
			return nil, err
		}
		changes, err := changerequests.Diff(a, b)
		if err != nil {
			return nil, err
		}
		if len(changes) > 0 {
			entries = append(entries, audit.Entry{Action: "CONFIG_PLATFORM_CHANGED", Actor: actor,
				Snapshot: snapshot(map[string]any{"platform": name, "changes": changes})})
		}
	}
	return entries, nil
}

// platform returns the configured platform called name and its type.
func (c *Checks) platform(name string) (*config.Platform, string) {
	for _, pp := range c.Config.PlatformProviders {
		for i := range pp.Platforms {
			if pp.Platforms[i].Name == name {
				return &pp.Platforms[i], pp.Type
			}
		}
	}
	return nil, ""
}

// instance reports whether (typ, name) is a configured identity provider,
// secret store or platform.
func (c *Checks) instance(typ, name string) bool {
	for _, group := range [][]config.InstanceProvider{c.Config.IdentityProviders, c.Config.SecretStores} {
		for _, p := range group {
			if p.Type == typ && slices.ContainsFunc(p.Instances, func(i config.Instance) bool { return i.Name == name }) {
				return true
			}
		}
	}
	_, pt := c.platform(name)
	return pt == typ
}

// orphans is rule 10: what non-retired targets and existing bindings
// reference must still be configured.
func (c *Checks) orphans(ctx context.Context) error {
	var found []string
	rows, err := c.DB.Query(ctx, "SELECT name, platform, platform_type, realm FROM targets WHERE state <> 'RETIRED' ORDER BY name")
	if err != nil {
		return err
	}
	type target struct{ name, platform, typ, realm string }
	targets, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (target, error) {
		var t target
		return t, r.Scan(&t.name, &t.platform, &t.typ, &t.realm)
	})
	if err != nil {
		return err
	}
	for _, t := range targets {
		if p, typ := c.platform(t.platform); p == nil || typ != t.typ || p.Realm != t.realm {
			found = append(found, fmt.Sprintf("target %s: platform %s (%s, realm %s)", t.name, t.platform, t.typ, t.realm))
		}
	}
	rows, err = c.DB.Query(ctx, `SELECT b.name, w.typ, w.instance FROM bindings b, LATERAL (VALUES
			(b.platform_type, b.platform), (b.identity_provider_type, b.identity_provider_instance), (b.secret_store_type, b.secret_store_instance)
		) AS w(typ, instance)
		UNION SELECT b.name, s.provider_type, s.provider_instance FROM binding_stage_state s JOIN bindings b ON b.id = s.binding_id
		ORDER BY 1, 2, 3`)
	if err != nil {
		return err
	}
	refs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([3]string, error) {
		var v [3]string
		return v, r.Scan(&v[0], &v[1], &v[2])
	})
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if !c.instance(ref[1], ref[2]) {
			found = append(found, fmt.Sprintf("binding %s: %s instance %s", ref[0], ref[1], ref[2]))
		}
	}
	return c.orphaned(ctx, found)
}

// orphaned fails startup on found, unless --allow-orphaned-bindings, which
// logs and audits them.
func (c *Checks) orphaned(ctx context.Context, found []string) error {
	if len(found) == 0 {
		return nil
	}
	if !c.AllowOrphanedBindings {
		return fmt.Errorf("startup: references to platforms or instances that are no longer configured (§8.2 rule 10; --allow-orphaned-bindings starts anyway): %s",
			strings.Join(found, "; "))
	}
	c.Logger.Warn("starting with orphaned references", "references", found)
	return appendTx(ctx, c.DB, audit.Entry{Action: "SYSTEM_ORPHANED_BINDINGS", Actor: actor, Snapshot: snapshot(map[string]any{"references": found})})
}

// Strategies is the part of rule 10 that needs the plugins' descriptions:
// the store of every binding must still declare its secret storage
// strategy. declared returns the strategies a secret store type declares.
func (c *Checks) Strategies(ctx context.Context, declared func(storeType string) []string) error {
	rows, err := c.DB.Query(ctx, "SELECT DISTINCT secret_store_type, secret_storage_strategy FROM bindings ORDER BY 1, 2")
	if err != nil {
		return err
	}
	pairs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([2]string, error) {
		var v [2]string
		return v, r.Scan(&v[0], &v[1])
	})
	if err != nil {
		return err
	}
	var found []string
	for _, p := range pairs {
		if !slices.Contains(declared(p[0]), p[1]) {
			found = append(found, fmt.Sprintf("secret store type %s no longer declares strategy %s", p[0], p[1]))
		}
	}
	return c.orphaned(ctx, found)
}

// wiring is rule 11: bindings whose wiring differs from their platform's
// current wiring keep their snapshot (INV-08); it is only logged.
func (c *Checks) wiring(ctx context.Context) error {
	rows, err := c.DB.Query(ctx, `SELECT name, platform, identity_provider_type, identity_provider_instance, secret_store_type,
		secret_store_instance, secret_storage_strategy FROM bindings ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, platform, idpType, idp, storeType, st, strategy string
		if err := rows.Scan(&name, &platform, &idpType, &idp, &storeType, &st, &strategy); err != nil {
			return err
		}
		p, _ := c.platform(platform)
		if p == nil {
			continue // rule 10
		}
		if p.IdentityProvider.Type != idpType || p.IdentityProvider.Instance != idp || p.SecretStore.Type != storeType || p.SecretStore.Instance != st ||
			p.SecretStore.SecretStorageStrategy != "" && p.SecretStore.SecretStorageStrategy != strategy {
			c.Logger.Warn("a binding keeps the wiring it was created with", "binding", name, "platform", platform)
		}
	}
	return rows.Err()
}

// names is the startup part of rule 16: every name prefix that applies to
// the jurisdiction of an existing resource resolves.
func (c *Checks) names(ctx context.Context) error {
	rows, err := c.DB.Query(ctx, `SELECT 'source', jurisdiction FROM sources WHERE state <> 'RETIRED'
		UNION SELECT 'target', jurisdiction FROM targets WHERE state <> 'RETIRED' UNION SELECT 'binding', source_jurisdiction FROM bindings`)
	if err != nil {
		return err
	}
	jurisdictions, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([2]string, error) {
		var v [2]string
		return v, r.Scan(&v[0], &v[1])
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range jurisdictions {
		if _, err := engine.ResolvePrefix(engine.Kind(s[0]), s[1], c.Config.Governance.NamePrefixes); err != nil {
			errs = append(errs, fmt.Errorf("%s jurisdiction %s: %w", s[0], s[1], err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("startup: name prefixes (§8.2 rule 16): %w", errors.Join(errs...))
	}
	return nil
}

// Namespaces refuses a namespace_template on a platform whose plugin holds no
// namespace, and an existing target outside its namespace (.specs/ligo-tenancy.md
// §5, TN-16). It needs the plugins, as Platforms does.
func (c *Checks) Namespaces(ctx context.Context, declared func(platformType string) string) error {
	var fatal []string
	for _, pp := range c.Config.PlatformProviders {
		for _, p := range pp.Platforms {
			if p.NamespaceTemplate != "" && declared(pp.Type) == "" {
				fatal = append(fatal, fmt.Sprintf("platform %s: plugin %s declares no namespace_field", p.Name, pp.Type))
			}
			bounds := p.PrivilegeBounds()
			if shared, _ := bounds["grantableRoles"].([]string); p.NamespaceTemplate != "" && len(shared) > 0 {
				c.Logger.Warn("grantable_roles on a namespaced platform are shared across tenants", "platform", p.Name, "roles", shared)
			}
			if templates, _ := bounds["grantableRoleTemplates"].([]string); p.NamespaceTemplate == "" && len(templates) > 0 {
				c.Logger.Warn("grantable_role_templates with no namespace_template: a target's schema, and so its roles, are the operator's choice", "platform", p.Name)
			}
		}
	}
	rows, err := c.DB.Query(ctx, "SELECT name, platform, jurisdiction, definition FROM targets WHERE state <> 'RETIRED' ORDER BY name")
	if err != nil {
		return err
	}
	type target struct {
		name, platform, jurisdiction string
		definition                   []byte
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (target, error) {
		var t target
		return t, r.Scan(&t.name, &t.platform, &t.jurisdiction, &t.definition)
	})
	if err != nil {
		return err
	}
	for _, t := range all {
		p, typ := c.platform(t.platform)
		if p == nil || p.NamespaceTemplate == "" {
			continue
		}
		if field := declared(typ); field != "" {
			if err := targets.CheckNamespace(c.Config.Governance.Accounts, p.NamespaceTemplate, field, t.jurisdiction, t.definition); err != nil {
				fatal = append(fatal, fmt.Sprintf("target %s: %v", t.name, err))
			}
		}
	}
	if len(fatal) > 0 {
		return fmt.Errorf("startup: namespaces: correct or retire these: %s", strings.Join(fatal, "; "))
	}
	return nil
}

// drift is a resource whose stored jurisdiction no longer matches the
// configuration.
type drift struct {
	id                uuid.UUID
	name              string
	old, jurisdiction string
}

// accountDrift is a source or target whose account column differs from what
// its jurisdiction gives under the configuration.
type accountDrift struct {
	drift
	typ, table string
}

// accountOf compares the stored account of a resource with its jurisdiction's. A new
// account must be registered: a server that cannot start cannot register it,
// so the message says how to get there.
func (c *Checks) accountOf(ctx context.Context, typ, table string, d drift, jurisdiction, stored string, fatal, drifted *[]string, out *[]accountDrift) error {
	a := c.Config.Governance.Accounts
	want, _ := a.AccountOf(jurisdiction)
	if want == stored {
		return nil
	}
	if _, err := accounts.Require(ctx, c.DB, a, jurisdiction); err != nil {
		if e := (*changerequests.Error)(nil); errors.As(err, &e) {
			*fatal = append(*fatal, fmt.Sprintf("%s %s: account %q of jurisdiction %s is not registered: restore the configuration, register it, and start again",
				strings.ToLower(typ), d.name, want, jurisdiction))
			return nil
		}
		return err
	}
	d.old, d.jurisdiction = stored, want
	*out = append(*out, accountDrift{drift: d, typ: typ, table: table})
	*drifted = append(*drifted, fmt.Sprintf("%s %s: account %q to %q", strings.ToLower(typ), d.name, stored, want))
	return nil
}

// reaccount sets the account of one source or target: a pending request needs
// no failing, as its approval checks the registry again.
func (c *Checks) reaccount(ctx context.Context, d accountDrift) error {
	return pgx.BeginFunc(ctx, c.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ligo.transfer = 'on'"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE "+d.table+" SET account = nullif($2, '') WHERE id = $1", d.id, d.jurisdiction); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, audit.Entry{ResourceType: d.typ, ResourceID: &d.id, ResourceName: d.name, Action: d.typ + "_TRANSFERRED", Actor: actor,
			Snapshot: snapshot(map[string]string{"column": "account", "old": d.old, "new": d.jurisdiction})})
		if err == nil {
			c.Logger.Warn("transferred", "resource_type", d.typ, "name", d.name, "old_account", d.old, "new_account", d.jurisdiction)
		}
		return err
	})
}

// jurisdictions is rule 17: sources, targets and bindings whose jurisdictions drifted
// fail startup, unless --accept-jurisdiction-changes transfers them.
func (c *Checks) jurisdictions(ctx context.Context) error {
	var fatal, drifted []string
	var sources, targets []drift
	var reaccounted []accountDrift
	rows, err := c.DB.Query(ctx, "SELECT id, name, jurisdiction, trust_domain, svid_regex, coalesce(account, '') FROM sources WHERE state <> 'RETIRED' ORDER BY name")
	if err != nil {
		return err
	}
	type source struct {
		drift
		td, regex, account string
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (source, error) {
		var s source
		return s, r.Scan(&s.id, &s.name, &s.old, &s.td, &s.regex, &s.account)
	})
	if err != nil {
		return err
	}
	for _, s := range all {
		x, ok := c.Extractors[s.td]
		if ok {
			s.jurisdiction, err = x.SourceJurisdiction(s.regex, s.td)
		}
		switch {
		case !ok || err != nil:
			fatal = append(fatal, fmt.Sprintf("source %s: its regex resolves to no jurisdiction", s.name))
		case s.jurisdiction != s.old:
			sources = append(sources, s.drift)
			drifted = append(drifted, fmt.Sprintf("source %s: %s to %s", s.name, s.old, s.jurisdiction))
		}
		if ok && err == nil {
			if a := c.Config.Governance.Accounts; !a.SourceConforms(s.jurisdiction) {
				fatal = append(fatal, fmt.Sprintf("source %s: jurisdiction %s does not conform to %s", s.name, s.jurisdiction, a.SourceJurisdiction))
			}
			if err := c.accountOf(ctx, "SOURCE", "sources", s.drift, s.jurisdiction, s.account, &fatal, &drifted, &reaccounted); err != nil {
				return err
			}
		}
	}
	rows, err = c.DB.Query(ctx, "SELECT id, name, jurisdiction, platform_jurisdiction, platform, coalesce(account, '') FROM targets WHERE state <> 'RETIRED' ORDER BY name")
	if err != nil {
		return err
	}
	type target struct {
		drift
		jurisdiction, platform, account string
	}
	tgts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (target, error) {
		var t target
		return t, r.Scan(&t.id, &t.name, &t.jurisdiction, &t.old, &t.platform, &t.account)
	})
	if err != nil {
		return err
	}
	for _, t := range tgts {
		p, _ := c.platform(t.platform)
		if p == nil {
			continue // rule 10
		}
		if !slices.ContainsFunc(p.TargetJurisdictions, func(pat string) bool { return governance.JurisdictionMatches(pat, t.jurisdiction) }) {
			fatal = append(fatal, fmt.Sprintf("target %s: jurisdiction %s is not in the target_jurisdictions of %s", t.name, t.jurisdiction, p.Name))
		}
		if p.Jurisdiction != t.old {
			t.drift.jurisdiction = p.Jurisdiction
			targets = append(targets, t.drift)
			drifted = append(drifted, fmt.Sprintf("target %s: platform jurisdiction %s to %s", t.name, t.old, p.Jurisdiction))
		}
		if a := c.Config.Governance.Accounts; !a.TargetConforms(t.jurisdiction) {
			fatal = append(fatal, fmt.Sprintf("target %s: jurisdiction %s does not conform to %s", t.name, t.jurisdiction, a.TargetJurisdiction))
		}
		if err := c.accountOf(ctx, "TARGET", "targets", t.drift, t.jurisdiction, t.account, &fatal, &drifted, &reaccounted); err != nil {
			return err
		}
	}
	var stale int
	if err := c.DB.QueryRow(ctx, staleBindings("count(*)")).Scan(&stale); err != nil {
		return err
	}
	if stale > 0 {
		drifted = append(drifted, fmt.Sprintf("%d bindings whose jurisdictions differ from their source's or target's", stale))
	}
	if len(fatal) > 0 {
		return fmt.Errorf("startup: jurisdictions that no transfer can fix (§8.2 rule 17): retire the resources or correct the configuration: %s",
			strings.Join(fatal, "; "))
	}
	if len(drifted) == 0 {
		return nil
	}
	if !c.AcceptJurisdictionChanges {
		return fmt.Errorf("startup: jurisdictions changed (§8.2 rule 17; --accept-jurisdiction-changes transfers): %s", strings.Join(drifted, "; "))
	}
	for _, s := range sources {
		if err := c.transfer(ctx, "SOURCE", s, "UPDATE sources SET jurisdiction = $2 WHERE id = $1",
			"source_id = $1", "source_jurisdiction", "payload->>'source' = $2"); err != nil {
			return err
		}
	}
	for _, t := range targets {
		if err := c.transfer(ctx, "TARGET", t, "UPDATE targets SET platform_jurisdiction = $2 WHERE id = $1",
			"target_id = $1", "platform_jurisdiction", "payload->>'target' = $2"); err != nil {
			return err
		}
	}
	for _, d := range reaccounted {
		if err := c.reaccount(ctx, d); err != nil {
			return err
		}
	}
	return c.restale(ctx)
}

// staleBindings selects cols of the bindings whose jurisdictions differ from their
// source's and target's.
func staleBindings(cols string) string {
	return "SELECT " + cols + ` FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id
		WHERE b.source_jurisdiction <> s.jurisdiction OR b.target_jurisdiction <> t.jurisdiction OR b.platform_jurisdiction <> t.platform_jurisdiction`
}

// transfer changes the jurisdiction of one source or target and its bindings in
// one transaction, failing their pending change requests (§8.2 rule 17).
// The queries are fixed by the callers: the resource update ($1 id, $2
// jurisdiction), the bindings' condition ($1 resource id), the binding column, and
// the condition on pending binding CREATE payloads ($2 resource name).
func (c *Checks) transfer(ctx context.Context, typ string, d drift, update, bindingsOf, column, creates string) error {
	return pgx.BeginFunc(ctx, c.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ligo.transfer = 'on'"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, update, d.id, d.jurisdiction); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "UPDATE bindings b SET "+column+" = $2 WHERE "+bindingsOf+" RETURNING b.id, b.name", d.id, d.jurisdiction)
		if err != nil {
			return err
		}
		bound, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (drift, error) {
			var b drift
			return b, r.Scan(&b.id, &b.name)
		})
		if err != nil {
			return err
		}
		ids := []uuid.UUID{d.id}
		entries := []audit.Entry{{ResourceType: typ, ResourceID: &d.id, ResourceName: d.name, Action: typ + "_TRANSFERRED", Actor: actor,
			Snapshot: snapshot(map[string]string{"old": d.old, "new": d.jurisdiction})}}
		for _, b := range bound {
			ids = append(ids, b.id)
			entries = append(entries, audit.Entry{ResourceType: "BINDING", ResourceID: &b.id, ResourceName: b.name, Action: "BINDING_TRANSFERRED",
				Actor: actor, Snapshot: snapshot(map[string]string{"column": column, "old": d.old, "new": d.jurisdiction})})
		}
		failed, err := failPending(ctx, tx, `SELECT id, resource_type, resource_name FROM change_requests WHERE status = 'PENDING'
			AND (resource_id = ANY($1) OR resource_type = 'BINDING' AND operation = 'CREATE' AND `+creates+`)`, ids, d.name)
		if err != nil {
			return err
		}
		for _, e := range append(entries, failed...) {
			if _, err := audit.Append(ctx, tx, e); err != nil {
				return err
			}
		}
		c.Logger.Warn("transferred", "resource_type", typ, "name", d.name, "old", d.old, "new", d.jurisdiction, "bindings", len(bound),
			"failed_requests", len(failed))
		return nil
	})
}

// restale transfers, each in its own transaction, the bindings whose copies
// still differ from their source's and target's.
func (c *Checks) restale(ctx context.Context) error {
	rows, err := c.DB.Query(ctx, staleBindings("b.id"))
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, id := range ids {
		err := pgx.BeginFunc(ctx, c.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL ligo.transfer = 'on'"); err != nil {
				return err
			}
			var name string
			var old, jurisdictions []string
			err := tx.QueryRow(ctx, `UPDATE bindings b SET source_jurisdiction = s.jurisdiction, target_jurisdiction = t.jurisdiction, platform_jurisdiction = t.platform_jurisdiction
				FROM sources s, targets t, bindings o WHERE b.id = $1 AND o.id = b.id AND s.id = b.source_id AND t.id = b.target_id
				RETURNING b.name, ARRAY[o.source_jurisdiction, o.target_jurisdiction, o.platform_jurisdiction]::text[], ARRAY[b.source_jurisdiction, b.target_jurisdiction, b.platform_jurisdiction]::text[]`,
				id).Scan(&name, &old, &jurisdictions)
			if err != nil {
				return err
			}
			failed, err := failPending(ctx, tx, "SELECT id, resource_type, resource_name FROM change_requests WHERE status = 'PENDING' AND resource_id = $1", id)
			if err != nil {
				return err
			}
			entries := append([]audit.Entry{{ResourceType: "BINDING", ResourceID: &id, ResourceName: name, Action: "BINDING_TRANSFERRED", Actor: actor,
				Snapshot: snapshot(map[string][]string{"old": old, "new": jurisdictions})}}, failed...)
			for _, e := range entries {
				if _, err := audit.Append(ctx, tx, e); err != nil {
					return err
				}
			}
			c.Logger.Warn("transferred", "resource_type", "BINDING", "name", name, "old", old, "new", jurisdictions)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// failPending moves the pending requests the query selects (id,
// resource_type, resource_name) to FAILED_TO_APPLY, "transferred", and returns
// their audit entries.
func failPending(ctx context.Context, tx pgx.Tx, query string, args ...any) ([]audit.Entry, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	type request struct {
		id        uuid.UUID
		typ, name string
	}
	pending, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (request, error) {
		var q request
		return q, r.Scan(&q.id, &q.typ, &q.name)
	})
	if err != nil {
		return nil, err
	}
	var entries []audit.Entry
	for _, q := range pending {
		if err := store.CloseRequest(ctx, tx, q.id, "FAILED_TO_APPLY", actor, "", "transferred"); err != nil {
			return nil, err
		}
		entries = append(entries, audit.Entry{ResourceType: q.typ, ResourceName: q.name, ChangeRequestID: &q.id, Action: "CR_APPLY_FAILED",
			Actor: actor, Snapshot: snapshot(map[string]string{"error": "transferred"})})
	}
	return entries, nil
}

// interconnects is rule 18: cross-jurisdiction bindings that the current policy
// would deny are logged and audited, never changed (ADR-14 rule 6). It
// returns nothing to stop startup.
func (c *Checks) interconnects(ctx context.Context) error {
	rows, err := c.DB.Query(ctx, "SELECT name, source_jurisdiction, target_jurisdiction FROM bindings WHERE source_jurisdiction <> target_jurisdiction ORDER BY name")
	if err != nil {
		return err
	}
	pairs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([3]string, error) {
		var v [3]string
		return v, r.Scan(&v[0], &v[1], &v[2])
	})
	if err != nil {
		return err
	}
	type violation struct {
		Binding            string `json:"binding"`
		SourceJurisdiction string `json:"sourceJurisdiction"`
		TargetJurisdiction string `json:"targetJurisdiction"`
		Rule               string `json:"rule"`
	}
	var found []violation
	for _, p := range pairs {
		if d := c.policy.Evaluate(p[1], p[2]); !d.Allowed {
			c.Logger.Warn("the interconnection policy would deny a binding", "binding", p[0], "source_jurisdiction", p[1], "target_jurisdiction", p[2], "rule", d.Rule)
			found = append(found, violation{p[0], p[1], p[2], d.Rule})
		}
	}
	metrics.InterconnectViolations.Set(float64(len(found)))
	if len(found) == 0 {
		return nil
	}
	return appendTx(ctx, c.DB, audit.Entry{Action: "SYSTEM_INTERCONNECT_VIOLATIONS", Actor: actor, Snapshot: snapshot(map[string]any{"bindings": found})})
}

// breakGlassParties warns of the parties that no break-glass policy covers,
// so that the refusal shows before an incident (rule 18, ADR-12).
func (c *Checks) breakGlassParties(ctx context.Context) error {
	found := c.policy.PartiesWithoutBreakGlass()
	if len(found) == 0 {
		return nil
	}
	for _, f := range found {
		c.Logger.Warn("no break-glass policy covers an additional party: break-glass under this rule is always refused", "rule", f.Rule, "party", f.Party, "jurisdiction", f.Jurisdiction)
	}
	return appendTx(ctx, c.DB, audit.Entry{Action: "SYSTEM_BREAK_GLASS_PARTY_UNCOVERED", Actor: actor, Snapshot: snapshot(map[string]any{"parties": found})})
}

// Platforms is the part of rule 19 that needs the plugins: every ACTIVE or
// DEPRECATED access level is re-checked against its platform's current
// privilege bounds (ValidateTarget, without check_existence), and every
// target flow against its platform's allowed_endpoints. Violations are
// logged and audited in one SYSTEM_PRIVILEGE_BOUND_VIOLATIONS entry, never
// changed: their bindings fail in EnsureTarget until the owner acts, and
// the flows are left out of effective flows.
// shortcut: one ValidateTarget call per level, to name the level that
// fails; batch per target if startup grows slow with many targets.
func (c *Checks) Platforms(ctx context.Context, validate targets.ValidateTarget) error {
	rows, err := c.DB.Query(ctx, `SELECT t.name, t.platform, t.definition, l.name, l.grants FROM targets t
		JOIN target_access_levels l ON l.target_id = t.id
		WHERE t.state <> 'RETIRED' AND l.state IN ('ACTIVE', 'DEPRECATED') ORDER BY t.name, l.name`)
	if err != nil {
		return err
	}
	type level struct {
		target, platform, name string
		definition, grants     []byte
	}
	levels, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (level, error) {
		var l level
		return l, r.Scan(&l.target, &l.platform, &l.definition, &l.name, &l.grants)
	})
	if err != nil {
		return err
	}
	type violation struct {
		Target string   `json:"target"`
		Level  string   `json:"level,omitempty"`
		Flow   string   `json:"flow,omitempty"`
		Errors []string `json:"errors"`
	}
	var found []violation
	for _, l := range levels {
		if p, _ := c.platform(l.platform); p == nil {
			continue // rule 10
		}
		resp, err := validate(ctx, &pluginv1.ValidateTargetRequest{Instance: l.platform, DefinitionJson: l.definition,
			AccessLevels: []*pluginv1.AccessLevelInput{{Name: l.name, GrantsJson: l.grants}}})
		if err != nil {
			return fmt.Errorf("startup: ValidateTarget of %s level %s on %s: %w", l.target, l.name, l.platform, err)
		}
		if !resp.GetValid() {
			found = append(found, violation{Target: l.target, Level: l.name, Errors: resp.GetErrors()})
		}
	}
	rows, err = c.DB.Query(ctx, `SELECT t.name, t.platform, f.name, f.purpose, f.protocol, f.destination, f.ports::text, f.tls
		FROM targets t JOIN target_network_flows f ON f.target_id = t.id WHERE t.state <> 'RETIRED' ORDER BY t.name, f.name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var target, platform, ports string
		var f flows.Flow
		if err := rows.Scan(&target, &platform, &f.Name, &f.Purpose, &f.Protocol, &f.Destination, &ports, &f.TLS); err != nil {
			return err
		}
		p, _ := c.platform(platform)
		if p == nil {
			continue // rule 10
		}
		if f.Ports, err = flows.ParseMultirange(ports); err != nil {
			return err
		}
		allow, err := flows.ParseAllowlist(p.AllowedEndpoints())
		if err != nil {
			return err
		}
		if err := allow.CheckFlow(f); err != nil {
			found = append(found, violation{Target: target, Flow: f.Name, Errors: []string{err.Error()}})
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	metrics.PrivilegeBoundViolations.Set(float64(len(found)))
	if len(found) == 0 {
		return nil
	}
	c.Logger.Warn("access levels or flows outside their platform's current bounds", "violations", len(found))
	return appendTx(ctx, c.DB, audit.Entry{Action: "SYSTEM_PRIVILEGE_BOUND_VIOLATIONS", Actor: actor, Snapshot: snapshot(map[string]any{"violations": found})})
}
