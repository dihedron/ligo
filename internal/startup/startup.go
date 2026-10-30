// Package startup runs the startup checks that need the database (§8.2
// step 2): the CONFIG_LOADED audit and the governance policy's changes,
// references to platforms and plugins that no longer exist (rules 10 and
// 11), names of existing resources (rule 16), scope drift and re-scoping
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
	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/engine"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/governance"
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
	Extractors   map[string]*governance.Extractor // the source scope extractors, by trust domain (sources.Rules)
	// AllowOrphanedBindings and AcceptScopeChanges are the flags of
	// ligo serve (§8.2 rules 10 and 17).
	AllowOrphanedBindings bool
	AcceptScopeChanges    bool
	Logger                *slog.Logger

	policy *governance.Policy
}

// Run runs the checks in the order of §8.2 step 2; the first that fails
// stops startup.
func (c *Checks) Run(ctx context.Context) error {
	c.policy = c.Config.Policy()
	for _, check := range []func(context.Context) error{c.configLoaded, c.orphans, c.wiring, c.names, c.scopes, c.interconnects} {
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
// shortcut: no theme file hashes until the UI exists (phase 9).
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
		"policy": json.RawMessage(canonical), "policySha256": sha, "platforms": platforms})}}
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
	rows, err := c.DB.Query(ctx, "SELECT name, platform, platform_type, zone FROM targets WHERE state <> 'RETIRED' ORDER BY name")
	if err != nil {
		return err
	}
	type target struct{ name, platform, typ, zone string }
	targets, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (target, error) {
		var t target
		return t, r.Scan(&t.name, &t.platform, &t.typ, &t.zone)
	})
	if err != nil {
		return err
	}
	for _, t := range targets {
		if p, typ := c.platform(t.platform); p == nil || typ != t.typ || p.Zone != t.zone {
			found = append(found, fmt.Sprintf("target %s: platform %s (%s, zone %s)", t.name, t.platform, t.typ, t.zone))
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
// the scope of an existing resource resolves.
func (c *Checks) names(ctx context.Context) error {
	rows, err := c.DB.Query(ctx, `SELECT 'source', scope FROM sources WHERE state <> 'RETIRED'
		UNION SELECT 'target', scope FROM targets WHERE state <> 'RETIRED' UNION SELECT 'binding', source_scope FROM bindings`)
	if err != nil {
		return err
	}
	scopes, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([2]string, error) {
		var v [2]string
		return v, r.Scan(&v[0], &v[1])
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, s := range scopes {
		if _, err := engine.ResolvePrefix(engine.Kind(s[0]), s[1], c.Config.Governance.NamePrefixes); err != nil {
			errs = append(errs, fmt.Errorf("%s scope %s: %w", s[0], s[1], err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("startup: name prefixes (§8.2 rule 16): %w", errors.Join(errs...))
	}
	return nil
}

// drift is a resource whose stored scope no longer matches the
// configuration.
type drift struct {
	id         uuid.UUID
	name       string
	old, scope string
}

// scopes is rule 17: sources, targets and bindings whose scopes drifted
// fail startup, unless --accept-scope-changes re-scopes them.
func (c *Checks) scopes(ctx context.Context) error {
	var fatal, drifted []string
	var sources, targets []drift
	rows, err := c.DB.Query(ctx, "SELECT id, name, scope, trust_domain, svid_regex FROM sources WHERE state <> 'RETIRED' ORDER BY name")
	if err != nil {
		return err
	}
	type source struct {
		drift
		td, regex string
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (source, error) {
		var s source
		return s, r.Scan(&s.id, &s.name, &s.old, &s.td, &s.regex)
	})
	if err != nil {
		return err
	}
	for _, s := range all {
		x, ok := c.Extractors[s.td]
		if ok {
			s.scope, err = x.SourceScope(s.regex, s.td)
		}
		switch {
		case !ok || err != nil:
			fatal = append(fatal, fmt.Sprintf("source %s: its regex resolves to no scope", s.name))
		case s.scope != s.old:
			sources = append(sources, s.drift)
			drifted = append(drifted, fmt.Sprintf("source %s: %s to %s", s.name, s.old, s.scope))
		}
	}
	rows, err = c.DB.Query(ctx, "SELECT id, name, scope, platform_scope, platform FROM targets WHERE state <> 'RETIRED' ORDER BY name")
	if err != nil {
		return err
	}
	type target struct {
		drift
		scope, platform string
	}
	tgts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (target, error) {
		var t target
		return t, r.Scan(&t.id, &t.name, &t.scope, &t.old, &t.platform)
	})
	if err != nil {
		return err
	}
	for _, t := range tgts {
		p, _ := c.platform(t.platform)
		if p == nil {
			continue // rule 10
		}
		if !slices.ContainsFunc(p.TargetScopes, func(pat string) bool { return governance.ScopeMatches(pat, t.scope) }) {
			fatal = append(fatal, fmt.Sprintf("target %s: scope %s is not in the target_scopes of %s", t.name, t.scope, p.Name))
		}
		if p.Scope != t.old {
			t.drift.scope = p.Scope
			targets = append(targets, t.drift)
			drifted = append(drifted, fmt.Sprintf("target %s: platform scope %s to %s", t.name, t.old, p.Scope))
		}
	}
	var stale int
	if err := c.DB.QueryRow(ctx, staleBindings("count(*)")).Scan(&stale); err != nil {
		return err
	}
	if stale > 0 {
		drifted = append(drifted, fmt.Sprintf("%d bindings whose scopes differ from their source's or target's", stale))
	}
	if len(fatal) > 0 {
		return fmt.Errorf("startup: scopes that no re-scoping can fix (§8.2 rule 17): retire the resources or correct the configuration: %s",
			strings.Join(fatal, "; "))
	}
	if len(drifted) == 0 {
		return nil
	}
	if !c.AcceptScopeChanges {
		return fmt.Errorf("startup: scopes changed (§8.2 rule 17; --accept-scope-changes re-scopes): %s", strings.Join(drifted, "; "))
	}
	for _, s := range sources {
		if err := c.rescope(ctx, "SOURCE", s, "UPDATE sources SET scope = $2 WHERE id = $1",
			"source_id = $1", "source_scope", "payload->>'source' = $2"); err != nil {
			return err
		}
	}
	for _, t := range targets {
		if err := c.rescope(ctx, "TARGET", t, "UPDATE targets SET platform_scope = $2 WHERE id = $1",
			"target_id = $1", "platform_scope", "payload->>'target' = $2"); err != nil {
			return err
		}
	}
	return c.restale(ctx)
}

// staleBindings selects cols of the bindings whose scopes differ from their
// source's and target's.
func staleBindings(cols string) string {
	return "SELECT " + cols + ` FROM bindings b JOIN sources s ON s.id = b.source_id JOIN targets t ON t.id = b.target_id
		WHERE b.source_scope <> s.scope OR b.target_scope <> t.scope OR b.platform_scope <> t.platform_scope`
}

// rescope changes the scope of one source or target and its bindings in
// one transaction, failing their pending change requests (§8.2 rule 17).
// The queries are fixed by the callers: the resource update ($1 id, $2
// scope), the bindings' condition ($1 resource id), the binding column, and
// the condition on pending binding CREATE payloads ($2 resource name).
func (c *Checks) rescope(ctx context.Context, typ string, d drift, update, bindingsOf, column, creates string) error {
	return pgx.BeginFunc(ctx, c.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ligo.rescope = 'on'"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, update, d.id, d.scope); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "UPDATE bindings b SET "+column+" = $2 WHERE "+bindingsOf+" RETURNING b.id, b.name", d.id, d.scope)
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
		entries := []audit.Entry{{ResourceType: typ, ResourceID: &d.id, ResourceName: d.name, Action: typ + "_RESCOPED", Actor: actor,
			Snapshot: snapshot(map[string]string{"old": d.old, "new": d.scope})}}
		for _, b := range bound {
			ids = append(ids, b.id)
			entries = append(entries, audit.Entry{ResourceType: "BINDING", ResourceID: &b.id, ResourceName: b.name, Action: "BINDING_RESCOPED",
				Actor: actor, Snapshot: snapshot(map[string]string{"column": column, "old": d.old, "new": d.scope})})
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
		c.Logger.Warn("re-scoped", "resource_type", typ, "name", d.name, "old", d.old, "new", d.scope, "bindings", len(bound),
			"failed_requests", len(failed))
		return nil
	})
}

// restale re-scopes, each in its own transaction, the bindings whose copies
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
			if _, err := tx.Exec(ctx, "SET LOCAL ligo.rescope = 'on'"); err != nil {
				return err
			}
			var name string
			var old, scopes []string
			err := tx.QueryRow(ctx, `UPDATE bindings b SET source_scope = s.scope, target_scope = t.scope, platform_scope = t.platform_scope
				FROM sources s, targets t, bindings o WHERE b.id = $1 AND o.id = b.id AND s.id = b.source_id AND t.id = b.target_id
				RETURNING b.name, ARRAY[o.source_scope, o.target_scope, o.platform_scope]::text[], ARRAY[b.source_scope, b.target_scope, b.platform_scope]::text[]`,
				id).Scan(&name, &old, &scopes)
			if err != nil {
				return err
			}
			failed, err := failPending(ctx, tx, "SELECT id, resource_type, resource_name FROM change_requests WHERE status = 'PENDING' AND resource_id = $1", id)
			if err != nil {
				return err
			}
			entries := append([]audit.Entry{{ResourceType: "BINDING", ResourceID: &id, ResourceName: name, Action: "BINDING_RESCOPED", Actor: actor,
				Snapshot: snapshot(map[string][]string{"old": old, "new": scopes})}}, failed...)
			for _, e := range entries {
				if _, err := audit.Append(ctx, tx, e); err != nil {
					return err
				}
			}
			c.Logger.Warn("re-scoped", "resource_type", "BINDING", "name", name, "old", old, "new", scopes)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// failPending moves the pending requests the query selects (id,
// resource_type, resource_name) to FAILED_TO_APPLY, "re-scoped", and returns
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
		if err := store.CloseRequest(ctx, tx, q.id, "FAILED_TO_APPLY", actor, "", "re-scoped"); err != nil {
			return nil, err
		}
		entries = append(entries, audit.Entry{ResourceType: q.typ, ResourceName: q.name, ChangeRequestID: &q.id, Action: "CR_APPLY_FAILED",
			Actor: actor, Snapshot: snapshot(map[string]string{"error": "re-scoped"})})
	}
	return entries, nil
}

// interconnects is rule 18: cross-scope bindings that the current policy
// would deny are logged and audited, never changed (ADR-14 rule 6). It
// returns nothing to stop startup.
// shortcut: no ligo_interconnect_violations gauge until metrics (phase 10).
func (c *Checks) interconnects(ctx context.Context) error {
	rows, err := c.DB.Query(ctx, "SELECT name, source_scope, target_scope FROM bindings WHERE source_scope <> target_scope ORDER BY name")
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
		Binding     string `json:"binding"`
		SourceScope string `json:"sourceScope"`
		TargetScope string `json:"targetScope"`
		Rule        string `json:"rule"`
	}
	var found []violation
	for _, p := range pairs {
		if d := c.policy.Evaluate(p[1], p[2]); !d.Allowed {
			c.Logger.Warn("the interconnection policy would deny a binding", "binding", p[0], "source_scope", p[1], "target_scope", p[2], "rule", d.Rule)
			found = append(found, violation{p[0], p[1], p[2], d.Rule})
		}
	}
	if len(found) == 0 {
		return nil
	}
	return appendTx(ctx, c.DB, audit.Entry{Action: "SYSTEM_INTERCONNECT_VIOLATIONS", Actor: actor, Snapshot: snapshot(map[string]any{"bindings": found})})
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
// shortcut: no ligo_privilege_bound_violations gauge until metrics (phase 10).
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
	if len(found) == 0 {
		return nil
	}
	c.Logger.Warn("access levels or flows outside their platform's current bounds", "violations", len(found))
	return appendTx(ctx, c.DB, audit.Entry{Action: "SYSTEM_PRIVILEGE_BOUND_VIOLATIONS", Actor: actor, Snapshot: snapshot(map[string]any{"violations": found})})
}
