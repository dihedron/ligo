package adminhttp

import (
	"encoding/json"
	"os"
	"testing"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/accounts"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/catalog"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/instances"
	"github.com/dihedron/ligo/internal/preview"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/targets"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

// compileOpenAPI compiles schemas of the OpenAPI document by JSON pointer;
// the network flow schema is the document's one external reference.
func compileOpenAPI(t *testing.T) func(pointer string) *jsonschema.Schema {
	t.Helper()
	data, _ := openAPI(t)
	var asJSON any
	if err := yaml.Unmarshal(data, &asJSON); err != nil {
		t.Fatal(err)
	}
	flow, err := os.Open("../../../api/schemas/v1alpha1/network-flow.json")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = flow.Close() }()
	flowDoc, err := jsonschema.UnmarshalJSON(flow)
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("https://ligo.test/api/openapi/admin.v1alpha1.json", asJSON); err != nil {
		t.Fatal(err)
	}
	if err := c.AddResource("https://ligo.test/api/schemas/v1alpha1/network-flow.json", flowDoc); err != nil {
		t.Fatal(err)
	}
	return func(pointer string) *jsonschema.Schema {
		sch, err := c.Compile("https://ligo.test/api/openapi/admin.v1alpha1.json#" + pointer)
		if err != nil {
			t.Fatalf("%s: %v", pointer, err)
		}
		return sch
	}
}

// satisfies checks that what the server would send for value satisfies sch.
func satisfies(t *testing.T, name string, sch *jsonschema.Schema, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(v); err != nil {
		t.Errorf("%s: %v\n%s", name, err, raw)
	}
}

// TestOpenAPISourceTarget: the source and the target the server sends, in a
// single read with its audit, a list and a page of audit entries, satisfy
// the document's schemas (.specs/ligo-adminclient.md §3.4b).
func TestOpenAPISourceTarget(t *testing.T) {
	compile := compileOpenAPI(t)
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	pending := uuid.New()
	revision := int64(7)
	audit := []auditDTO{
		{ID: 9, Action: "SOURCE_UPDATED", Actor: "ada", Approver: "dora", ChangeRequestID: &pending, Revision: &revision, OccurredAt: now, Snapshot: json.RawMessage(`{"name":"s"}`)},
		{ID: 8, Action: "SOURCE_CREATED", Actor: "ada", OccurredAt: now},
	}

	src := &sources.View{APIVersion: sources.APIVersion, Source: sources.Source{Kind: "Source",
		Identity: sources.Identity{TrustDomain: "example.org", SVIDRegex: "^spiffe://example.org/ns/(a)/sa/.*$", SampleSPIFFEIDs: []string{"spiffe://example.org/ns/a/sa/x"}},
		Labels:   map[string]string{"team": "a"}, Contacts: []sources.Contact{{Name: "Ada", Email: "ada@example.org"}},
		Visibility: sources.Visibility{Mode: "LISTED", VisibleTo: []string{"dc/*"}}}}
	src.Metadata = sources.ViewMetadata{ID: uuid.New(), Name: "s", Jurisdiction: "dc/a", State: "ACTIVE", Revision: 7, CreatedAt: now, UpdatedAt: now, CreatedBy: "ada", UpdatedBy: "ada"}
	src.Status.Bindings = 2

	tgt := &targets.View{APIVersion: sources.APIVersion, Target: targets.Target{Kind: "Target",
		Definition:   json.RawMessage(`{"database":"orders"}`),
		AccessLevels: []targets.AccessLevel{{Name: "read", Grants: json.RawMessage(`{"privileges":["SELECT"]}`), Privileges: []string{"SELECT"}, State: "ACTIVE"}},
		NetworkFlows: []flows.Flow{{Name: "data", Purpose: "DATA", Protocol: "TCP", Destination: "db.example.org", Ports: []flows.Port{{Low: 5432, High: 5432}}, TLS: true}},
		Visibility:   sources.Visibility{Mode: "PRIVATE"}}}
	tgt.Metadata = targets.ViewMetadata{ID: uuid.New(), Name: "t", Jurisdiction: "dc/b", Platform: "pg", PlatformType: "postgres", PlatformJurisdiction: "dc/b",
		Realm: "prod", State: "ACTIVE", Revision: 3, CreatedAt: now, UpdatedAt: now, CreatedBy: "ada", UpdatedBy: "ada", PendingChangeRequestID: &pending}

	for name, tc := range map[string]struct {
		pointer string
		body    any
	}{
		"source read": {"/components/responses/Source/content/application~1json/schema", struct {
			*sources.View
			Audit []auditDTO `json:"audit"`
		}{src, audit}},
		"source list": {"/components/responses/SourcePage/content/application~1json/schema", map[string]any{"items": []any{src}, "nextPageToken": nil}},
		"target read": {"/components/responses/Target/content/application~1json/schema", struct {
			*targets.View
			Audit []auditDTO `json:"audit"`
		}{tgt, audit}},
		"target list": {"/components/responses/TargetPage/content/application~1json/schema", map[string]any{"items": []any{tgt}, "nextPageToken": "x"}},
		"audit page":  {"/components/responses/AuditPage/content/application~1json/schema", map[string]any{"items": audit, "nextPageToken": nil}},
	} {
		satisfies(t, name, compile(tc.pointer), tc.body)
	}

	expires := now.Add(24 * time.Hour)
	bnd := &bindings.View{APIVersion: sources.APIVersion, Kind: "Binding", Source: "s", Target: "t", AccessLevel: "read",
		Parameters: json.RawMessage(`{}`), Purpose: "reporting", Labels: map[string]string{"team": "a"}, ExpiresAt: &expires,
		Auth: json.RawMessage(`{"strategy":"vault-dynamic"}`), Spec: json.RawMessage(`{"host":"db"}`)}
	bnd.Metadata = bindings.ViewMetadata{ID: uuid.New(), Name: "b", Realm: "prod", SourceJurisdiction: "dc/a", TargetJurisdiction: "dc/b", PlatformJurisdiction: "dc/b",
		PlatformType: "postgres", Platform: "pg", Revision: 4, ActiveRevision: &revision, CreatedAt: now, UpdatedAt: now, CreatedBy: "ada", UpdatedBy: "ada"}
	bnd.Metadata.Wiring.IdentityProvider = bindings.Instance{Type: "spire", Instance: "main"}
	bnd.Metadata.Wiring.SecretStore = bindings.Instance{Type: "vault", Instance: "main"}
	bnd.Status = bindings.ViewStatus{Phase: "FAILED", Operation: "REAPPLY", Attempt: 2, WorkflowID: "w", CurrentStep: "TARGET", Message: "boom", LastTransitionTime: now,
		PendingChangeRequestID: &pending, PropagationPending: true,
		BreakGlass: &bindings.BreakGlassStatus{ChangeRequestID: pending, RequestedBy: "ada", IncidentReference: "INC-1", ExpiresAt: expires}}
	bnd.Active = &bindings.ViewActive{Revision: 3, SVIDRegex: "^x$", Since: now}
	bnd.Requested.SourceRevision, bnd.Requested.TargetRevision, bnd.Requested.TrustDomain, bnd.Requested.SVIDRegex = 7, 3, "example.org", "^x$"
	bnd.Requested.Spec = json.RawMessage(`{}`)
	stages := []bindings.Stage{{Stage: "TARGET", ProviderType: "postgres", ProviderInstance: "pg", Status: "ENSURED", Revision: 4, WorkflowID: "w", Artifact: json.RawMessage(`{}`), UpdatedAt: now}}
	for name, tc := range map[string]struct {
		pointer string
		body    any
	}{
		"binding read": {"/components/responses/Binding/content/application~1json/schema", struct {
			*bindings.View
			Stages []bindings.Stage `json:"stages"`
			Audit  []auditDTO       `json:"audit"`
		}{bnd, stages, audit}},
		"binding list": {"/components/responses/BindingPage/content/application~1json/schema", map[string]any{"items": []any{bnd}, "nextPageToken": nil}},
	} {
		satisfies(t, name, compile(tc.pointer), tc.body)
	}
	b := bindings.Binding{Kind: "Binding", Name: "b", Source: "s", Target: "t", AccessLevel: "read", ExpiresAt: &expires}
	satisfies(t, "binding body", compile("/components/schemas/BindingSpec"), b)
	satisfies(t, "binding body with an inline source", compile("/components/schemas/BindingSpec"),
		struct {
			bindings.Binding
			InlineSource sources.Source `json:"inlineSource"`
		}{b, src.Source})

	// An applied filing carries the resource; a pending one, an instance and a deletion carry none.
	filed := compile("/components/responses/Filed/content/application~1json/schema")
	cr := dto(&changerequests.Request{ID: uuid.New(), ResourceType: "SOURCE", ResourceName: "s", Operation: "CREATE", Consent: "ALL", Status: "APPLIED", PayloadSHA256: "ab",
		PolicySHA256: "cd", RequestedBy: "ada", RequestedAt: now, ExpiresAt: now.Add(time.Hour)}, false)
	for name, res := range map[string]any{"a source": src, "a target": tgt, "a binding": bnd, "nothing": nil} {
		satisfies(t, "filed "+name, filed, map[string]any{"changeRequest": cr, "resource": res})
	}

	// Platforms and instances, as a viewer and as a decider sees them.
	revision = 5
	def := &instances.Definition{Kind: "Platform", Metadata: instances.Metadata{Name: "pg", Jurisdiction: "dc/b", Realm: "prod", Contacts: []instances.Contact{{Name: "Ada"}}},
		Type: "postgres", Config: json.RawMessage(`{"host":"db"}`), TargetJurisdictions: []string{"dc/b"}, AllowedSourceTrustDomains: []string{"example.org"},
		RotationInterval: new(instances.Duration), IdentityProvider: &instances.Wiring{Type: "spire", Instance: "main"},
		SecretStore:  &instances.Wiring{Type: "vault", Instance: "main", SecretStorageStrategy: "vault-dynamic"},
		NetworkFlows: []flows.Flow{{Name: "data", Purpose: "DATA", Protocol: "TCP", Destination: "db.example.org", Ports: []flows.Port{{Low: 5432, High: 5432}}, TLS: true}}}
	*def.RotationInterval = instances.Duration(24 * time.Hour)
	plat := platformOf(def)
	plat.Health = &healthDTO{Serving: true}
	plat.UISchemas = json.RawMessage(`{"target":{}}`)
	decided := plat
	decided.Revision, decided.Definition = &revision, def
	idp := &instances.Definition{Kind: "IdentityProvider", Metadata: instances.Metadata{Name: "main", Jurisdiction: "dc/b", Realm: "prod"}, Type: "spire", Config: json.RawMessage(`{}`)}
	inst := instanceOf(idp)
	instDecided := inst
	instDecided.Revision, instDecided.Definition = &revision, idp
	for name, tc := range map[string]struct {
		pointer string
		body    any
	}{
		"platform":           {"/components/responses/Platform/content/application~1json/schema", plat},
		"platform (decider)": {"/components/responses/Platform/content/application~1json/schema", decided},
		"platform list":      {"/components/responses/PlatformPage/content/application~1json/schema", map[string]any{"items": []any{plat}}},
		"instance":           {"/components/responses/Instance/content/application~1json/schema", inst},
		"instance (decider)": {"/components/responses/Instance/content/application~1json/schema", instDecided},
		"instance list":      {"/components/responses/InstancePage/content/application~1json/schema", map[string]any{"items": []any{inst}}},
		"platform body":      {"/components/schemas/InstanceDefinition", def},
		"instance body":      {"/components/schemas/InstanceDefinition", idp},
	} {
		satisfies(t, name, compile(tc.pointer), tc.body)
	}

	// The catalog, the accounts and the bindings of a source or a target.
	retired := now.Add(time.Hour)
	acct := &accounts.Account{Name: "ops", DisplayName: "Operations", Status: "RETIRED", RegisteredBy: "ada", RegisteredAt: now, RetiredBy: "ivy", RetiredAt: &retired,
		Counts: &accounts.Counts{Sources: 1, Targets: 2, Bindings: 3}}
	outcomes := []catalog.Outcome{{Source: "s", SourceJurisdiction: "dc/a", Allowed: true, Rule: "default", Sides: []string{"SOURCE", "TARGET"}}, {Source: "s2", SourceJurisdiction: "dc/b"}}
	for name, tc := range map[string]struct {
		pointer string
		body    any
	}{
		"catalog targets": {"/components/responses/CatalogTargetPage/content/application~1json/schema", map[string]any{"items": []catalog.Target{{Name: "t", Jurisdiction: "dc/b", Platform: "pg",
			PlatformType: "postgres", PlatformJurisdiction: "dc/b", State: "ACTIVE", Labels: map[string]string{"a": "b"}, Bound: true}}, "nextPageToken": nil}},
		"catalog target": {"/components/responses/CatalogTarget/content/application~1json/schema", struct {
			*targets.View
			Outcomes []catalog.Outcome `json:"outcomes"`
		}{tgt, outcomes}},
		"catalog sources": {"/components/responses/CatalogSourcePage/content/application~1json/schema", map[string]any{"items": []catalog.Source{{Name: "s", Jurisdiction: "dc/a", TrustDomain: "example.org"}}, "nextPageToken": nil}},
		"account":         {"/components/responses/Account/content/application~1json/schema", acct},
		"accounts":        {"/components/responses/AccountPage/content/application~1json/schema", map[string]any{"items": []*accounts.Account{acct, {Name: "dev", Status: "ACTIVE", RegisteredBy: "ada", RegisteredAt: now}}, "nextPageToken": "x"}},
	} {
		satisfies(t, name, compile(tc.pointer), tc.body)
	}

	// What a caller writes: the stored form of a source and a target.
	satisfies(t, "source body", compile("/components/schemas/SourceSpec"), src.Source)
	satisfies(t, "target body", compile("/components/schemas/TargetSpec"), tgt.Target)
}

// TestOpenAPIOperations: what the server sends for the operations of
// containment, charter, maintenance, audit and executors satisfies the
// document's schemas (.specs/ligo-adminclient.md §3.4b).
func TestOpenAPIOperations(t *testing.T) {
	compile := compileOpenAPI(t)
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	decision := "APPROVED"
	for name, c := range map[string]struct {
		schema string
		value  any
	}{
		"source test": {"/components/schemas/SourceTestResult", &sources.TestResult{Valid: true, Jurisdiction: "it/rm", Matches: map[string]bool{"spiffe://x/a": true},
			Narrowing: &sources.TestNarrowing{Narrower: false, Witness: "spiffe://x/b", DroppedSamples: []string{"spiffe://x/c"}},
			Overlaps:  []sources.TestOverlap{{Source: "s1", Witness: "spiffe://x/a", Undecided: true}}}},
		"source test, an error": {"/components/schemas/SourceTestResult", &sources.TestResult{Error: "no", Matches: map[string]bool{}, Overlaps: []sources.TestOverlap{}}},
		"charter":               {"/components/schemas/Charter", map[string]any{"policy": json.RawMessage(`{"a":1}`), "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
		"evaluation": {"/components/schemas/Evaluation", &preview.Evaluation{ResourceType: "BINDING", Name: "b", Jurisdictions: map[string]string{"source": "it"},
			NamePrefix: preview.NameCheck{Valid: true}, Consent: "ALL", Interconnect: &preview.Interconnect{Rule: "default", Action: "allow"},
			Sides: []preview.Side{{Side: "SOURCE", Jurisdiction: "it", Basis: "AUTO", Decision: &decision, DecidedAt: &now}}}},
		"evaluation, no rule": {"/components/schemas/Evaluation", &preview.Evaluation{ResourceType: "SOURCE", Name: "s", Jurisdictions: map[string]string{}, Consent: "ANY", Sides: []preview.Side{}}},
		"maintenance":         {"/components/schemas/Maintenance", maintenance{MaintenanceMode: true, Reason: "r", ChangedBy: "u", ChangedAt: &now, InFlight: 1, PropagationQueued: 2}},
		"maintenance, never":  {"/components/schemas/Maintenance", maintenance{}},
		"audit verification":  {"/components/schemas/AuditVerification", map[string]any{"valid": false, "entries": 3, "checkpoints": 1, "full": true, "firstBroken": int64(2)}},
		"export record":       {"/components/schemas/AuditExportRecord", map[string]any{"through": int64(9), "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
		"executor":            {"/components/schemas/Executor", executorDTO{Executor: "e", ApplicationVersion: "v", Pending: 2, OldestPending: &now, LiveSessions: 1, Self: true}},
		"executor, sessions":  {"/components/schemas/Executor", executorDTO{Executor: "e"}},
		"recovery":            {"/components/schemas/ExecutorRecovery", map[string]any{"executor": "e", "recovered": 1, "otherVersions": 0}},
		"revocation":          {"/components/schemas/Revocation", map[string]any{"changeRequests": []any{}, "errors": []map[string]any{{"binding": "b", "type": "urn:ligo:problem:internal", "detail": "internal error"}}}},
	} {
		satisfies(t, name, compile(c.schema), c.value)
	}
}
