//go:build integration

package adminhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/dbos-inc/dbos-transact-golang/dbos"
	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/adminauth"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/catalog"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/config"
	"github.com/dihedron/ligo/internal/sources"
	"github.com/dihedron/ligo/internal/store"
	"github.com/dihedron/ligo/internal/store/migrate"
	"github.com/dihedron/ligo/internal/targets"
	"github.com/dihedron/ligo/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// insecure: CI's container has no TLS; the lab's DSNs use verify-full.
var insecure = os.Getenv("CI") != ""

func dsn(t *testing.T, role string) string {
	t.Helper()
	v := os.Getenv("LIGO_TEST_PG_" + role + "_DSN")
	if v == "" {
		t.Fatalf("LIGO_TEST_PG_%s_DSN is not set: run the integration tests with test/lab/lab.sh test", role)
	}
	return v
}

// ca is a test certificate authority issuing SVIDs and a server
// certificate.
type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, td string) *ca {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse("spiffe://" + td)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, URIs: []*url.URL{u}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &ca{cert, key}
}

func (c *ca) issue(t *testing.T, id string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	if id != "" {
		u, _ := url.Parse(id)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

const (
	opID     = "spiffe://prod.lab/ops/olga"
	appID    = "spiffe://prod.lab/ops/dora"
	adminID  = "spiffe://prod.lab/ops/root"
	viewerID = "spiffe://prod.lab/ops/vera"
	bgID     = "spiffe://prod.lab/ops/glass"
)

// fakeDirectory accepts olivia, a viewer.
type fakeDirectory struct{}

func (fakeDirectory) Authenticate(_ context.Context, user, password string) (authz.Principal, error) {
	switch {
	case user == "olivia" && password == "pw":
		return authz.Principal{Name: "olivia", Groups: []string{"cn=ligo-viewers,ou=groups,dc=ligo,dc=lab"}}, nil
	case user == "livia" && password == "pw":
		return authz.Principal{Name: "livia", Groups: []string{"cn=ligo-breakglass-prod,ou=groups,dc=ligo,dc=lab"}}, nil
	}
	return authz.Principal{}, adminauth.ErrInvalidCredentials
}

// fakeWorkflows records the operational actions it is asked for.
type fakeWorkflows struct{ calls []string }

func (f *fakeWorkflows) Retry(_ context.Context, id uuid.UUID, actor string) (dbos.WorkflowHandle[string], error) {
	f.calls = append(f.calls, "retry "+actor)
	return nil, nil
}

func (f *fakeWorkflows) Rotate(_ context.Context, id uuid.UUID, actor string) (dbos.WorkflowHandle[string], error) {
	f.calls = append(f.calls, "rotate "+actor)
	return nil, nil
}

// fakePlugins: oracle-prod serves, every other platform is unreachable.
type fakePlugins struct{}

func (fakePlugins) Health(_ context.Context, platform string) (*pluginv1.HealthResponse, error) {
	if platform != "oracle-prod" {
		return nil, errors.New("unreachable")
	}
	return &pluginv1.HealthResponse{Serving: true}, nil
}

func (fakePlugins) UISchemas(_ context.Context, platform string) (*pluginv1.GetUISchemasResponse, error) {
	if platform != "oracle-prod" {
		return nil, errors.New("unreachable")
	}
	return &pluginv1.GetUISchemasResponse{PluginType: "oracle.v1", Instance: platform, TargetDefinition: &pluginv1.UIForm{
		Fields: []*pluginv1.UIFieldDescriptor{{JsonKey: "schema", Label: "Schema", FieldType: pluginv1.UIFieldType_UI_FIELD_TYPE_TEXT}}}}, nil
}

type env struct {
	srv     *httptest.Server
	s       *Server
	owner   *pgxpool.Pool
	ca      *ca
	bs      *bindings.Service
	name    string // a binding filed by olga, waiting for dora
	request *changerequests.Request
	suffix  string
}

func validate(_ context.Context, req *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error) {
	return &pluginv1.ValidateBindingResponse{Valid: true, NormalizedParametersJson: []byte("{}"), RequestedSpecJson: []byte("{}"),
		Privileges: []string{"role:LEDGER_RO_ROLE"}}, nil
}

// validateTarget accepts any definition; a level's privileges are its
// roles, sorted.
func validateTarget(_ context.Context, req *pluginv1.ValidateTargetRequest) (*pluginv1.ValidateTargetResponse, error) {
	resp := &pluginv1.ValidateTargetResponse{Valid: true, NormalizedDefinitionJson: req.GetDefinitionJson()}
	for _, l := range req.GetAccessLevels() {
		var g struct {
			Roles []string `json:"roles"`
		}
		_ = json.Unmarshal(l.GetGrantsJson(), &g)
		slices.Sort(g.Roles)
		var privileges []string
		for _, r := range g.Roles {
			privileges = append(privileges, "role:"+r)
		}
		resp.AccessLevels = append(resp.AccessLevels, &pluginv1.NormalizedAccessLevel{Name: l.GetName(), GrantsJson: l.GetGrantsJson(), Privileges: privileges})
	}
	return resp, nil
}

func setup(t *testing.T, listener config.AdminListener) *env {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrate.Apply(ctx, conn, migrations.FS); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)
	pools, err := store.Open(ctx, dsn(t, "APP"), dsn(t, "READER"), insecure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pools.Close)
	owner, err := pgxpool.New(ctx, dsn(t, "MIGRATOR"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)

	data, err := os.ReadFile("../../../examples/server.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := bindings.NewRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	bs := &bindings.Service{DB: pools.App, Rules: rules, Validate: validate}
	bs.Requests = &changerequests.Service{DB: pools.App, Policy: cfg.Policy(), TTL: time.Hour, Resources: map[string]changerequests.Resource{"BINDING": bs},
		BreakGlassRules: cfg.BreakGlass}
	srcRules, err := sources.NewRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ss := &sources.Service{DB: pools.App, Rules: srcRules, Requests: bs.Requests}
	bs.Requests.Resources["SOURCE"] = ss
	tgtRules, err := targets.NewRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := &targets.Service{DB: pools.App, Rules: tgtRules, Requests: bs.Requests, Validate: validateTarget}
	bs.Requests.Resources["TARGET"] = ts
	az, err := authz.New([]config.RoleBinding{
		{SPIFFEID: opID, Role: config.RoleOperator, Scopes: []string{"dc/corp-prod"}},
		{SPIFFEID: appID, Role: config.RoleApprover, Scopes: []string{"dc/*"}},
		{SPIFFEID: adminID, Role: config.RoleFullAccess, Scopes: []string{"*"}},
		{SPIFFEID: viewerID, Role: config.RoleViewer, Scopes: []string{"*"}},
		{SPIFFEID: bgID, Role: config.RoleBreakGlass, Scopes: []string{"dc/*"}},
		{LDAPGroupDN: "cn=ligo-viewers,ou=groups,dc=ligo,dc=lab", Role: config.RoleViewer, Scopes: []string{"*"}},
		{LDAPGroupDN: "cn=ligo-breakglass-prod,ou=groups,dc=ligo,dc=lab", Role: config.RoleBreakGlass, Scopes: []string{"dc/corp-prod/*"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	authority := newCA(t, "prod.lab")
	listener.ClientSVIDAuth = config.ClientSVIDAuth{Enabled: true, AcceptedTrustDomains: []string{"prod.lab"}}
	s := &Server{Listener: listener, Config: cfg, Catalog: &catalog.Reader{DB: pools.App, Policy: cfg.Policy()}, Plugins: fakePlugins{},
		Authz: az, DB: pools.App, Requests: bs.Requests, Bindings: bs, Sources: ss, Targets: ts, Workflows: &fakeWorkflows{},
		Bundles: x509bundle.FromX509Authorities(spiffeid.RequireTrustDomainFromString("prod.lab"), []*x509.Certificate{authority.cert}),
		Logger:  slog.New(slog.DiscardHandler)}
	if listener.AllowBasicAuth {
		s.LDAP = fakeDirectory{}
	}
	srv := httptest.NewUnstartedServer(s.Handler())
	serverCert := authority.issue(t, "")
	srv.TLS = s.TLSConfig(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return &serverCert, nil })
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// a source and a target in dc/corp-prod, and a binding filed by olga
	x := uuid.NewV7().String()[24:]
	targetID := uuid.NewV7()
	err = pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`insert into sources (id, name, scope, trust_domain, svid_regex, visibility, created_by, updated_by) values ($1, $2, 'dc/corp-prod',
				'prod.internal', $3, 'PUBLIC', 't', 't')`, []any{uuid.NewV7(), "src-" + x, `^spiffe://prod\.internal/ns/api/sa/` + x + `$`}},
			{`insert into targets (id, name, platform, platform_type, zone, scope, platform_scope, definition, visibility, created_by, updated_by)
				values ($1, $2, 'oracle-prod', 'oracle.v1', 'prod', 'dc/corp-prod', 'dc/corp-prod', '{}', 'PUBLIC', 't', 't')`, []any{targetID, "tgt-" + x}},
			{`insert into target_access_levels (target_id, name, grants, privileges) values ($1, 'read', '{"roles":["LEDGER_RO_ROLE"]}',
				'["role:LEDGER_RO_ROLE"]')`, []any{targetID}},
		} {
			if _, err := tx.Exec(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = owner.Exec(ctx, "update system_settings set maintenance_mode = false, maintenance_reason = null")
		_, _ = owner.Exec(ctx, "delete from bindings where name like $1", "%"+x)
		_, _ = owner.Exec(ctx, "delete from change_requests where resource_name like $1", "%"+x)
		_, _ = owner.Exec(ctx, "delete from target_access_levels where target_id in (select id from targets where name like $1)", "%"+x)
		_, _ = owner.Exec(ctx, "delete from target_network_flows where target_id in (select id from targets where name like $1)", "%"+x)
		_, _ = owner.Exec(ctx, "delete from targets where name like $1", "%"+x)
		_, _ = owner.Exec(ctx, "delete from sources where name like $1", "%"+x)
	})
	name := "api-" + x
	olga := changerequests.Caller{Principal: authz.Principal{SPIFFEID: opID}, Grants: az.For(authz.Principal{SPIFFEID: opID})}
	r, err := bs.Create(ctx, olga, []byte(fmt.Sprintf(`{"name":%q,"source":"src-%s","target":"tgt-%s","accessLevel":"read"}`, name, x, x)))
	if err != nil || r.Status != "PENDING" {
		t.Fatalf("file the binding: %v", err)
	}
	return &env{srv: srv, s: s, owner: owner, ca: authority, bs: bs, name: name, request: r, suffix: x}
}

// client presents the SVID of id ("" for none) and trusts the test CA.
func (v *env) client(t *testing.T, id string) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(v.ca.cert)
	cfg := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if id != "" {
		cfg.Certificates = []tls.Certificate{v.ca.issue(t, id)}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

type response struct {
	code   int
	header http.Header
	body   map[string]any
}

func (v *env) do(t *testing.T, c *http.Client, method, path string, body any, basic ...string) response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, v.srv.URL+path, rd)
	if len(basic) == 2 {
		req.SetBasicAuth(basic[0], basic[1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := response{code: resp.StatusCode, header: resp.Header}
	_ = json.NewDecoder(resp.Body).Decode(&out.body)
	return out
}

func (r response) slug() string {
	t, _ := r.body["type"].(string)
	return t
}

// TestAuthentication: a verified SVID of an accepted trust domain, or
// Basic credentials only if allowed; every refusal is a problem, and the
// login and API rate limits apply (§7.2.1, §7.3 rule 6).
func TestAuthentication(t *testing.T) {
	v := setup(t, config.AdminListener{RateLimit: config.AdminRateLimit{APIPerPrincipalRPS: 1, LoginPerUserPerMin: 2}})
	if r := v.do(t, v.client(t, ""), "GET", "/v1/admin/maintenance", nil); r.code != 401 || r.slug() != "urn:ligo:problem:unauthenticated" ||
		r.header.Get("X-Request-Id") == "" || r.header.Get("WWW-Authenticate") != "" {
		t.Errorf("no credentials: %+v", r)
	}
	if r := v.do(t, v.client(t, ""), "GET", "/v1/admin/maintenance", nil, "olivia", "pw"); r.code != 401 {
		t.Errorf("Basic while not allowed: %d", r.code)
	}
	foreign := newCA(t, "test.lab")
	c := v.client(t, "")
	c.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{foreign.issue(t, "spiffe://test.lab/ops/x")}
	if _, err := c.Get(v.srv.URL + "/v1/admin/maintenance"); err == nil {
		t.Error("an SVID of another trust domain was accepted")
	}
	viewer := v.client(t, viewerID)
	codes := []int{}
	for range 4 {
		codes = append(codes, v.do(t, viewer, "GET", "/v1/admin/maintenance", nil).code)
	}
	if codes[0] != 200 || !slices.Contains(codes, 429) {
		t.Errorf("API rate limit: %v", codes)
	}

	b := setup(t, config.AdminListener{AllowBasicAuth: true, RateLimit: config.AdminRateLimit{LoginPerUserPerMin: 2}})
	if r := b.do(t, b.client(t, ""), "GET", "/v1/admin/maintenance", nil, "olivia", "pw"); r.code != 200 {
		t.Errorf("Basic olivia: %+v", r)
	}
	if r := b.do(t, b.client(t, ""), "GET", "/v1/admin/maintenance", nil, "olivia", "nope"); r.code != 401 || r.header.Get("WWW-Authenticate") == "" {
		t.Errorf("wrong password: %+v", r)
	}
	if r := b.do(t, b.client(t, ""), "GET", "/v1/admin/maintenance", nil, "olivia", "nope"); r.code != 429 {
		t.Errorf("beyond the login limit: %d", r.code)
	}
	if r := b.do(t, b.client(t, bgID), "GET", "/v1/admin/change-requests", nil); r.code != 403 {
		t.Errorf("break_glass alone lists requests: %d", r.code)
	}
}

// TestRequestsAPI: list, show and decide change requests; refusals are
// problems; audit entries carry the request's id and page by keyset.
func TestRequestsAPI(t *testing.T) {
	v := setup(t, config.AdminListener{})
	dora, olga := v.client(t, appID), v.client(t, opID)
	id := v.request.ID.String()
	r := v.do(t, dora, "GET", "/v1/admin/change-requests?awaitingMe=true&pageSize=200", nil)
	items, _ := r.body["items"].([]any)
	if r.code != 200 || !slices.ContainsFunc(items, func(i any) bool { return i.(map[string]any)["id"] == id }) {
		t.Fatalf("awaiting dora: %d %v", r.code, r.body)
	}
	if r := v.do(t, olga, "GET", "/v1/admin/change-requests?awaitingMe=true&resourceName="+v.name, nil); len(r.body["items"].([]any)) != 0 {
		t.Errorf("awaiting the requester: %v", r.body)
	}
	got := v.do(t, dora, "GET", "/v1/admin/change-requests/"+id, nil)
	if got.code != 200 || got.body["payloadSha256"] != v.request.PayloadSHA256 || got.body["payload"] == nil ||
		fmt.Sprint(got.body["awaitingApproval"]) != "[TARGET]" {
		t.Fatalf("get: %+v", got)
	}
	for _, tc := range []struct {
		path string
		body any
		code int
		slug string
	}{
		{"/approve", map[string]string{"payloadSha256": "00"}, 409, "payload-mismatch"},
		{"/decline", map[string]string{}, 422, "validation-failed"},
		{"/approve", map[string]string{"payloadSha256": v.request.PayloadSHA256, "unknown": "x"}, 422, "validation-failed"},
	} {
		if r := v.do(t, dora, "POST", "/v1/admin/change-requests/"+id+tc.path, tc.body); r.code != tc.code || r.slug() != "urn:ligo:problem:"+tc.slug {
			t.Errorf("%s %v: %d %v", tc.path, tc.body, r.code, r.body)
		}
	}
	if r := v.do(t, olga, "POST", "/v1/admin/change-requests/"+id+"/approve", map[string]string{"payloadSha256": v.request.PayloadSHA256}); r.code != 403 {
		t.Errorf("the requester approves: %d %v", r.code, r.body)
	}
	ok := v.do(t, dora, "POST", "/v1/admin/change-requests/"+id+"/approve", map[string]string{"payloadSha256": v.request.PayloadSHA256, "comment": "fine"})
	if ok.code != 200 || ok.body["changeRequest"].(map[string]any)["status"] != "APPLIED" {
		t.Fatalf("approve: %+v", ok)
	}
	var requestID string
	if err := v.owner.QueryRow(context.Background(), `select coalesce(request_id, '') from audit_log where change_request_id = $1
		and action = 'CR_APPROVED'`, v.request.ID).Scan(&requestID); err != nil || requestID != ok.header.Get("X-Request-Id") {
		t.Errorf("audit request_id %q, response %q (%v)", requestID, ok.header.Get("X-Request-Id"), err)
	}
	if r := v.do(t, olga, "POST", "/v1/admin/change-requests/"+id+"/withdraw", nil); r.code != 409 {
		t.Errorf("withdraw an applied request: %d %v", r.code, r.body)
	}
	for _, p := range []string{"/v1/admin/change-requests/" + uuid.NewV7().String(), "/v1/admin/change-requests/x", "/v1/admin/bindings/nope/audit", "/v1/admin/things/x/audit"} {
		if r := v.do(t, dora, "GET", p, nil); r.code != 404 {
			t.Errorf("%s: %d", p, r.code)
		}
	}

	first := v.do(t, dora, "GET", "/v1/admin/bindings/"+v.name+"/audit?pageSize=1", nil)
	next, _ := first.body["nextPageToken"].(string)
	if first.code != 200 || len(first.body["items"].([]any)) != 1 || next == "" {
		t.Fatalf("audit page 1: %+v", first)
	}
	second := v.do(t, dora, "GET", "/v1/admin/bindings/"+v.name+"/audit?pageSize=1&pageToken="+next, nil)
	a, b := first.body["items"].([]any)[0].(map[string]any)["id"], second.body["items"].([]any)[0].(map[string]any)["id"]
	if second.code != 200 || a.(float64) <= b.(float64) {
		t.Errorf("audit page 2: %v after %v", b, a)
	}
	if r := v.do(t, dora, "GET", "/v1/admin/bindings/"+v.name+"/audit?pageSize=500", nil); r.code != 422 {
		t.Errorf("pageSize 500: %d", r.code)
	}
	if r := v.do(t, dora, "GET", "/v1/admin/audit/verify", nil); r.code != 200 || r.body["valid"] != true {
		t.Errorf("verify: %+v", r)
	}
}

// TestMaintenanceAPI: admin.full_access turns maintenance on with a
// reason; changes are then refused with 503 and Retry-After (AC-26).
func TestMaintenanceAPI(t *testing.T) {
	v := setup(t, config.AdminListener{})
	admin, viewer, dora := v.client(t, adminID), v.client(t, viewerID), v.client(t, appID)
	var start int64 // audit ids grow; clocks of host and database may differ
	if err := v.owner.QueryRow(context.Background(), "select coalesce(max(id), 0) from audit_log").Scan(&start); err != nil {
		t.Fatal(err)
	}
	if r := v.do(t, viewer, "PUT", "/v1/admin/maintenance", map[string]any{"enabled": true, "reason": "upgrade"}); r.code != 403 {
		t.Errorf("a viewer: %d", r.code)
	}
	if r := v.do(t, admin, "PUT", "/v1/admin/maintenance", map[string]any{"enabled": true}); r.code != 422 {
		t.Errorf("no reason: %d", r.code)
	}
	if r := v.do(t, admin, "PUT", "/v1/admin/maintenance", map[string]any{"enabled": true, "reason": "upgrade to 4.1"}); r.code != 200 ||
		r.body["maintenanceMode"] != true || r.body["changedBy"] != adminID {
		t.Fatalf("enable: %+v", r)
	}
	r := v.do(t, dora, "POST", "/v1/admin/change-requests/"+v.request.ID.String()+"/approve", map[string]string{"payloadSha256": v.request.PayloadSHA256})
	if r.code != 503 || r.slug() != "urn:ligo:problem:maintenance" || r.header.Get("Retry-After") != "60" {
		t.Errorf("approve in maintenance: %+v", r)
	}
	if r := v.do(t, admin, "PUT", "/v1/admin/maintenance", map[string]any{"enabled": false}); r.code != 200 || r.body["maintenanceMode"] != false {
		t.Errorf("disable: %+v", r)
	}
	var n int
	if err := v.owner.QueryRow(context.Background(), `select count(*) from audit_log where actor = $1
		and action in ('SYSTEM_MAINTENANCE_ENABLED', 'SYSTEM_MAINTENANCE_DISABLED') and id > $2`, adminID, start).Scan(&n); err != nil || n != 2 {
		t.Errorf("audited %d (%v)", n, err)
	}
}

// TestSourcesAPI: register a source through approval, show and list it,
// narrow it with a diff of the samples it drops, test regexes; refusals
// are problems (§7.2.3 sources).
func TestSourcesAPI(t *testing.T) {
	v := setup(t, config.AdminListener{})
	olga, dora, viewer := v.client(t, opID), v.client(t, appID), v.client(t, viewerID)
	name, re := "api-src-"+v.suffix, `^spiffe://prod\.internal/ns/api/sa/w-[0-9]+$`
	sample := func(n string) string { return "spiffe://prod.internal/ns/api/sa/w-" + n }
	created := v.do(t, olga, "POST", "/v1/admin/sources", map[string]any{"metadata": map[string]string{"name": name},
		"identity":   map[string]any{"trustDomain": "prod.internal", "svidRegex": re, "sampleSpiffeIds": []string{sample("1"), sample("12")}},
		"visibility": map[string]string{"mode": "PRIVATE"}})
	cr, _ := created.body["changeRequest"].(map[string]any)
	if created.code != 202 || cr["status"] != "PENDING" || created.body["resource"] != nil {
		t.Fatalf("create: %+v", created)
	}
	ok := v.do(t, dora, "POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve", map[string]string{"payloadSha256": cr["payloadSha256"].(string)})
	if ok.code != 200 {
		t.Fatalf("approve: %+v", ok)
	}
	got := v.do(t, viewer, "GET", "/v1/admin/sources/"+name, nil)
	md, _ := got.body["metadata"].(map[string]any)
	if got.code != 200 || got.body["apiVersion"] != sources.APIVersion || md["scope"] != "dc/corp-prod" || md["revision"] != 1.0 ||
		md["pendingChangeRequestId"] != nil || len(got.body["audit"].([]any)) == 0 {
		t.Fatalf("get: %+v", got)
	}

	narrow := v.do(t, olga, "PUT", "/v1/admin/sources/"+name, map[string]any{"metadata": map[string]string{"name": name},
		"identity":   map[string]any{"trustDomain": "prod.internal", "svidRegex": `^spiffe://prod\.internal/ns/api/sa/w-[0-9]$`, "sampleSpiffeIds": []string{sample("1")}},
		"visibility": map[string]string{"mode": "PRIVATE"}, "expectedRevision": 1})
	ncr, _ := narrow.body["changeRequest"].(map[string]any)
	if narrow.code != 202 || ncr["status"] != "PENDING" {
		t.Fatalf("narrow: %+v", narrow)
	}
	shown := v.do(t, dora, "GET", "/v1/admin/change-requests/"+ncr["id"].(string), nil)
	diff, _ := shown.body["diff"].(map[string]any)
	if fmt.Sprint(diff["droppedSamples"]) != "["+sample("12")+"]" || len(diff["changes"].([]any)) != 1 {
		t.Errorf("diff: %v", shown.body["diff"])
	}
	if md := v.do(t, viewer, "GET", "/v1/admin/sources/"+name, nil).body["metadata"].(map[string]any); md["pendingChangeRequestId"] != ncr["id"] {
		t.Errorf("pending: %v", md["pendingChangeRequestId"])
	}
	for _, tc := range []struct {
		method, path string
		body         any
		code         int
	}{
		{"POST", "/v1/admin/sources/" + name + "/deprecate", map[string]any{}, 422},
		{"POST", "/v1/admin/sources/" + name + "/deprecate", map[string]any{"expectedRevision": 1}, 409},
		{"POST", "/v1/admin/sources/" + name + "/explode", map[string]any{"expectedRevision": 1}, 404},
		{"GET", "/v1/admin/sources/nope-" + v.suffix, nil, 404},
	} {
		if r := v.do(t, olga, tc.method, tc.path, tc.body); r.code != tc.code {
			t.Errorf("%s %s: %d %v", tc.method, tc.path, r.code, r.body)
		}
	}

	tested := v.do(t, viewer, "POST", "/v1/admin/sources/test", map[string]any{"trustDomain": "prod.internal",
		"svidRegex": `^spiffe://prod\.internal/ns/api/sa/w-1[0-9]$`, "spiffeIds": []string{sample("12"), sample("3")}, "currentSource": name})
	n, _ := tested.body["narrowing"].(map[string]any)
	if tested.code != 200 || tested.body["valid"] != true || tested.body["scope"] != "dc/corp-prod" ||
		fmt.Sprint(tested.body["matches"]) != fmt.Sprintf("map[%s:true %s:false]", sample("12"), sample("3")) ||
		n["narrower"] != true || fmt.Sprint(n["droppedSamples"]) != "["+sample("1")+"]" {
		t.Errorf("test: %+v", tested.body)
	}
	overlap := v.do(t, viewer, "POST", "/v1/admin/sources/test", map[string]any{"trustDomain": "prod.internal", "svidRegex": `^spiffe://prod\.internal/ns/api/sa/w-7$`})
	if o := overlap.body["overlaps"].([]any); len(o) != 1 || o[0].(map[string]any)["source"] != name || o[0].(map[string]any)["witness"] != sample("7") {
		t.Errorf("overlaps: %v", overlap.body["overlaps"])
	}
	if r := v.do(t, viewer, "POST", "/v1/admin/sources/test", map[string]any{"trustDomain": "prod.internal", "svidRegex": "^spiffe://.*$"}); r.body["valid"] != false {
		t.Errorf("invalid regex: %v", r.body)
	}

	first := v.do(t, viewer, "GET", "/v1/admin/sources?q="+v.suffix+"&pageSize=1", nil)
	next, _ := first.body["nextPageToken"].(string)
	if first.code != 200 || len(first.body["items"].([]any)) != 1 || next == "" {
		t.Fatalf("list: %+v", first.body)
	}
	second := v.do(t, viewer, "GET", "/v1/admin/sources?q="+v.suffix+"&pageSize=1&pageToken="+next, nil)
	if items := second.body["items"].([]any); len(items) != 1 || second.body["nextPageToken"] != nil ||
		items[0].(map[string]any)["metadata"].(map[string]any)["name"] == first.body["items"].([]any)[0].(map[string]any)["metadata"].(map[string]any)["name"] {
		t.Errorf("list page 2: %+v", second.body)
	}
}

// TestTargetsAPI: publish a target through its owner and platform sides,
// show, list and narrow it, with the privileges a level loses; revoke a
// source's bindings on it in bulk (§7.2.3 targets, AC-79).
func TestTargetsAPI(t *testing.T) {
	v := setup(t, config.AdminListener{})
	olga, dora, admin, viewer := v.client(t, opID), v.client(t, appID), v.client(t, adminID), v.client(t, viewerID)
	name := "api-tgt-" + v.suffix
	level := func(n string, roles ...string) map[string]any {
		return map[string]any{"name": n, "grants": map[string][]string{"roles": roles}}
	}
	target := func(levels ...map[string]any) map[string]any {
		return map[string]any{"metadata": map[string]string{"name": name, "platform": "oracle-prod", "scope": "dc/corp-prod/ledger"},
			"definition": map[string]string{"schema": "LEDGER_APP"}, "accessLevels": levels, "networkFlows": []any{},
			"visibility": map[string]string{"mode": "PRIVATE"}}
	}
	created := v.do(t, olga, "POST", "/v1/admin/targets", target(level("read", "LEDGER_RO_ROLE"), level("write", "LEDGER_RO_ROLE", "LEDGER_RW_ROLE")))
	cr, _ := created.body["changeRequest"].(map[string]any)
	if created.code != 202 || cr["status"] != "PENDING" || fmt.Sprint(cr["awaitingApproval"]) != "[OWNER PLATFORM]" {
		t.Fatalf("create: %+v", created)
	}
	for i, c := range []*http.Client{dora, admin} { // distinct approvers, one per side
		side := []string{"OWNER", "PLATFORM"}[i]
		if r := v.do(t, c, "POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve", map[string]string{"payloadSha256": cr["payloadSha256"].(string), "side": side}); r.code != 200 {
			t.Fatalf("approve %s: %+v", side, r)
		}
	}
	got := v.do(t, viewer, "GET", "/v1/admin/targets/"+name, nil)
	md, _ := got.body["metadata"].(map[string]any)
	if got.code != 200 || md["platformScope"] != "dc/corp-prod" || md["revision"] != 1.0 || len(got.body["accessLevels"].([]any)) != 2 ||
		len(got.body["audit"].([]any)) == 0 {
		t.Fatalf("get: %+v", got)
	}

	body := target(level("read", "LEDGER_RO_ROLE"), level("write", "LEDGER_RO_ROLE"))
	body["expectedRevision"] = 1
	narrow := v.do(t, olga, "PUT", "/v1/admin/targets/"+name, body)
	ncr, _ := narrow.body["changeRequest"].(map[string]any)
	if narrow.code != 202 || ncr["status"] != "PENDING" {
		t.Fatalf("narrow: %+v", narrow)
	}
	diff, _ := v.do(t, dora, "GET", "/v1/admin/change-requests/"+ncr["id"].(string), nil).body["diff"].(map[string]any)
	if fmt.Sprint(diff["removedPrivileges"]) != "map[write:[role:LEDGER_RW_ROLE]]" {
		t.Errorf("diff: %v", diff)
	}
	for _, tc := range []struct {
		path string
		body any
		code int
	}{
		{"/access-levels/read/deprecate", map[string]any{}, 422},
		{"/access-levels/read/deprecate", map[string]any{"expectedRevision": 1}, 409},
		{"/retire", map[string]any{"expectedRevision": 1}, 409},
	} {
		if r := v.do(t, olga, "POST", "/v1/admin/targets/"+name+tc.path, tc.body); r.code != tc.code {
			t.Errorf("%s: %d %v", tc.path, r.code, r.body)
		}
	}
	list := v.do(t, olga, "GET", "/v1/admin/targets?q="+v.suffix, nil)
	if items := list.body["items"].([]any); list.code != 200 || len(items) != 2 {
		t.Errorf("olga administers %d targets: %v", len(items), list.body)
	}
	if r := v.do(t, viewer, "GET", "/v1/admin/targets?platform=oracle-prod&q=api-tgt-"+v.suffix, nil); len(r.body["items"].([]any)) != 1 {
		t.Errorf("platform filter: %v", r.body)
	}

	// bulk revocation: the binding filed in setup, applied, then revoked
	if r := v.do(t, dora, "POST", "/v1/admin/change-requests/"+v.request.ID.String()+"/approve", map[string]string{"payloadSha256": v.request.PayloadSHA256}); r.code != 200 {
		t.Fatalf("approve the binding: %+v", r)
	}
	if _, err := v.owner.Exec(context.Background(), "update bindings set phase = 'ACTIVE' where name = $1", v.name); err != nil {
		t.Fatal(err)
	}
	revoke := "/v1/admin/targets/tgt-" + v.suffix + "/bindings/revoke"
	for _, tc := range []struct {
		c    *http.Client
		body map[string]string
		code int
	}{
		{olga, map[string]string{"source": "src-" + v.suffix}, 422},
		{olga, map[string]string{"source": "src-" + v.suffix, "sourceScope": "dc/*", "comment": "x"}, 422},
		{viewer, map[string]string{"sourceScope": "dc/*", "comment": "contain"}, 403},
	} {
		if r := v.do(t, tc.c, "POST", revoke, tc.body); r.code != tc.code {
			t.Errorf("%v: %d %v", tc.body, r.code, r.body)
		}
	}
	r := v.do(t, olga, "POST", revoke, map[string]string{"sourceScope": "dc/*", "comment": "compromised workload"})
	crs, _ := r.body["changeRequests"].([]any)
	if r.code != 202 || len(crs) != 1 || len(r.body["errors"].([]any)) != 0 {
		t.Fatalf("revoke: %+v", r)
	}
	if c := crs[0].(map[string]any); c["operation"] != "DELETE" || c["consent"] != "ANY" || c["resourceName"] != v.name {
		t.Errorf("revocation: %v", c)
	}
}

// TestBindingsAPI: show, list, change, rotate and revoke bindings; their
// flows; break-glass with Basic credentials only (§7.2.3 bindings).
func TestBindingsAPI(t *testing.T) {
	v := setup(t, config.AdminListener{AllowBasicAuth: true})
	ctx := context.Background()
	olga, dora, viewer := v.client(t, opID), v.client(t, appID), v.client(t, viewerID)
	x := v.suffix
	if r := v.do(t, dora, "POST", "/v1/admin/change-requests/"+v.request.ID.String()+"/approve", map[string]string{"payloadSha256": v.request.PayloadSHA256}); r.code != 200 {
		t.Fatalf("approve: %+v", r)
	}
	got := v.do(t, viewer, "GET", "/v1/admin/bindings/"+v.name, nil)
	st, _ := got.body["status"].(map[string]any)
	req, _ := got.body["requested"].(map[string]any)
	if got.code != 200 || got.body["kind"] != "Binding" || st["phase"] != "PROVISIONING" || got.body["active"] != nil ||
		req["svidRegex"] == "" || got.body["stages"] == nil || len(got.body["audit"].([]any)) == 0 {
		t.Fatalf("get: %+v", got.body)
	}
	for path, n := range map[string]int{"/v1/admin/bindings?source=src-" + x: 1, "/v1/admin/bindings?source=src-" + x + "&phase=ACTIVE": 0,
		"/v1/admin/bindings?scope=dc/*&target=tgt-" + x: 1, "/v1/admin/sources/src-" + x + "/bindings": 1, "/v1/admin/targets/tgt-" + x + "/bindings": 1,
		"/v1/admin/bindings?propagationPending=true&source=src-" + x: 0} {
		if r := v.do(t, viewer, "GET", path, nil); r.code != 200 || len(r.body["items"].([]any)) != n {
			t.Errorf("%s: %d %v", path, r.code, r.body)
		}
	}
	if r := v.do(t, viewer, "GET", "/v1/admin/sources/nope-"+x+"/bindings", nil); r.code != 404 {
		t.Errorf("bindings of an unknown source: %d", r.code)
	}
	if r := v.do(t, viewer, "GET", "/v1/admin/bindings?expiringBefore=tomorrow", nil); r.code != 422 {
		t.Errorf("bad expiringBefore: %d", r.code)
	}
	flows := v.do(t, viewer, "GET", "/v1/admin/bindings/"+v.name+"/flows", nil)
	if fs, _ := flows.body["networkFlows"].([]any); flows.code != 200 || len(fs) == 0 || fs[len(fs)-1].(map[string]any)["declaredBy"] != "ligo" {
		t.Errorf("flows: %+v", flows.body)
	}

	if _, err := v.owner.Exec(ctx, "update bindings set phase = 'ACTIVE' where name = $1", v.name); err != nil {
		t.Fatal(err)
	}
	upd := v.do(t, olga, "PUT", "/v1/admin/bindings/"+v.name, map[string]any{"name": v.name, "source": "src-" + x, "target": "tgt-" + x,
		"accessLevel": "read", "purpose": "reporting", "expectedRevision": 1})
	ucr, _ := upd.body["changeRequest"].(map[string]any)
	if upd.code != 202 || ucr["status"] != "PENDING" {
		t.Fatalf("update: %+v", upd)
	}
	diff, _ := v.do(t, dora, "GET", "/v1/admin/change-requests/"+ucr["id"].(string), nil).body["diff"].(map[string]any)
	if changes, _ := diff["changes"].([]any); len(changes) != 1 || changes[0].(map[string]any)["field"] != "purpose" {
		t.Errorf("diff: %v", diff)
	}
	if r := v.do(t, olga, "POST", "/v1/admin/change-requests/"+ucr["id"].(string)+"/withdraw", nil); r.code != 200 {
		t.Fatalf("withdraw: %+v", r)
	}
	if r := v.do(t, viewer, "POST", "/v1/admin/bindings/"+v.name+"/rotate", nil); r.code != 403 {
		t.Errorf("a viewer rotates: %d", r.code)
	}
	if r := v.do(t, olga, "POST", "/v1/admin/bindings/"+v.name+"/rotate", nil); r.code != 202 ||
		fmt.Sprint(v.s.Workflows.(*fakeWorkflows).calls) != "[rotate "+opID+"]" {
		t.Errorf("rotate: %d %v", r.code, v.s.Workflows.(*fakeWorkflows).calls)
	}
	if r := v.do(t, olga, "DELETE", "/v1/admin/bindings/"+v.name, nil); r.code != 422 {
		t.Errorf("delete without a revision: %d", r.code)
	}
	if r := v.do(t, olga, "DELETE", "/v1/admin/bindings/"+v.name+"?expectedRevision=1", nil); r.code != 202 ||
		r.body["changeRequest"].(map[string]any)["operation"] != "DELETE" {
		t.Errorf("delete: %+v", r)
	}

	// ?wait=true: a change complete at creation answers once the binding settled
	if _, err := v.owner.Exec(ctx, `insert into sources (id, name, scope, trust_domain, svid_regex, visibility, created_by, updated_by)
		values ($1, $2, 'dc/corp-prod', 'prod.internal', $3, 'PUBLIC', 't', 't')`, uuid.NewV7(), "src2-"+x,
		`^spiffe://prod\.internal/ns/api2/sa/`+x+`$`); err != nil {
		t.Fatal(err)
	}
	v.bs.Requests.Policy.RequiredScopes = nil
	v.bs.Start = func(ctx context.Context, id uuid.UUID) error {
		_, err := v.owner.Exec(ctx, "update bindings set phase = 'ACTIVE' where id = $1", id)
		return err
	}
	waited := v.do(t, olga, "POST", "/v1/admin/bindings?wait=true", map[string]string{"name": "api2-" + x, "source": "src2-" + x,
		"target": "tgt-" + x, "accessLevel": "read"})
	if res, _ := waited.body["resource"].(map[string]any); waited.code != 200 || res["status"].(map[string]any)["phase"] != "ACTIVE" {
		t.Errorf("wait: %+v", waited)
	}

	// break-glass: Basic credentials on the request, never an SVID
	v.bs.Requests.Policy.RequiredScopes = []string{"dc/corp-prod/*"}
	bg := map[string]any{"operation": "DELETE", "name": "api2-" + x, "expectedRevision": 1, "justification": "the workload is compromised, cut it",
		"incidentReference": "INC0012345"}
	if r := v.do(t, olga, "POST", "/v1/admin/break-glass", bg); r.code != 403 {
		t.Errorf("break-glass by SVID: %d", r.code)
	}
	r := v.do(t, v.client(t, ""), "POST", "/v1/admin/break-glass", bg, "livia", "pw")
	if bcr, _ := r.body["changeRequest"].(map[string]any); r.code != 202 || bcr["kind"] != "BREAK_GLASS" || bcr["status"] != "APPLIED" {
		t.Fatalf("break-glass: %+v", r)
	}
	listed := v.do(t, dora, "GET", "/v1/admin/break-glass?resourceName=api2-"+x, nil)
	if items, _ := listed.body["items"].([]any); len(items) != 1 || items[0].(map[string]any)["breakGlass"] == nil {
		t.Errorf("break-glass list: %+v", listed.body)
	}
	if r = v.do(t, v.client(t, ""), "GET", "/v1/admin/maintenance", nil, "livia", "wrong"); r.code != 401 {
		t.Errorf("wrong password: %d", r.code)
	}
	var failed int
	if err := v.owner.QueryRow(ctx, `select count(*) from audit_log where action = 'SESSION_LOGIN_FAILED' and snapshot->>'username' = 'livia'
		and request_id = $1`, r.header.Get("X-Request-Id")).Scan(&failed); err != nil || failed != 1 {
		t.Errorf("failed login not audited (%v)", err)
	}
}

// TestPlatformsAPI: platforms from server.yaml, without credentials, with
// their health and, one at a time, their forms (§3.4).
func TestPlatformsAPI(t *testing.T) {
	v := setup(t, config.AdminListener{})
	viewer := v.client(t, viewerID)
	list := v.do(t, viewer, "GET", "/v1/admin/platforms", nil)
	byName := map[string]map[string]any{}
	for _, it := range list.body["items"].([]any) {
		p := it.(map[string]any)
		byName[p["name"].(string)] = p
	}
	prod, test := byName["oracle-prod"], byName["oracle-test-dynamic"]
	if list.code != 200 || prod == nil || test == nil || prod["kind"] != "Platform" || prod["scope"] != "dc/corp-prod" ||
		prod["health"].(map[string]any)["serving"] != true || test["health"].(map[string]any)["serving"] != false ||
		fmt.Sprint(prod["privilegeBounds"]) != "map[grantableRoles:[ORDERS_RO_ROLE ORDERS_RW_ROLE LEDGER_RO_ROLE LEDGER_RW_ROLE]]" ||
		prod["config"] != nil || prod["uiSchemas"] != nil {
		t.Fatalf("list: %d %+v", list.code, prod)
	}
	got := v.do(t, viewer, "GET", "/v1/admin/platforms/oracle-prod", nil)
	ui, _ := got.body["uiSchemas"].(map[string]any)
	if got.code != 200 || ui["targetDefinition"] == nil || ui["pluginType"] != nil {
		t.Errorf("get: %d %+v", got.code, got.body)
	}
	if r := v.do(t, viewer, "GET", "/v1/admin/platforms/oracle-test-dynamic", nil); r.code != 503 {
		t.Errorf("unreachable plugin: %d", r.code)
	}
	if r := v.do(t, viewer, "GET", "/v1/admin/platforms/nope", nil); r.code != 404 {
		t.Errorf("unknown platform: %d", r.code)
	}
	if r := v.do(t, v.client(t, bgID), "GET", "/v1/admin/platforms", nil); r.code != 403 {
		t.Errorf("break-glass only: %d", r.code)
	}
}

// TestCatalogAPI: the catalog search with its filters and forSource, a
// target's card with its outcomes and flows, and the sources visible
// beyond one's own (§7.2.4).
func TestCatalogAPI(t *testing.T) {
	v := setup(t, config.AdminListener{})
	ctx := context.Background()
	olga, viewer := v.client(t, opID), v.client(t, viewerID)
	x := v.suffix
	for _, q := range []struct{ name, scope, td, vis string }{
		{"cloud-" + x, "cloud/fin-01/payments", "cloud.internal", "PUBLIC"},
		{"test-" + x, "dc/corp-test", "test.internal", "PUBLIC"},
		{"hidden-" + x, "dc/corp-test", "test.internal", "PRIVATE"},
	} {
		if _, err := v.owner.Exec(ctx, `insert into sources (id, name, scope, trust_domain, svid_regex, visibility, created_by, updated_by)
			values ($1, $2, $3, $4, $5, $6, 't', 't')`, uuid.NewV7(), q.name, q.scope, q.td, `^spiffe://`+q.td+`/x/`+q.name+`$`, q.vis); err != nil {
			t.Fatal(err)
		}
	}
	if r := v.do(t, v.client(t, appID), "POST", "/v1/admin/change-requests/"+v.request.ID.String()+"/approve",
		map[string]string{"payloadSha256": v.request.PayloadSHA256}); r.code != 200 {
		t.Fatalf("approve: %+v", r)
	}
	names := func(r response) string {
		var out []string
		for _, it := range r.body["items"].([]any) {
			m := it.(map[string]any)
			out = append(out, fmt.Sprint(m["name"], m["bound"]))
		}
		return strings.Join(out, ",")
	}
	for path, want := range map[string]string{
		"?q=" + x:                                  "tgt-" + x + "<nil>",
		"?q=" + x + "&platform=oracle-test":        "",
		"?q=" + x + "&platformType=oracle.v1":      "tgt-" + x + "<nil>",
		"?q=" + x + "&scope=cloud/*":               "",
		"?q=" + x + "&forSource=src-" + x:          "tgt-" + x + "true",
		"?q=" + x + "&forSource=cloud-" + x:        "tgt-" + x + "<nil>",
		"?q=" + x + "&forSource=test-" + x:         "", // no-test-to-prod
		"?q=" + x + "&state=DEPRECATED&pageSize=1": "tgt-" + x + "<nil>",
	} {
		if r := v.do(t, olga, "GET", "/v1/admin/catalog/targets"+path, nil); r.code != 200 || names(r) != want {
			t.Errorf("%s: %d %q, want %q", path, r.code, names(r), want)
		}
	}
	if r := v.do(t, olga, "GET", "/v1/admin/catalog/targets?forSource=hidden-"+x, nil); r.code != 404 {
		t.Errorf("forSource of a hidden source: %d", r.code)
	}

	card := v.do(t, olga, "GET", "/v1/admin/catalog/targets/tgt-"+x, nil)
	var outcome map[string]any
	for _, o := range card.body["outcomes"].([]any) {
		if o.(map[string]any)["source"] == "src-"+x {
			outcome = o.(map[string]any)
		}
	}
	if card.code != 200 || len(card.body["accessLevels"].([]any)) != 1 || outcome == nil || outcome["allowed"] != true ||
		fmt.Sprint(outcome["sides"]) != "[TARGET]" {
		t.Errorf("card: %d %+v", card.code, card.body)
	}
	// a flow outside oracle-prod's allowed_endpoints, left there by a tightened allowlist, is left out (§8.2 rule 19)
	if _, err := v.owner.Exec(ctx, `insert into target_network_flows (target_id, name, protocol, destination, ports, tls)
		select id, f.name, 'TCP', f.dest, f.ports::int4multirange, true from targets,
		(values ('ledger', 'ledger-db.prod.internal', '{[1522,1523)}'), ('legacy', 'legacy.prod.internal', '{[1521,1522)}')) as f(name, dest, ports)
		where targets.name = $1`, "tgt-"+x); err != nil {
		t.Fatal(err)
	}
	flows := v.do(t, viewer, "GET", "/v1/admin/catalog/targets/tgt-"+x+"/flows", nil)
	fs, _ := flows.body["networkFlows"].([]any)
	var declared []string
	for _, f := range fs {
		m := f.(map[string]any)
		declared = append(declared, fmt.Sprint(m["declaredBy"], "/", m["name"]))
		if strings.HasPrefix(m["declaredBy"].(string), "secret-store:") {
			t.Errorf("a secret store flow: %v", f)
		}
	}
	if got := strings.Join(declared, ","); !strings.Contains(got, "target:tgt-"+x+"/ledger") || strings.Contains(got, "legacy") {
		t.Errorf("target flows: %s", got)
	}
	if flows.code != 200 || len(fs) == 0 || fs[len(fs)-1].(map[string]any)["declaredBy"] != "ligo" {
		t.Errorf("flows: %+v", flows.body)
	}
	if r := v.do(t, olga, "GET", "/v1/admin/catalog/targets/nope-"+x, nil); r.code != 404 {
		t.Errorf("unknown target: %d", r.code)
	}

	beyond := v.do(t, olga, "GET", "/v1/admin/catalog/sources?pageSize=200", nil)
	got := names(beyond)
	if beyond.code != 200 || !strings.Contains(got, "cloud-"+x) || !strings.Contains(got, "test-"+x) ||
		strings.Contains(got, "hidden-"+x) || strings.Contains(got, "src-"+x) {
		t.Errorf("sources beyond olga's: %q", got)
	}
	if r := v.do(t, viewer, "GET", "/v1/admin/catalog/sources?pageSize=200", nil); strings.Contains(names(r), x) {
		t.Errorf("a viewer of * sees nothing beyond: %q", names(r))
	}
}

// TestGovernanceAPI: the policy in force with its SHA-256, and the dry run
// of a binding, a source and a target: scopes, name prefix, interconnection
// rule and sides with their basis, storing nothing.
func TestGovernanceAPI(t *testing.T) {
	v := setup(t, config.AdminListener{})
	ctx := context.Background()
	olga, viewer := v.client(t, opID), v.client(t, viewerID)
	x := v.suffix
	if _, err := v.owner.Exec(ctx, `insert into sources (id, name, scope, trust_domain, svid_regex, visibility, created_by, updated_by)
		values ($1, $2, 'dc/corp-test', 'test.internal', $3, 'PUBLIC', 't', 't')`, uuid.NewV7(), "test-"+x, `^spiffe://test\.internal/x/`+x+`$`); err != nil {
		t.Fatal(err)
	}

	g := v.do(t, viewer, "GET", "/v1/admin/governance", nil)
	if p, _ := g.body["policy"].(map[string]any); g.code != 200 || g.body["sha256"] != v.bs.Requests.Policy.SHA256() || p["interconnects"] == nil {
		t.Fatalf("governance: %d %v", g.code, g.body["sha256"])
	}

	var before int64
	if err := v.owner.QueryRow(ctx, "select coalesce(max(id), 0) from audit_log").Scan(&before); err != nil {
		t.Fatal(err)
	}
	sides := func(r response) string {
		var out []string
		for _, s := range r.body["sides"].([]any) {
			m := s.(map[string]any)
			out = append(out, fmt.Sprint(m["side"], ":", m["basis"]))
		}
		return strings.Join(out, ",")
	}
	cloud := map[string]string{"trustDomain": "cloud.internal", "svidRegex": `^spiffe://cloud\.internal/acct/fin-01/tenant/payments/sa/[a-z]+$`}
	for _, tc := range []struct {
		name               string
		body               map[string]any
		sides, rule, valid string
	}{
		{"same scope", map[string]any{"resourceType": "BINDING", "name": "eval-" + x, "source": "src-" + x, "target": "tgt-" + x, "accessLevel": "read"},
			"TARGET:HUMAN", "<nil>", "true"},
		{"inline cloud source", map[string]any{"resourceType": "BINDING", "name": "eval-" + x, "source": cloud, "target": "tgt-" + x, "accessLevel": "read"},
			"TARGET:HUMAN,SOURCE:HUMAN,PARTY:security:HUMAN", "map[action:allow rule:cloud-to-dc]", "false"},
		{"denied", map[string]any{"resourceType": "BINDING", "name": "eval-" + x, "source": "test-" + x, "target": "tgt-" + x, "accessLevel": "read"},
			"", "map[action:deny rule:no-test-to-prod]", "true"},
		{"source", map[string]any{"kind": "Source", "metadata": map[string]string{"name": "fin-01-payments-" + x}, "identity": cloud},
			"OWNER:HUMAN", "<nil>", "true"},
		{"target", map[string]any{"kind": "Target", "metadata": map[string]string{"name": "ledger-" + x, "platform": "oracle-prod", "scope": "dc/corp-prod/ledger"}},
			"OWNER:HUMAN,PLATFORM:HUMAN", "<nil>", "true"},
	} {
		r := v.do(t, olga, "POST", "/v1/admin/governance/evaluate", tc.body)
		if r.code != 200 || sides(r) != tc.sides || fmt.Sprint(r.body["interconnect"]) != tc.rule ||
			fmt.Sprint(r.body["namePrefix"].(map[string]any)["valid"]) != tc.valid {
			t.Errorf("%s: %d %+v", tc.name, r.code, r.body)
		}
	}
	v.bs.Requests.Policy.RequiredScopes = nil
	if r := v.do(t, olga, "POST", "/v1/admin/governance/evaluate", map[string]any{"resourceType": "BINDING", "name": "eval-" + x,
		"source": "src-" + x, "target": "tgt-" + x, "accessLevel": "read"}); sides(r) != "TARGET:AUTO" {
		t.Errorf("no approval required: %+v", r.body)
	}
	for body, code := range map[string]int{`{"resourceType":"BINDING","source":"src-` + x + `","target":"nope-` + x + `","accessLevel":"read"}`: 404,
		`{"resourceType":"BINDING","source":"src-` + x + `","target":"tgt-` + x + `","accessLevel":"admin"}`: 422,
		`{"kind":"Other"}`: 422, `[]`: 422} {
		req, _ := http.NewRequest("POST", v.srv.URL+"/v1/admin/governance/evaluate", strings.NewReader(body))
		resp, err := olga.Do(req)
		if err != nil || resp.StatusCode != code {
			t.Errorf("%s: %v %v, want %d", body, err, resp.StatusCode, code)
		}
		_ = resp.Body.Close()
	}
	var after, filed int64
	if err := v.owner.QueryRow(ctx, "select coalesce(max(id), 0), (select count(*) from change_requests where resource_name like 'eval-%') from audit_log").
		Scan(&after, &filed); err != nil || after != before || filed != 0 {
		t.Errorf("the dry run stored something: audit %d to %d, %d requests (%v)", before, after, filed, err)
	}
}
