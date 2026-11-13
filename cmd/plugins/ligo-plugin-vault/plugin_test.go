package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"google.golang.org/grpc/status"
)

const (
	id      = "01a1ac77-0d46-7515-bbf4-24f877af4b2b"
	subject = "spiffe://prod.lab/ns/a/sa/w"
	regex   = `^spiffe://prod\.lab/ns/a/sa/w$`
)

func errorCode(t *testing.T, err error) (string, bool) {
	t.Helper()
	st, ok := status.FromError(err)
	if !ok || len(st.Details()) != 1 {
		t.Fatalf("not a plugin error: %v", err)
	}
	d := st.Details()[0].(*pluginv1.PluginErrorDetail)
	return d.GetCode(), d.GetRetryable()
}

// TestParseConfig: VS-1, every field's rule names the field.
func TestParseConfig(t *testing.T) {
	good := map[string]any{"address": "https://v.lab:8200", "allowed_endpoints": []string{"v.lab:8200"}, "auth_mount": "jwt/spiffe", "role": "r", "workload_jwt_audience": "a"}
	config := func(field string, value any) []byte {
		m := map[string]any{}
		for k, v := range good {
			m[k] = v
		}
		if value == nil {
			delete(m, field)
		} else {
			m[field] = value
		}
		data, _ := json.Marshal(m)
		return data
	}
	c, err := parseConfig(config("x", nil))
	if err != nil || c.KVMount != "kv" || c.DatabaseMount != "database" || c.port != 8200 || c.host != "v.lab" {
		t.Fatalf("%+v %v", c, err)
	}
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"unknown":     {config("nope", 1), "nope"},
		"http":        {config("address", "http://v.lab:8200"), "address"},
		"path":        {config("address", "https://v.lab:8200/x"), "address"},
		"endpoint":    {config("allowed_endpoints", []string{"other:1"}), "allowed_endpoints"},
		"auth mount":  {config("auth_mount", "../x"), "auth_mount"},
		"kv mount":    {config("kv_mount", "a b"), "kv_mount"},
		"no role":     {config("role", nil), "role"},
		"no audience": {config("workload_jwt_audience", nil), "workload_jwt_audience"},
		"ca_pem":      {config("ca_pem", "not a certificate"), "ca_pem"},
		"ca_file":     {config("ca_file", "/etc/shadow"), "ca_file"}, // no file paths (ligo-instances T-22d)
	} {
		if _, err := parseConfig(tc.data); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	if c, err := parseConfig(config("allowed_endpoints", []string{"v.lab:8200"})); err != nil || c == nil {
		t.Error(err)
	}
}

// TestEndpoints: the Vault is all the instance connects to (ligo-instances
// §6 rule 5); a bad config is INVALID_CONFIG before any agent is reached.
func TestEndpoints(t *testing.T) {
	c, err := parseConfig([]byte(`{"address":"https://v.lab","allowed_endpoints":["v.lab:443"],"auth_mount":"m","role":"r","workload_jwt_audience":"a"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.endpoints(); len(got) != 1 || got[0] != "v.lab:443" {
		t.Errorf("got %v", got)
	}
	_, err = (&plugin{}).ValidateInstance(context.Background(), &pluginv1.ValidateInstanceRequest{SpiffeWorkloadSocket: "unix:///nonexistent",
		Instance: &pluginv1.InstanceDescriptor{Name: "v", ConfigJson: `{}`}})
	if code, _ := errorCode(t, err); code != "INVALID_CONFIG" {
		t.Errorf("got %s", code)
	}
}

// fakeJWT is the instance's JWT-SVID.
type fakeJWT struct{ err error }

func (f fakeJWT) FetchJWT(context.Context) (string, error) { return "the-jwt", f.err }

// vault records the requests it is sent, and answers status to the paths in
// fail.
type vault struct {
	*httptest.Server
	requests []string
	bodies   map[string]map[string]any
	headers  http.Header
	fail     map[string]int
}

func newVault(t *testing.T) *vault {
	t.Helper()
	v := &vault{bodies: map[string]map[string]any{}, fail: map[string]int{}}
	v.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/")
		v.requests = append(v.requests, r.Method+" "+path)
		v.headers = r.Header
		data, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(data, &body)
		v.bodies[path] = body
		if status, ok := v.fail[path]; ok {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"errors":["secret text from the server"]}`))
			return
		}
		if strings.HasSuffix(path, "/login") {
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]string{"client_token": "the-token"}})
		}
	}))
	t.Cleanup(v.Close)
	return v
}

func (v *vault) plugin(c config) *plugin {
	c.Address, c.host, c.port = v.URL, "v.lab", 8200
	if c.AuthMount == "" {
		c.AuthMount = "jwt-spiffe"
	}
	if c.KVMount == "" {
		c.KVMount = "kv"
	}
	if c.DatabaseMount == "" {
		c.DatabaseMount = "database"
	}
	c.Role, c.WorkloadJWTAudience = "plugin-role", "the-audience"
	return &plugin{instances: map[string]*instance{"v": {config: c, jwt: fakeJWT{}, client: v.Client()}}}
}

func staticRequest(payload *pluginv1.SecretProvisioningPayload) *pluginv1.EnsureSecretStoreRequest {
	return &pluginv1.EnsureSecretStoreRequest{Instance: "v", SecretStorageStrategy: static, SecretPayload: payload,
		Binding: &pluginv1.BindingContext{BindingId: id, SourceSvidRegex: regex}}
}

func secret() *pluginv1.SecretProvisioningPayload {
	return &pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL,
		Payload: &pluginv1.SecretProvisioningPayload_StaticSecret{StaticSecret: &pluginv1.StaticSecret{Username: "u", Password: "the-password"}}}
}

// TestStatic: VS-3 and VS-7, the objects of §5 with custom mounts and a
// namespace, and the token revoked.
func TestStatic(t *testing.T) {
	v := newVault(t)
	p := v.plugin(config{KVMount: "secrets/ligo", AuthMount: "jwt", Namespace: "ns1"})
	r, err := p.EnsureSecretStore(context.Background(), staticRequest(secret()))
	if err != nil {
		t.Fatal(err)
	}
	path := "secrets/ligo/data/bindings/" + id
	for _, want := range []string{"POST auth/jwt/login", "POST secrets/ligo/metadata/bindings/" + id, "POST " + path,
		"PUT sys/policies/acl/binding-" + id, "POST auth/jwt/role/binding-" + id, "POST auth/token/revoke-self"} {
		if !slices.Contains(v.requests, want) {
			t.Errorf("no %s in %v", want, v.requests)
		}
	}
	if v.requests[len(v.requests)-1] != "POST auth/token/revoke-self" {
		t.Errorf("the token is not revoked last: %v", v.requests)
	}
	if v.headers.Get("X-Vault-Namespace") != "ns1" {
		t.Error("no namespace")
	}
	if md := v.bodies["secrets/ligo/metadata/bindings/"+id]; md["max_versions"] != 1.0 {
		t.Errorf("metadata %v", md)
	}
	role := v.bodies["auth/jwt/role/binding-"+id]
	if role["bound_subject"] != subject || fmt.Sprint(role["bound_audiences"]) != "[the-audience]" || role["token_policies"] != "binding-"+id {
		t.Errorf("role %v", role)
	}
	if acl := v.bodies["sys/policies/acl/binding-"+id]; !strings.Contains(fmt.Sprint(acl["policy"]), `"`+path+`"`) {
		t.Errorf("policy %v", acl)
	}
	var auth map[string]string
	if err := json.Unmarshal(r.GetFinalizedClientAuthJson(), &auth); err != nil || auth["secretPath"] != path || auth["role"] != "binding-"+id || auth["authMount"] != "jwt" || auth["audience"] != "the-audience" {
		t.Errorf("auth %v (%v)", auth, err)
	}
	if e := r.GetDeclaredEndpoints()[0]; e.GetHost() != "v.lab" || e.GetPort() != 8200 {
		t.Errorf("endpoint %v", e)
	}
}

// TestUnchanged: VS-4, the secret is not written; the rest converges.
func TestUnchanged(t *testing.T) {
	v := newVault(t)
	p := v.plugin(config{})
	_, err := p.EnsureSecretStore(context.Background(), staticRequest(&pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR, SecretUnchanged: true}))
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(v.requests, "POST kv/data/bindings/"+id) {
		t.Error("the secret was written")
	}
	if !slices.Contains(v.requests, "POST auth/jwt-spiffe/role/binding-"+id) {
		t.Errorf("no role: %v", v.requests)
	}
}

// TestDynamic: VS-5, a role, its policy, and the workload's JWT role.
func TestDynamic(t *testing.T) {
	v := newVault(t)
	p := v.plugin(config{DBConnection: "conn"})
	req := &pluginv1.EnsureSecretStoreRequest{Instance: "v", SecretStorageStrategy: dynamic, Binding: &pluginv1.BindingContext{BindingId: id, SourceSvidRegex: regex},
		SecretPayload: &pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC,
			Payload: &pluginv1.SecretProvisioningPayload_DelegatedRole{DelegatedRole: &pluginv1.DelegatedRoleSpec{RoleType: "database-dynamic", CreationStatements: []string{"x"}}}}}
	r, err := p.EnsureSecretStore(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if body := v.bodies["database/roles/binding-"+id]; body["db_name"] != "conn" {
		t.Errorf("role %v", body)
	}
	if role := v.bodies["auth/jwt-spiffe/role/binding-"+id]; role["bound_subject"] != subject {
		t.Errorf("no JWT role for the workload: %v", role)
	}
	var auth map[string]string
	if err := json.Unmarshal(r.GetFinalizedClientAuthJson(), &auth); err != nil || auth["credsPath"] != "database/creds/binding-"+id || auth["role"] != "binding-"+id || auth["audience"] != "the-audience" {
		t.Errorf("auth %v", auth)
	}
	_, err = v.plugin(config{}).EnsureSecretStore(context.Background(), req)
	if code, retry := errorCode(t, err); code != "DB_CONNECTION_NOT_CONFIGURED" || retry {
		t.Errorf("%s %v", code, retry)
	}
}

// TestRefused: VS-2, nothing reaches Vault.
func TestRefused(t *testing.T) {
	v := newVault(t)
	p := v.plugin(config{})
	delegated := &pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC}
	for want, r := range map[string]*pluginv1.EnsureSecretStoreRequest{
		"INVALID_BINDING":            {Instance: "v", SecretStorageStrategy: static, Binding: &pluginv1.BindingContext{BindingId: "../x", SourceSvidRegex: regex}},
		"SOURCE_NOT_EXACT":           {Instance: "v", SecretStorageStrategy: static, Binding: &pluginv1.BindingContext{BindingId: id, SourceSvidRegex: `^spiffe://prod\.lab/ns/a/sa/w-[0-9]+$`}},
		"UNKNOWN_STRATEGY":           {Instance: "v", SecretStorageStrategy: "nope", Binding: &pluginv1.BindingContext{BindingId: id, SourceSvidRegex: regex}},
		"INCOMPATIBLE_IDENTITY_MODE": {Instance: "v", SecretStorageStrategy: dynamic, Binding: &pluginv1.BindingContext{BindingId: id, SourceSvidRegex: regex}, SecretPayload: delegated},
	} {
		_, err := p.EnsureSecretStore(context.Background(), r)
		if code, retry := errorCode(t, err); code != want || retry {
			t.Errorf("%s: %s %v", want, code, retry)
		}
	}
	_, err := p.EnsureSecretStore(context.Background(), staticRequest(&pluginv1.SecretProvisioningPayload{Mode: pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL}))
	if code, _ := errorCode(t, err); code != "INCOMPATIBLE_IDENTITY_MODE" {
		t.Errorf("no secret: %s", code)
	}
	if len(v.requests) != 0 {
		t.Errorf("reached Vault: %v", v.requests)
	}
}

// TestStatuses: VS-6, each status's code and retryability, with no body in it;
// the token is revoked whatever the outcome.
func TestStatuses(t *testing.T) {
	for status, want := range map[int]struct {
		code  string
		retry bool
	}{
		403: {"VAULT_ACCESS_DENIED", false},
		400: {"VAULT_REJECTED", false},
		404: {"VAULT_REJECTED", false},
		429: {"VAULT_UNAVAILABLE", true},
		503: {"VAULT_UNAVAILABLE", true},
	} {
		v := newVault(t)
		v.fail["kv/data/bindings/"+id] = status
		_, err := v.plugin(config{}).EnsureSecretStore(context.Background(), staticRequest(secret()))
		code, retry := errorCode(t, err)
		if code != want.code || retry != want.retry || strings.Contains(err.Error(), "secret text") {
			t.Errorf("%d: %s %v: %v", status, code, retry, err)
		}
		if !slices.Contains(v.requests, "POST auth/token/revoke-self") {
			t.Errorf("%d: the token is not revoked", status)
		}
	}
	v := newVault(t)
	v.fail["auth/jwt-spiffe/login"] = 403
	_, err := v.plugin(config{}).EnsureSecretStore(context.Background(), staticRequest(secret()))
	if code, _ := errorCode(t, err); code != "VAULT_ACCESS_DENIED" {
		t.Errorf("login: %s", code)
	}
	p := newVault(t).plugin(config{})
	p.instances["v"].jwt = fakeJWT{err: errors.New("no agent")}
	_, err = p.EnsureSecretStore(context.Background(), staticRequest(secret()))
	if code, retry := errorCode(t, err); code != "SVID_UNAVAILABLE" || !retry {
		t.Errorf("svid: %s %v", code, retry)
	}
	gone := newVault(t)
	q := gone.plugin(config{})
	gone.Close()
	_, err = q.EnsureSecretStore(context.Background(), staticRequest(secret()))
	if code, retry := errorCode(t, err); code != "VAULT_UNAVAILABLE" || !retry {
		t.Errorf("no answer: %s %v", code, retry)
	}
}

// TestCleanup: VS-9, a static-only instance does not touch the engine, what is
// absent is success.
func TestCleanup(t *testing.T) {
	v := newVault(t)
	req := &pluginv1.CleanupSecretStoreRequest{Instance: "v", Binding: &pluginv1.BindingContext{BindingId: id}}
	v.fail["kv/metadata/bindings/"+id] = 404
	if _, err := v.plugin(config{}).CleanupSecretStore(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	for _, r := range v.requests {
		if strings.Contains(r, "database") {
			t.Errorf("touched the engine: %s", r)
		}
	}
	v = newVault(t)
	if _, err := v.plugin(config{DBConnection: "c"}).CleanupSecretStore(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(v.requests, "PUT sys/leases/revoke-prefix/database/creds/binding-"+id) {
		t.Errorf("no lease revocation: %v", v.requests)
	}
	v = newVault(t)
	v.fail["sys/policies/acl/binding-"+id] = 403
	_, err := v.plugin(config{}).CleanupSecretStore(context.Background(), req)
	if code, _ := errorCode(t, err); code != "VAULT_ACCESS_DENIED" {
		t.Errorf("%s", code)
	}
}

// TestHealth: a login; not serving with a fixed message otherwise.
func TestHealth(t *testing.T) {
	v := newVault(t)
	p := v.plugin(config{})
	if h, err := p.Health(context.Background(), &pluginv1.HealthRequest{Instance: "v"}); err != nil || !h.GetServing() {
		t.Errorf("%v %v", h, err)
	}
	v.fail["auth/jwt-spiffe/login"] = 503
	h, err := p.Health(context.Background(), &pluginv1.HealthRequest{Instance: "v"})
	if err != nil || h.GetServing() || h.GetPublicMessage() == "" {
		t.Errorf("%v %v", h, err)
	}
	if _, err := p.Health(context.Background(), &pluginv1.HealthRequest{Instance: "nope"}); err == nil {
		t.Error("an unknown instance")
	}
	d, err := p.Describe(context.Background(), &pluginv1.DescribeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.GetSecretStore().GetSecretStorageStrategies() {
		if s.GetSubjectMatch() != pluginv1.SubjectMatch_SUBJECT_MATCH_EXACT {
			t.Errorf("%s does not declare exact subjects", s.GetName())
		}
	}
}
