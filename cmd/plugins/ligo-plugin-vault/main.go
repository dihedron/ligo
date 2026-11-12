// Command ligo-plugin-vault is the vault.v1 secret store: a binding's
// credential in Vault or OpenBao, readable by that binding's workload only
// (.specs/ligo-vault-plugin.md).
package main

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/command/version"
	"github.com/dihedron/ligo/pkg/metadata"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"google.golang.org/grpc/codes"
)

const (
	typ          = "vault.v1"
	maxResponse  = 1 << 20
	static       = "vault-static"
	dynamic      = "vault-dynamic"
	revokeWithin = 5 * time.Second
)

var (
	// uuidRE is a binding ID, the only request value that reaches a path.
	uuidRE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	mountRE = regexp.MustCompile(`^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$`)
)

//go:embed schemas/config.json
var configSchema string

//go:embed schemas/output.json
var outputSchema string

// config is an instance's checked config_json.
type config struct {
	Address             string   `json:"address"`
	AllowedEndpoints    []string `json:"allowed_endpoints"`
	AuthMount           string   `json:"auth_mount"`
	Role                string   `json:"role"`
	WorkloadJWTAudience string   `json:"workload_jwt_audience"`
	KVMount             string   `json:"kv_mount"`
	Namespace           string   `json:"namespace"`
	DatabaseMount       string   `json:"database_mount"`
	DBConnection        string   `json:"db_connection"`
	CAPEM               string   `json:"ca_pem"`

	host  string
	port  uint32
	roots *x509.CertPool // nil: the system roots
}

// parseConfig checks an instance's configuration (§3); errors name the field.
func parseConfig(data []byte) (*config, error) {
	c := config{KVMount: "kv", DatabaseMount: "database"}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	u, err := url.Parse(c.Address)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Path != "" || u.User != nil || u.RawQuery != "" {
		return nil, errors.New("address must be https://host[:port]")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, errors.New("address must be https://host[:port]")
	}
	c.host, c.port = u.Hostname(), uint32(n)
	if !slices.Contains(c.AllowedEndpoints, net.JoinHostPort(c.host, port)) {
		return nil, fmt.Errorf("allowed_endpoints must contain %s", net.JoinHostPort(c.host, port))
	}
	for field, value := range map[string]string{"auth_mount": c.AuthMount, "kv_mount": c.KVMount, "database_mount": c.DatabaseMount} {
		if !mountRE.MatchString(value) {
			return nil, fmt.Errorf("%s is not a valid mount", field)
		}
	}
	if c.Role == "" {
		return nil, errors.New("role is required")
	}
	if c.WorkloadJWTAudience == "" {
		return nil, errors.New("workload_jwt_audience is required")
	}
	c.roots, err = pluginsdk.ParseRoots(c.CAPEM)
	return &c, err
}

// endpoints are what the instance connects to: its Vault (ligo-instances
// §6 rule 5).
func (c *config) endpoints() []string {
	return []string{net.JoinHostPort(c.host, strconv.FormatUint(uint64(c.port), 10))}
}

type instance struct {
	config
	jwt    pluginsdk.JWTSource
	client *http.Client
}

type plugin struct {
	pluginv1.UnimplementedPluginControlServer
	pluginv1.UnimplementedSecretStorePluginServer
	mu        sync.Mutex
	instances map[string]*instance
}

func (*plugin) Describe(context.Context, *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	exact := pluginv1.SubjectMatch_SUBJECT_MATCH_EXACT
	return &pluginv1.DescribeResponse{PluginType: typ, Kind: pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, PluginProtocolVersion: 2,
		PluginVersion: metadata.Version, InstanceConfigSchemaJson: configSchema,
		Capabilities: &pluginv1.DescribeResponse_SecretStore{SecretStore: &pluginv1.SecretStoreCapabilities{
			ClientOutputSchemaJson: outputSchema,
			SecretStorageStrategies: []*pluginv1.SecretStorageStrategy{
				{Name: static, SubjectMatch: exact, IdentityModes: []pluginv1.IdentityMode{pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR}},
				{Name: dynamic, SubjectMatch: exact, IdentityModes: []pluginv1.IdentityMode{pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC}},
			},
		}},
	}, nil
}

// ConfigureInstances checks every instance's configuration, then selects its
// SVID (§5.4).
func (p *plugin) ConfigureInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (*pluginv1.ConfigureInstancesResponse, error) {
	instances := map[string]*instance{}
	for _, in := range r.GetInstances() {
		c, err := parseConfig([]byte(in.GetConfigJson()))
		if err != nil {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": "+err.Error(), false)
		}
		instances[in.GetName()] = &instance{config: *c, client: pluginsdk.HTTPClient(c.roots)}
	}
	selectors, out, err := pluginsdk.SelectInstances(ctx, r)
	if err != nil {
		return nil, err
	}
	for name, in := range instances {
		in.jwt = selectors[name]
	}
	p.mu.Lock()
	p.instances = instances
	p.mu.Unlock()
	return out, nil
}

// ValidateInstance checks one instance without serving it (ligo-instances §7.1).
func (p *plugin) ValidateInstance(ctx context.Context, r *pluginv1.ValidateInstanceRequest) (*pluginv1.ValidateInstanceResponse, error) {
	return pluginsdk.ValidateInstance(ctx, r, func(in *pluginv1.InstanceDescriptor) ([]string, error) {
		c, err := parseConfig([]byte(in.GetConfigJson()))
		if err != nil {
			return nil, err
		}
		return c.endpoints(), nil
	})
}

func (p *plugin) instance(name string) (*instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if in := p.instances[name]; in != nil {
		return in, nil
	}
	return nil, pluginsdk.Error(codes.NotFound, "UNKNOWN_INSTANCE", "no instance "+name, false)
}

// statusError maps a status to §8's codes, with fixed messages.
func statusError(status int) error {
	switch {
	case status == http.StatusForbidden:
		return pluginsdk.Error(codes.PermissionDenied, "VAULT_ACCESS_DENIED", "the plugin's role may not do this", false)
	case status == http.StatusTooManyRequests, status >= 500:
		return unavailable()
	}
	return pluginsdk.Error(codes.FailedPrecondition, "VAULT_REJECTED", "Vault refused a request", false)
}

func unavailable() error {
	return pluginsdk.Error(codes.Unavailable, "VAULT_UNAVAILABLE", "Vault cannot be reached", true)
}

// call sends one request; a 404 is not an error when absentOK is set. Only the
// method, the path and the status are logged, never a body (§8).
func (in *instance) call(ctx context.Context, method, path, token string, body any, absentOK bool, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, in.Address+"/v1/"+path, r)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if in.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", in.Namespace)
	}
	resp, err := in.client.Do(req)
	if err != nil {
		slog.Warn("vault: no answer", "method", method, "path", path)
		return unavailable()
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return unavailable()
	}
	switch {
	case resp.StatusCode == http.StatusNotFound && absentOK:
		return nil
	case resp.StatusCode >= 300:
		slog.Warn("vault: refused", "method", method, "path", path, "status", resp.StatusCode)
		return statusError(resp.StatusCode)
	case out != nil:
		if err := json.Unmarshal(data, out); err != nil {
			return unavailable()
		}
	}
	return nil
}

// login is a token for this call, from the instance's JWT-SVID; done revokes
// it, whatever the call's outcome and its context's state (§6).
func (in *instance) login(ctx context.Context) (token string, done func(), err error) {
	jwt, err := in.jwt.FetchJWT(ctx)
	if err != nil {
		return "", nil, pluginsdk.Error(codes.Unavailable, "SVID_UNAVAILABLE", "cannot fetch the JWT-SVID", true)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := in.call(ctx, http.MethodPost, "auth/"+in.AuthMount+"/login", "", map[string]string{"role": in.Role, "jwt": jwt}, false, &out); err != nil {
		return "", nil, err
	}
	return out.Auth.ClientToken, func() {
		revoke, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeWithin)
		defer cancel()
		_ = in.call(revoke, http.MethodPost, "auth/token/revoke-self", out.Auth.ClientToken, nil, false, nil) // otherwise its TTL ends it
	}, nil
}

// Health logs in with the instance's JWT-SVID.
func (p *plugin) Health(ctx context.Context, r *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	_, done, err := in.login(ctx)
	if err != nil {
		return &pluginv1.HealthResponse{PublicMessage: "Vault cannot be reached with the plugin's identity"}, nil //nolint:nilerr // what Health answers
	}
	done()
	return &pluginv1.HealthResponse{Serving: true}, nil
}

func bindingID(b *pluginv1.BindingContext) (string, error) {
	if id := b.GetBindingId(); uuidRE.MatchString(id) {
		return id, nil
	}
	return "", pluginsdk.Error(codes.InvalidArgument, "INVALID_BINDING", "the binding id is not a UUID", false)
}

func incompatible() error {
	return pluginsdk.Error(codes.FailedPrecondition, "INCOMPATIBLE_IDENTITY_MODE", "the payload does not fit the secret storage strategy", false)
}

// EnsureSecretStore keeps the binding's secret or database role, the policy
// that reads it, and the JWT role that gives the policy to its workload (§5).
func (p *plugin) EnsureSecretStore(ctx context.Context, r *pluginv1.EnsureSecretStoreRequest) (*pluginv1.EnsureSecretStoreResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	id, err := bindingID(r.GetBinding())
	if err != nil {
		return nil, err
	}
	subject, ok := pluginsdk.LiteralSPIFFEID(r.GetBinding().GetSourceSvidRegex())
	if !ok {
		return nil, pluginsdk.Error(codes.FailedPrecondition, "SOURCE_NOT_EXACT", "this store binds one exact SPIFFE ID, and the source's regex matches more", false)
	}
	payload := r.GetSecretPayload()
	strategy := r.GetSecretStorageStrategy()
	switch strategy {
	case static:
		mode := payload.GetMode()
		if mode != pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL && mode != pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR ||
			payload.GetDelegatedRole() != nil || payload.GetStaticSecret() == nil && !payload.GetSecretUnchanged() {
			return nil, incompatible()
		}
	case dynamic:
		d := payload.GetDelegatedRole()
		if payload.GetMode() != pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC || d == nil || d.GetRoleType() != "database-dynamic" {
			return nil, incompatible()
		}
		if in.DBConnection == "" {
			return nil, pluginsdk.Error(codes.FailedPrecondition, "DB_CONNECTION_NOT_CONFIGURED", "vault-dynamic needs db_connection", false)
		}
	default:
		return nil, pluginsdk.Error(codes.FailedPrecondition, "UNKNOWN_STRATEGY", "vault-static or vault-dynamic only", false)
	}
	token, done, err := in.login(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	policy := "binding-" + id
	auth := map[string]string{"address": in.Address, "policy": policy, "authMount": in.AuthMount, "role": policy}
	var readPath string
	if strategy == static {
		readPath = in.KVMount + "/data/bindings/" + id
		auth["secretPath"] = readPath
		err = in.ensureStatic(ctx, token, id, readPath, payload)
	} else {
		readPath = in.DatabaseMount + "/creds/binding-" + id
		auth["credsPath"] = readPath
		err = in.ensureDynamic(ctx, token, id, payload.GetDelegatedRole())
	}
	if err != nil {
		return nil, err
	}
	hcl := fmt.Sprintf("# ligo:binding_id=%s\npath %q {\n  capabilities = [\"read\"]\n}\n", id, readPath)
	if err := in.call(ctx, http.MethodPut, "sys/policies/acl/"+policy, token, map[string]string{"policy": hcl}, false, nil); err != nil {
		return nil, err
	}
	// token_policies is a string: allowed_parameters' globs (binding-*) refuse a JSON array
	if err := in.call(ctx, http.MethodPost, "auth/"+in.AuthMount+"/role/"+policy, token, map[string]any{"role_type": "jwt", "user_claim": "sub",
		"bound_subject": subject, "bound_audiences": []string{in.WorkloadJWTAudience}, "token_policies": policy, "token_ttl": "10m", "token_max_ttl": "1h"},
		false, nil); err != nil {
		return nil, err
	}
	data, _ := json.Marshal(auth)
	return &pluginv1.EnsureSecretStoreResponse{FinalizedClientAuthJson: data,
		DeclaredEndpoints: []*pluginv1.Endpoint{{Host: in.host, Port: in.port, Scheme: "https"}}}, nil
}

// ensureStatic writes the secret, unless it is unchanged, and keeps one
// version of it, so that an old password does not linger.
func (in *instance) ensureStatic(ctx context.Context, token, id, path string, payload *pluginv1.SecretProvisioningPayload) error {
	if err := in.call(ctx, http.MethodPost, in.KVMount+"/metadata/bindings/"+id, token, map[string]any{
		"max_versions": 1, "custom_metadata": map[string]string{"ligo_binding_id": id}}, false, nil); err != nil {
		return err
	}
	s := payload.GetStaticSecret()
	if s == nil || payload.GetSecretUnchanged() {
		return nil
	}
	return in.call(ctx, http.MethodPost, path, token, map[string]any{"data": map[string]string{
		"username": s.GetUsername(), "password": s.GetPassword()}}, false, nil)
}

func (in *instance) ensureDynamic(ctx context.Context, token, id string, d *pluginv1.DelegatedRoleSpec) error {
	return in.call(ctx, http.MethodPost, in.DatabaseMount+"/roles/binding-"+id, token, map[string]any{
		"db_name": in.DBConnection, "creation_statements": d.GetCreationStatements(), "revocation_statements": d.GetRevocationStatements(),
		"rollback_statements": d.GetRollbackStatements(), "default_ttl": d.GetDefaultTtlSeconds(), "max_ttl": d.GetMaxTtlSeconds(),
	}, false, nil)
}

// CleanupSecretStore revokes the binding's leases and deletes its objects;
// what is absent is success (§6).
func (p *plugin) CleanupSecretStore(ctx context.Context, r *pluginv1.CleanupSecretStoreRequest) (*pluginv1.CleanupSecretStoreResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	id, err := bindingID(r.GetBinding())
	if err != nil {
		return nil, err
	}
	token, done, err := in.login(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	var steps []struct{ method, path string }
	if in.DBConnection != "" { // a static-only deployment gives the plugin no rights on the engine
		steps = append(steps, struct{ method, path string }{http.MethodPut, "sys/leases/revoke-prefix/" + in.DatabaseMount + "/creds/binding-" + id},
			struct{ method, path string }{http.MethodDelete, in.DatabaseMount + "/roles/binding-" + id})
	}
	steps = append(steps, struct{ method, path string }{http.MethodDelete, in.KVMount + "/metadata/bindings/" + id},
		struct{ method, path string }{http.MethodDelete, "sys/policies/acl/binding-" + id},
		struct{ method, path string }{http.MethodDelete, "auth/" + in.AuthMount + "/role/binding-" + id})
	for _, s := range steps {
		if err := in.call(ctx, s.method, s.path, token, nil, true, nil); err != nil {
			return nil, err
		}
	}
	return &pluginv1.CleanupSecretStoreResponse{}, nil
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		os.Exit(version.Run(os.Args[2:]))
	}
	if len(os.Args) == 3 && os.Args[1] == "-svids" {
		os.Exit(pluginsdk.PrintSVIDs(os.Args[2]))
	}
	p := &plugin{}
	pluginsdk.Serve(pluginsdk.Plugins{Control: p, Store: p})
}
