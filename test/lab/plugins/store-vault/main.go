// Command store-vault is a lab plugin (test tooling, never shipped, not
// hardened): a stand-in for the vault.v1 secret store, so that phase 6 runs
// its workflows against a real OpenBao. It logs in with its own JWT-SVID
// and keeps, per binding, a secret or a database role and the policy that
// reads it (.specs/ligo-test-environment.md, "Plugins on ligo1").
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"sync"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/dihedron/ligo/test/lab/plugins/labkit"
	"google.golang.org/grpc/codes"
)

const typ = "vault.v1"

// uuidRE is a binding ID, the only value that reaches a Vault path.
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// config is an instance's config_json.
type config struct {
	labkit.Common
	Address      string `json:"address"`
	AuthMount    string `json:"auth_mount"`
	Role         string `json:"role"`
	DBConnection string `json:"db_connection"` // the database engine's connection, for vault-dynamic
}

type instance struct {
	*labkit.Instance
	config
	client *http.Client
}

type plugin struct {
	pluginv1.UnimplementedPluginControlServer
	pluginv1.UnimplementedSecretStorePluginServer
	mu        sync.Mutex
	instances map[string]*instance
}

const configSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object",
"required":["address","auth_mount","role","db_connection","ca_file"],
"properties":{"address":{"type":"string"},"auth_mount":{"type":"string"},"role":{"type":"string"},
"db_connection":{"type":"string"},"ca_file":{"type":"string"}}}`

const outputSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
"required":["address","policy"],
"properties":{"address":{"type":"string","x-ligo-endpoint":true},"secretPath":{"type":"string"},"credsPath":{"type":"string"},"policy":{"type":"string"}}}`

func (*plugin) Describe(context.Context, *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	return &pluginv1.DescribeResponse{PluginType: typ, Kind: pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, PluginProtocolVersion: 1,
		PluginVersion: "lab", InstanceConfigSchemaJson: configSchema,
		Capabilities: &pluginv1.DescribeResponse_SecretStore{SecretStore: &pluginv1.SecretStoreCapabilities{
			ClientOutputSchemaJson: outputSchema,
			SecretStorageStrategies: []*pluginv1.SecretStorageStrategy{
				{Name: "vault-static", IdentityModes: []pluginv1.IdentityMode{pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL, pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR}},
				{Name: "vault-dynamic", IdentityModes: []pluginv1.IdentityMode{pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC}},
			},
		}},
	}, nil
}

func (p *plugin) ConfigureInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (*pluginv1.ConfigureInstancesResponse, error) {
	kits, out, err := labkit.Configure(ctx, r)
	if err != nil {
		return nil, err
	}
	instances := map[string]*instance{}
	for _, in := range r.GetInstances() {
		inst := &instance{Instance: kits[in.GetName()]}
		if err := json.Unmarshal([]byte(in.GetConfigJson()), &inst.config); err != nil || inst.Address == "" {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": config", false)
		}
		inst.client = labkit.HTTPClient(inst.Roots)
		instances[in.GetName()] = inst
	}
	p.mu.Lock()
	p.instances = instances
	p.mu.Unlock()
	return out, nil
}

func (p *plugin) Health(context.Context, *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	return &pluginv1.HealthResponse{Serving: true}, nil
}

func (p *plugin) instance(name string) (*instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if in := p.instances[name]; in != nil {
		return in, nil
	}
	return nil, pluginsdk.Error(codes.NotFound, "UNKNOWN_INSTANCE", "no instance "+name, false)
}

func unavailable() error {
	return pluginsdk.Error(codes.Unavailable, "VAULT_UNAVAILABLE", "OpenBao refused or failed a request", true)
}

// call sends one request to OpenBao; a 404 is not an error when absent is
// set. The response body goes to stderr only on failure, for the host's
// redacting logger.
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
	resp, err := in.client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store-vault:", method, path, err)
		return unavailable()
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	switch {
	case resp.StatusCode == http.StatusNotFound && absentOK:
		return nil
	case resp.StatusCode >= 300:
		fmt.Fprintln(os.Stderr, "store-vault:", method, path, resp.StatusCode)
		return unavailable()
	case out != nil:
		return json.Unmarshal(data, out)
	}
	return nil
}

// login is a token for this RPC, from the instance's JWT-SVID.
func (in *instance) login(ctx context.Context) (string, error) {
	jwt, err := in.JWT.FetchJWT(ctx)
	if err != nil {
		return "", pluginsdk.Error(codes.Unavailable, "SVID_UNAVAILABLE", "cannot fetch the JWT-SVID", true)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := in.call(ctx, http.MethodPost, "auth/"+in.AuthMount+"/login", "", map[string]string{"role": in.Role, "jwt": jwt}, false, &out); err != nil {
		return "", err
	}
	return out.Auth.ClientToken, nil
}

func bindingID(b *pluginv1.BindingContext) (string, error) {
	if id := b.GetBindingId(); uuidRE.MatchString(id) {
		return id, nil
	}
	return "", pluginsdk.Error(codes.InvalidArgument, "INVALID_BINDING", "binding id", false)
}

func incompatible() error {
	return pluginsdk.Error(codes.FailedPrecondition, "INCOMPATIBLE_IDENTITY_MODE", "the payload does not fit the secret storage strategy", false)
}

// EnsureSecretStore keeps the binding's secret (vault-static) or database
// role (vault-dynamic), and the policy that reads it (§5.6, §5.8 rule 1).
func (p *plugin) EnsureSecretStore(ctx context.Context, r *pluginv1.EnsureSecretStoreRequest) (*pluginv1.EnsureSecretStoreResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	id, err := bindingID(r.GetBinding())
	if err != nil {
		return nil, err
	}
	payload := r.GetSecretPayload()
	policy := "binding-" + id
	auth := map[string]string{"address": in.Address, "policy": policy}
	var readPath string
	token, err := in.login(ctx)
	if err != nil {
		return nil, err
	}
	switch r.GetSecretStorageStrategy() {
	case "vault-static":
		mode := payload.GetMode()
		if mode != pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL && mode != pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR ||
			payload.GetDelegatedRole() != nil || payload.GetStaticSecret() == nil && !payload.GetSecretUnchanged() {
			return nil, incompatible()
		}
		readPath = "kv/data/bindings/" + id
		if s := payload.GetStaticSecret(); s != nil && !payload.GetSecretUnchanged() {
			if err := in.call(ctx, http.MethodPost, readPath, token, map[string]any{"data": map[string]string{
				"username": s.GetUsername(), "password": s.GetPassword()}}, false, nil); err != nil {
				return nil, err
			}
		}
		if err := in.call(ctx, http.MethodPost, "kv/metadata/bindings/"+id, token, map[string]any{
			"custom_metadata": map[string]string{"ligo_binding_id": id}}, false, nil); err != nil {
			return nil, err
		}
		auth["secretPath"] = readPath
	case "vault-dynamic":
		d := payload.GetDelegatedRole()
		if payload.GetMode() != pluginv1.IdentityMode_IDENTITY_MODE_DELEGATED_DYNAMIC || d == nil || d.GetRoleType() != "database-dynamic" {
			return nil, incompatible()
		}
		if err := in.call(ctx, http.MethodPost, "database/roles/binding-"+id, token, map[string]any{
			"db_name": in.DBConnection, "creation_statements": d.GetCreationStatements(), "revocation_statements": d.GetRevocationStatements(),
			"rollback_statements": d.GetRollbackStatements(), "default_ttl": d.GetDefaultTtlSeconds(), "max_ttl": d.GetMaxTtlSeconds(),
		}, false, nil); err != nil {
			return nil, err
		}
		readPath = "database/creds/binding-" + id
		auth["credsPath"] = readPath
	default:
		return nil, pluginsdk.Error(codes.FailedPrecondition, "UNKNOWN_STRATEGY", "vault-static or vault-dynamic only", false)
	}
	hcl := fmt.Sprintf("# ligo:binding_id=%s\npath %q {\n  capabilities = [\"read\"]\n}\n", id, readPath)
	if err := in.call(ctx, http.MethodPut, "sys/policies/acl/"+policy, token, map[string]string{"policy": hcl}, false, nil); err != nil {
		return nil, err
	}
	data, _ := json.Marshal(auth)
	return &pluginv1.EnsureSecretStoreResponse{FinalizedClientAuthJson: data, DeclaredEndpoints: []*pluginv1.Endpoint{endpoint(in.Address)}}, nil
}

func endpoint(address string) *pluginv1.Endpoint {
	u, err := url.Parse(address)
	if err != nil {
		return &pluginv1.Endpoint{}
	}
	host, port, _ := net.SplitHostPort(u.Host)
	n, _ := strconv.Atoi(port)
	return &pluginv1.Endpoint{Host: host, Port: uint32(n), Scheme: u.Scheme} // #nosec G115 -- a port
}

// CleanupSecretStore revokes the binding's leases and deletes its objects;
// what is absent is success (§5.8 rule 1).
func (p *plugin) CleanupSecretStore(ctx context.Context, r *pluginv1.CleanupSecretStoreRequest) (*pluginv1.CleanupSecretStoreResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	id, err := bindingID(r.GetBinding())
	if err != nil {
		return nil, err
	}
	token, err := in.login(ctx)
	if err != nil {
		return nil, err
	}
	steps := []struct{ method, path string }{
		{http.MethodPut, "sys/leases/revoke-prefix/database/creds/binding-" + id},
		{http.MethodDelete, "database/roles/binding-" + id},
		{http.MethodDelete, "kv/metadata/bindings/" + id},
		{http.MethodDelete, "sys/policies/acl/binding-" + id},
	}
	for _, s := range steps {
		if err := in.call(ctx, s.method, s.path, token, nil, true, nil); err != nil {
			return nil, err
		}
	}
	return &pluginv1.CleanupSecretStoreResponse{}, nil
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-svids" {
		os.Exit(labkit.PrintSVIDs(os.Args[2]))
	}
	p := &plugin{}
	pluginsdk.Serve(pluginsdk.Plugins{Control: p, Store: p})
}
