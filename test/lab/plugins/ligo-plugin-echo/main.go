// Command ligo-plugin-echo is a lab plugin (test tooling, never shipped, not
// hardened): the platform provider of the echo target, which keeps the
// echo server's access list (SVID mode) or its users (TARGET_LOCAL) through
// the server's control API (.specs/ligo-echo-target.md).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/command/version"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/dihedron/ligo/test/lab/plugins/labkit"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"google.golang.org/grpc/codes"
)

const typ = "echo.v1"

var (
	principalRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,19}$`)
	modes       = map[string]pluginv1.IdentityMode{"svid": pluginv1.IdentityMode_IDENTITY_MODE_SVID, "password": pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL}
)

// config is an instance's config_json.
type config struct {
	labkit.Common
	DataAddress    string `json:"data_address"`    // host:port of the echo server's data port
	ControlAddress string `json:"control_address"` // host:port of its control API
	ServerID       string `json:"server_id"`       // its SPIFFE ID
	Mode           string `json:"mode"`            // svid or password
}

type instance struct {
	*labkit.Instance
	config
	serverID spiffeid.ID
	control  *http.Client
}

type plugin struct {
	pluginv1.UnimplementedPluginControlServer
	pluginv1.UnimplementedPlatformProviderPluginServer
	mu        sync.Mutex
	instances map[string]*instance
}

//go:embed schemas/config.json
var configSchema string

//go:embed schemas/output.json
var outputSchema string

func (*plugin) Describe(context.Context, *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	return &pluginv1.DescribeResponse{PluginType: typ, Kind: pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER, PluginProtocolVersion: 2,
		PluginVersion: "lab", InstanceConfigSchemaJson: configSchema,
		Capabilities: &pluginv1.DescribeResponse_PlatformProvider{PlatformProvider: &pluginv1.PlatformProviderCapabilities{
			AcceptedIdentityModes:  []pluginv1.IdentityMode{pluginv1.IdentityMode_IDENTITY_MODE_SVID, pluginv1.IdentityMode_IDENTITY_MODE_TARGET_LOCAL},
			ClientOutputSchemaJson: outputSchema,
		}},
	}, nil
}

func invalidConfig(name, why string) error {
	return pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+name+": "+why, false)
}

// ValidateInstance checks one instance without serving it: the echo server's
// two ports are its endpoints, with the bootstrap Vault.
func (*plugin) ValidateInstance(ctx context.Context, r *pluginv1.ValidateInstanceRequest) (*pluginv1.ValidateInstanceResponse, error) {
	return labkit.Validate(ctx, r, func(in *pluginv1.InstanceDescriptor) ([]string, error) {
		inst := &instance{}
		if err := json.Unmarshal([]byte(in.GetConfigJson()), &inst.config); err != nil {
			return nil, err
		}
		if err := inst.check(in.GetIdentityMode()); err != nil {
			return nil, err
		}
		return []string{inst.DataAddress, inst.ControlAddress}, nil
	})
}

func (p *plugin) ConfigureInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (*pluginv1.ConfigureInstancesResponse, error) {
	kits, out, err := labkit.Configure(ctx, r)
	if err != nil {
		return nil, err
	}
	instances := map[string]*instance{}
	for _, in := range r.GetInstances() {
		inst := &instance{Instance: kits[in.GetName()]}
		if err := json.Unmarshal([]byte(in.GetConfigJson()), &inst.config); err != nil {
			return nil, invalidConfig(in.GetName(), "config")
		}
		if err := inst.check(in.GetIdentityMode()); err != nil {
			return nil, invalidConfig(in.GetName(), err.Error())
		}
		inst.control = inst.controlClient()
		instances[in.GetName()] = inst
	}
	p.mu.Lock()
	p.instances = instances
	p.mu.Unlock()
	return out, nil
}

// check validates the configuration: the mode agrees with the platform's
// identity mode, the addresses are host:port, the server ID is one.
func (in *instance) check(mode pluginv1.IdentityMode) error {
	want, ok := modes[in.Mode]
	if !ok || mode != want {
		return fmt.Errorf("mode %q does not match the platform's identity mode %s", in.Mode, mode)
	}
	for _, a := range []string{in.DataAddress, in.ControlAddress} {
		if _, port, err := net.SplitHostPort(a); err != nil || port == "" {
			return fmt.Errorf("%q is not host:port", a)
		}
	}
	id, err := spiffeid.FromString(in.ServerID)
	if err != nil {
		return fmt.Errorf("server_id: %w", err)
	}
	in.serverID = id
	return nil
}

// controlClient calls the control API with the instance's SVID, verifying
// the server's SPIFFE ID against the agent's bundles at each handshake.
func (in *instance) controlClient() *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			svid, err := in.X509(context.Background())
			if err != nil {
				return nil, err
			}
			return tlsconfig.GetClientCertificate(svid)(nil)
		},
		InsecureSkipVerify: true, // a SPIFFE server certificate names no host: VerifyPeerCertificate checks it
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			bundles, err := in.Bundles(context.Background())
			if err != nil {
				return err
			}
			return tlsconfig.VerifyPeerCertificate(bundles, tlsconfig.AuthorizeID(in.serverID))(raw, nil)
		}}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// call sends a control request; absent answers success for a DELETE and
// false for a GET when the server says 404.
func (in *instance) call(ctx context.Context, method, path string, body any) (found bool, err error) {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://"+in.ControlAddress+path, rd)
	if err != nil {
		return false, err
	}
	resp, err := in.control.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ligo-plugin-echo:", err)
		return false, pluginsdk.Error(codes.Unavailable, "TARGET_UNAVAILABLE", "the echo server cannot be reached", true)
	}
	_ = resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode >= 300:
		fmt.Fprintln(os.Stderr, "ligo-plugin-echo:", method, path, resp.Status)
		return false, pluginsdk.Error(codes.Unavailable, "TARGET_ERROR", "the echo server refused a change", true)
	}
	return true, nil
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

// empty reports whether data is absent or the JSON object {}.
func empty(data []byte) bool {
	var m map[string]any
	return len(bytes.TrimSpace(data)) == 0 || json.Unmarshal(data, &m) == nil && len(m) == 0
}

// ValidateTarget: an empty definition; every level grants "echo".
func (p *plugin) ValidateTarget(_ context.Context, r *pluginv1.ValidateTargetRequest) (*pluginv1.ValidateTargetResponse, error) {
	if _, err := p.instance(r.GetInstance()); err != nil {
		return nil, err
	}
	if !empty(r.GetDefinitionJson()) {
		return &pluginv1.ValidateTargetResponse{Errors: []string{"definition must be {}"}}, nil
	}
	resp := &pluginv1.ValidateTargetResponse{Valid: true, NormalizedDefinitionJson: []byte("{}")}
	for _, l := range r.GetAccessLevels() {
		if !empty(l.GetGrantsJson()) {
			return &pluginv1.ValidateTargetResponse{Errors: []string{"accessLevels." + l.GetName() + ": grants must be {}"}}, nil
		}
		resp.AccessLevels = append(resp.AccessLevels, &pluginv1.NormalizedAccessLevel{Name: l.GetName(), GrantsJson: []byte("{}"), Privileges: []string{"echo"}})
	}
	return resp, nil
}

// spec is a binding's requested spec.
type spec struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	ServerID string `json:"serverId"`
	Mode     string `json:"mode"`
}

// ValidateBinding: no parameters; the spec names the server.
func (p *plugin) ValidateBinding(_ context.Context, r *pluginv1.ValidateBindingRequest) (*pluginv1.ValidateBindingResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	if !empty(r.GetParametersJson()) {
		return &pluginv1.ValidateBindingResponse{Errors: []string{"parameters must be {}"}}, nil
	}
	host, port, _ := net.SplitHostPort(in.DataAddress)
	n, _ := strconv.Atoi(port)
	requested, _ := json.Marshal(spec{Host: host, Port: n, ServerID: in.ServerID, Mode: in.Mode})
	return &pluginv1.ValidateBindingResponse{Valid: true, NormalizedParametersJson: []byte("{}"), RequestedSpecJson: requested, Privileges: []string{"echo"}}, nil
}

// EnsureTarget admits the binding's workloads: its source regex on the
// access list (SVID), or its user with a generated password, kept unless
// new or rotated (TARGET_LOCAL).
func (p *plugin) EnsureTarget(ctx context.Context, r *pluginv1.EnsureTargetRequest) (*pluginv1.EnsureTargetResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	b, mode := r.GetBinding(), r.GetIdentity().GetMode()
	if mode != modes[in.Mode] {
		return nil, pluginsdk.Error(codes.FailedPrecondition, "INCOMPATIBLE_IDENTITY_MODE", "this echo server is in "+in.Mode+" mode", false)
	}
	clientSpec := map[string]string{"endpoint": in.DataAddress, "serverId": in.ServerID, "mode": in.Mode}
	payload := &pluginv1.SecretProvisioningPayload{Mode: mode}
	if mode == pluginv1.IdentityMode_IDENTITY_MODE_SVID {
		if _, err := regexp.Compile(b.GetSourceSvidRegex()); err != nil || b.GetBindingId() == "" {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_BINDING", "binding ID and source regex", false)
		}
		if _, err := in.call(ctx, http.MethodPut, "/acl/"+b.GetBindingId(), map[string]string{"regex": b.GetSourceSvidRegex()}); err != nil {
			return nil, err
		}
	} else {
		user := b.GetDerivedPrincipalName()
		if !principalRE.MatchString(user) {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_PRINCIPAL", "principal name", false)
		}
		clientSpec["user"] = user
		exists, err := in.call(ctx, http.MethodGet, "/users/"+user, nil)
		if err != nil {
			return nil, err
		}
		if exists && !b.GetRotateStaticSecrets() {
			payload.SecretUnchanged = true
		} else {
			password, err := pluginsdk.GeneratePassword(32)
			if err != nil {
				return nil, err
			}
			if _, err := in.call(ctx, http.MethodPut, "/users/"+user, map[string]string{"password": password}); err != nil {
				return nil, err
			}
			payload.Payload = &pluginv1.SecretProvisioningPayload_StaticSecret{StaticSecret: &pluginv1.StaticSecret{Username: user, Password: password}}
		}
	}
	host, port, _ := net.SplitHostPort(in.DataAddress)
	n, _ := strconv.Atoi(port)
	out, _ := json.Marshal(clientSpec)
	return &pluginv1.EnsureTargetResponse{FinalizedClientSpecJson: out, SecretPayload: payload,
		DeclaredEndpoints: []*pluginv1.Endpoint{{Host: host, Port: uint32(n), Scheme: "tcp"}}}, nil // #nosec G115 -- a port
}

// CleanupTarget removes what EnsureTarget added; gone is success.
func (p *plugin) CleanupTarget(ctx context.Context, r *pluginv1.CleanupTargetRequest) (*pluginv1.CleanupTargetResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	b := r.GetBinding()
	path := "/acl/" + b.GetBindingId()
	if in.Mode == "password" {
		if !principalRE.MatchString(b.GetDerivedPrincipalName()) {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_PRINCIPAL", "principal name", false)
		}
		path = "/users/" + b.GetDerivedPrincipalName()
	}
	if _, err := in.call(ctx, http.MethodDelete, path, nil); err != nil {
		return nil, err
	}
	return &pluginv1.CleanupTargetResponse{}, nil
}

func (p *plugin) GetUISchemas(_ context.Context, r *pluginv1.GetUISchemasRequest) (*pluginv1.GetUISchemasResponse, error) {
	return &pluginv1.GetUISchemasResponse{PluginType: typ, Instance: r.GetInstance()}, nil
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		os.Exit(version.Run(os.Args[2:]))
	}
	if len(os.Args) == 3 && os.Args[1] == "-svids" {
		os.Exit(labkit.PrintSVIDs(os.Args[2]))
	}
	p := &plugin{}
	pluginsdk.Serve(pluginsdk.Plugins{Control: p, Platform: p})
}
