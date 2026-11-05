// Command ligo-plugin-openldap is the openldap.v1 identity provider: one
// directory account per binding (.specs/ligo-openldap-plugin.md).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/pkg/metadata"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/go-ldap/ldap/v3"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
)

const (
	typ            = "openldap.v1"
	passwordLength = 40
	callTimeout    = 10 * time.Second
)

// principalRE is the grammar of the one request value in a DN (§5.8 rule 3).
var principalRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,19}$`)

const configSchema = `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","additionalProperties":false,
"required":["url","service_ou_dn","allowed_endpoints","bootstrap_credential"],
"properties":{"url":{"type":"string"},"service_ou_dn":{"type":"string"},"allowed_endpoints":{"type":"array","items":{"type":"string"}},
"ca_file":{"type":"string"},"bootstrap_credential":{"type":"object"}}}`

// config is an instance's checked config_json.
type config struct {
	URL                 string                              `json:"url"`
	ServiceOU           string                              `json:"service_ou_dn"`
	AllowedEndpoints    []string                            `json:"allowed_endpoints"`
	CAFile              string                              `json:"ca_file"`
	BootstrapCredential pluginsdk.BootstrapCredentialConfig `json:"bootstrap_credential"`

	host  string
	roots *x509.CertPool // nil: the system roots
}

// parseConfig checks an instance's configuration (§3); errors name the field.
func parseConfig(data []byte) (*config, error) {
	var c config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "ldaps" || u.Hostname() == "" || u.Path != "" || u.User != nil || u.RawQuery != "" {
		return nil, errors.New("url must be ldaps://host[:port]")
	}
	c.host = u.Hostname()
	port := u.Port()
	if port == "" {
		port = "636"
	}
	if !slices.Contains(c.AllowedEndpoints, net.JoinHostPort(c.host, port)) {
		return nil, fmt.Errorf("allowed_endpoints must contain %s", net.JoinHostPort(c.host, port))
	}
	if c.ServiceOU == "" {
		return nil, errors.New("service_ou_dn is required")
	}
	if _, err := ldap.ParseDN(c.ServiceOU); err != nil {
		return nil, errors.New("service_ou_dn is not a valid DN")
	}
	if c.BootstrapCredential.Source == "" {
		return nil, errors.New("bootstrap_credential is required")
	}
	if c.BootstrapCredential.KVPath == "" {
		return nil, errors.New("bootstrap_credential.kv_path is required")
	}
	if err := c.BootstrapCredential.Validate(); err != nil {
		return nil, err
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, errors.New("ca_file cannot be read")
		}
		c.roots = x509.NewCertPool()
		if !c.roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca_file has no certificate")
		}
	}
	return &c, nil
}

type instance struct {
	serviceOU string
	dial      func(context.Context) (directory, error)
}

type plugin struct {
	pluginv1.UnimplementedPluginControlServer
	pluginv1.UnimplementedIdentityProviderPluginServer
	mu        sync.Mutex
	instances map[string]*instance
}

func (*plugin) Describe(context.Context, *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	return &pluginv1.DescribeResponse{PluginType: typ, Kind: pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER, PluginProtocolVersion: 1,
		PluginVersion: metadata.Version, InstanceConfigSchemaJson: configSchema,
		Capabilities: &pluginv1.DescribeResponse_IdentityProvider{IdentityProvider: &pluginv1.IdentityProviderCapabilities{
			ProducedIdentityMode: pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR}}}, nil
}

// ConfigureInstances checks every instance's configuration, then selects
// its SVID and prepares its bootstrap credential (§5.4, §5.5).
func (p *plugin) ConfigureInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (*pluginv1.ConfigureInstancesResponse, error) {
	configs := map[string]*config{}
	for _, in := range r.GetInstances() {
		c, err := parseConfig([]byte(in.GetConfigJson()))
		if err != nil {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": "+err.Error(), false)
		}
		configs[in.GetName()] = c
	}
	// the client lives as long as the process
	client, err := workloadapi.New(context.Background(), workloadapi.WithAddr(r.GetSpiffeWorkloadSocket()))
	if err != nil {
		return nil, pluginsdk.Error(codes.Unavailable, "WORKLOAD_API_UNAVAILABLE", "cannot reach the SPIRE agent", true)
	}
	instances := map[string]*instance{}
	out := &pluginv1.ConfigureInstancesResponse{}
	for _, in := range r.GetInstances() {
		sel, err := pluginsdk.NewInstanceSVIDSelector(client, in.GetName(), in.GetTrustDomain(), pluginsdk.SelectorConfig{
			MatchExpr: in.GetSvidSelector().GetMatchExpr(), JWTAudience: in.GetSvidSelector().GetJwtAudience()})
		if err != nil {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_SELECTOR", err.Error(), false)
		}
		svid, err := sel.SelectX509SVID(ctx)
		if err != nil {
			return nil, pluginsdk.Error(codes.FailedPrecondition, "SVID_SELECTION_FAILED", err.Error(), false)
		}
		c := configs[in.GetName()]
		var vault *http.Client // nil: the SDK's, with the system roots
		if c.roots != nil {
			vault = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: c.roots, MinVersion: tls.VersionTLS12}}}
		}
		cred, err := pluginsdk.NewBootstrapCredential(c.BootstrapCredential, sel, vault)
		if err != nil {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": "+err.Error(), false)
		}
		instances[in.GetName()] = &instance{serviceOU: c.ServiceOU, dial: dialer(c, cred)}
		out.Resolved = append(out.Resolved, &pluginv1.ResolvedInstance{Instance: in.GetName(), SpiffeId: svid.ID.String()})
	}
	p.mu.Lock()
	p.instances = instances
	p.mu.Unlock()
	return out, nil
}

func (p *plugin) instance(name string) (*instance, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if in := p.instances[name]; in != nil {
		return in, nil
	}
	return nil, pluginsdk.Error(codes.NotFound, "UNKNOWN_INSTANCE", "no instance "+name, false)
}

// Health binds with the bootstrap credential.
func (p *plugin) Health(ctx context.Context, r *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	d, err := in.dial(ctx)
	if err != nil {
		report(err)
		return &pluginv1.HealthResponse{PublicMessage: "the directory cannot be reached with the bootstrap credential"}, nil
	}
	d.close()
	return &pluginv1.HealthResponse{Serving: true}, nil
}

// entry checks a binding and returns its account's DN and ownership tag.
func entry(in *instance, b *pluginv1.BindingContext) (dn, tag string, err error) {
	if !principalRE.MatchString(b.GetDerivedPrincipalName()) {
		return "", "", pluginsdk.Error(codes.InvalidArgument, "INVALID_PRINCIPAL", "the principal name is outside the plugin's grammar", false)
	}
	if b.GetBindingId() == "" {
		return "", "", pluginsdk.Error(codes.InvalidArgument, "INVALID_BINDING", "the request has no binding id", false)
	}
	return "uid=" + b.GetDerivedPrincipalName() + "," + in.serviceOU, "ligo:binding_id=" + b.GetBindingId(), nil
}

// EnsureIdentity converges the binding's account (§5 of the plugin's spec).
func (p *plugin) EnsureIdentity(ctx context.Context, r *pluginv1.EnsureIdentityRequest) (*pluginv1.EnsureIdentityResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	b := r.GetBinding()
	dn, tag, err := entry(in, b)
	if err != nil {
		return nil, err
	}
	d, err := in.dial(ctx)
	if err != nil {
		return nil, failure(err)
	}
	defer d.close()
	artifact := &pluginv1.IdentityArtifact{Mode: pluginv1.IdentityMode_IDENTITY_MODE_EXTERNAL_DIR,
		PrincipalId: b.GetDerivedPrincipalName(), DistinguishedName: dn}
	setPassword := func() (*pluginv1.EnsureIdentityResponse, error) {
		password, err := pluginsdk.GeneratePassword(passwordLength)
		if err != nil {
			return nil, pluginsdk.Error(codes.Internal, "PASSWORD_GENERATION_FAILED", "cannot generate a password", true)
		}
		if err := d.setPassword(dn, password); err != nil {
			return nil, failure(err)
		}
		artifact.StaticSecret = &pluginv1.StaticSecret{Username: b.GetDerivedPrincipalName(), Password: password}
		return &pluginv1.EnsureIdentityResponse{Artifact: artifact}, nil
	}
	for range 2 { // an Add that finds the entry reads it again, once
		exists, descriptions, err := d.read(dn)
		if err != nil {
			return nil, failure(err)
		}
		switch {
		case exists && !slices.Contains(descriptions, tag):
			return nil, pluginsdk.ErrOwnedByOtherBinding("account " + b.GetDerivedPrincipalName())
		case exists && b.GetRotateStaticSecrets():
			return setPassword()
		case exists:
			artifact.SecretUnchanged = true
			return &pluginv1.EnsureIdentityResponse{Artifact: artifact}, nil
		}
		err = d.add(dn, b.GetDerivedPrincipalName(), tag)
		if err == nil {
			return setPassword()
		}
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return nil, failure(err)
		}
	}
	return nil, pluginsdk.Error(codes.FailedPrecondition, "DIRECTORY_REJECTED", "the directory refused the operation", false)
}

// CleanupIdentity removes the binding's account; it does not use the
// previous artifact, which may be empty (AC-10).
func (p *plugin) CleanupIdentity(ctx context.Context, r *pluginv1.CleanupIdentityRequest) (*pluginv1.CleanupIdentityResponse, error) {
	in, err := p.instance(r.GetInstance())
	if err != nil {
		return nil, err
	}
	dn, tag, err := entry(in, r.GetBinding())
	if err != nil {
		return nil, err
	}
	d, err := in.dial(ctx)
	if err != nil {
		return nil, failure(err)
	}
	defer d.close()
	exists, descriptions, err := d.read(dn)
	switch {
	case err != nil:
		return nil, failure(err)
	case !exists:
		return &pluginv1.CleanupIdentityResponse{}, nil
	case !slices.Contains(descriptions, tag):
		return &pluginv1.CleanupIdentityResponse{SkippedNotOwner: true}, nil
	}
	if err := d.remove(dn); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return nil, failure(err)
	}
	return &pluginv1.CleanupIdentityResponse{}, nil
}

// report logs an error's kind only: directory diagnostics can echo request
// data (§5.8 rule 6).
func report(err error) {
	var le *ldap.Error
	if errors.As(err, &le) {
		fmt.Fprintln(os.Stderr, "ligo-plugin-openldap: LDAP result", le.ResultCode)
		return
	}
	fmt.Fprintln(os.Stderr, "ligo-plugin-openldap: no LDAP result (network, TLS or credential)")
}

// failure maps an error to §6's codes, with fixed messages.
func failure(err error) error {
	report(err)
	unavailable := func() error {
		return pluginsdk.Error(codes.Unavailable, "DIRECTORY_UNAVAILABLE", "the directory cannot be reached", true)
	}
	if errors.Is(err, errCredential) {
		return pluginsdk.Error(codes.Unavailable, "BOOTSTRAP_CREDENTIAL_UNAVAILABLE", "cannot read the bootstrap credential", true)
	}
	var le *ldap.Error
	if !errors.As(err, &le) {
		return unavailable()
	}
	switch le.ResultCode {
	case ldap.ErrorNetwork, ldap.LDAPResultBusy, ldap.LDAPResultUnavailable:
		return unavailable()
	case ldap.LDAPResultInvalidCredentials:
		return pluginsdk.Error(codes.Unavailable, "BOOTSTRAP_CREDENTIAL_REJECTED", "the directory refused the bootstrap credential", true)
	case ldap.LDAPResultInsufficientAccessRights:
		return pluginsdk.Error(codes.PermissionDenied, "DIRECTORY_ACCESS_DENIED", "the bootstrap credential may not do this", false)
	}
	return pluginsdk.Error(codes.FailedPrecondition, "DIRECTORY_REJECTED", "the directory refused the operation", false)
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-svids" {
		os.Exit(pluginsdk.PrintSVIDs(os.Args[2]))
	}
	p := &plugin{}
	pluginsdk.Serve(pluginsdk.Plugins{Control: p, Identity: p})
}
