// Command testplugin is the plugin the pluginmgr tests launch: a platform
// provider that serves PluginControl. TESTPLUGIN_PROTOCOL=2 makes it a
// plugin of another handshake protocol, which the host must refuse;
// TESTPLUGIN_KIND=identity or store makes it a plugin of that kind, and
// TESTPLUGIN_TYPE sets the type it describes (default test.v1), and
// TESTPLUGIN_CAPS=identity, platform or store the capabilities it describes
// (default: its kind's). TESTPLUGIN_VERSION_FILE names a file whose
// content is the plugin version it describes.
//
// ConfigureInstances resolves an instance by its match_expr: "shared" to one
// SPIFFE ID for all, "foreign" to another trust domain, "skip" to nothing,
// "two" to the SDK's error for a selector matching two SVIDs (AC-15), and
// anything else to spiffe://<trust domain>/plugin/<instance>. Health of the
// instance "crash" exits; of "log", logs secrets the host must redact.
package main

import (
	"context"
	"fmt"
	"os"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc/codes"
)

var kinds = map[string]pluginv2.PluginKind{
	"":         pluginv2.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER,
	"identity": pluginv2.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER,
	"store":    pluginv2.PluginKind_PLUGIN_KIND_SECRET_STORE,
}

type control struct {
	pluginv2.UnimplementedPluginControlServer
}

func (control) Describe(context.Context, *pluginv2.DescribeRequest) (*pluginv2.DescribeResponse, error) {
	typ := os.Getenv("TESTPLUGIN_TYPE")
	if typ == "" {
		typ = "test.v1"
	}
	caps := os.Getenv("TESTPLUGIN_CAPS")
	if caps == "" {
		caps = os.Getenv("TESTPLUGIN_KIND")
	}
	d := &pluginv2.DescribeResponse{PluginType: typ, Kind: kinds[os.Getenv("TESTPLUGIN_KIND")], PluginProtocolVersion: 1}
	if f := os.Getenv("TESTPLUGIN_VERSION_FILE"); f != "" {
		v, _ := os.ReadFile(f)
		d.PluginVersion = string(v)
	}
	switch caps {
	case "identity":
		d.Capabilities = &pluginv2.DescribeResponse_IdentityProvider{IdentityProvider: &pluginv2.IdentityProviderCapabilities{}}
	case "store":
		d.Capabilities = &pluginv2.DescribeResponse_SecretStore{SecretStore: &pluginv2.SecretStoreCapabilities{}}
	default:
		d.Capabilities = &pluginv2.DescribeResponse_PlatformProvider{PlatformProvider: &pluginv2.PlatformProviderCapabilities{}}
	}
	return d, nil
}

func (control) ConfigureInstances(_ context.Context, r *pluginv2.ConfigureInstancesRequest) (*pluginv2.ConfigureInstancesResponse, error) {
	out := &pluginv2.ConfigureInstancesResponse{}
	for _, in := range r.GetInstances() {
		id := "spiffe://" + in.GetTrustDomain() + "/plugin/" + in.GetName()
		switch in.GetSvidSelector().GetMatchExpr() {
		case "shared":
			id = "spiffe://" + in.GetTrustDomain() + "/plugin/shared"
		case "foreign":
			id = "spiffe://other.lab/plugin/" + in.GetName()
		case "skip":
			continue
		case "two":
			return nil, pluginsdk.Error(codes.FailedPrecondition, "SVID_SELECTION_FAILED",
				fmt.Sprintf("selector for %q matched more than one SVID", in.GetName()), false)
		}
		out.Resolved = append(out.Resolved, &pluginv2.ResolvedInstance{Instance: in.GetName(), SpiffeId: id})
	}
	return out, nil
}

func (control) Health(_ context.Context, r *pluginv2.HealthRequest) (*pluginv2.HealthResponse, error) {
	switch r.GetInstance() {
	case "crash":
		os.Exit(3)
	case "log":
		hclog.New(&hclog.LoggerOptions{Output: os.Stderr, JSONFormat: true}).
			Info("connecting", "password", "pw-leak", "user", "admin")
		fmt.Fprintln(os.Stderr, "ALTER USER x IDENTIFIED BY raw-leak")
	}
	// go-plugin hands the host's client certificate over only with AutoMTLS
	mtls := os.Getenv("PLUGIN_CLIENT_CERT") != ""
	return &pluginv2.HealthResponse{Serving: true, PublicMessage: fmt.Sprintf("ok %s mtls=%t", r.GetInstance(), mtls)}, nil
}

type platform struct {
	pluginv2.UnimplementedPlatformProviderPluginServer
}

type identity struct {
	pluginv2.UnimplementedIdentityProviderPluginServer
}

type store struct {
	pluginv2.UnimplementedSecretStorePluginServer
}

func main() {
	plugins := pluginsdk.Plugins{Control: control{}, Platform: platform{}}
	switch os.Getenv("TESTPLUGIN_KIND") {
	case "identity":
		plugins = pluginsdk.Plugins{Control: control{}, Identity: identity{}}
	case "store":
		plugins = pluginsdk.Plugins{Control: control{}, Store: store{}}
	}
	if os.Getenv("TESTPLUGIN_PROTOCOL") == "2" {
		set, _ := plugins.Set()
		handshake := pluginsdk.Handshake
		handshake.ProtocolVersion = 2
		plugin.Serve(&plugin.ServeConfig{HandshakeConfig: handshake, Plugins: set, GRPCServer: plugin.DefaultGRPCServer})
		return
	}
	pluginsdk.Serve(plugins)
}
