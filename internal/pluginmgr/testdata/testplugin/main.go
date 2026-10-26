// Command testplugin is the plugin the pluginmgr tests launch: a target
// provider that serves PluginControl. TESTPLUGIN_PROTOCOL=2 makes it a
// plugin of another handshake protocol, which the host must refuse;
// TESTPLUGIN_KIND=identity or store makes it a plugin of that kind.
package main

import (
	"context"
	"fmt"
	"os"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/hashicorp/go-plugin"
)

type control struct {
	pluginv2.UnimplementedPluginControlServer
}

func (control) Describe(context.Context, *pluginv2.DescribeRequest) (*pluginv2.DescribeResponse, error) {
	return &pluginv2.DescribeResponse{PluginType: "test.v1", Kind: pluginv2.PluginKind_PLUGIN_KIND_TARGET_PROVIDER, PluginProtocolVersion: 1}, nil
}

func (control) ConfigureInstances(_ context.Context, r *pluginv2.ConfigureInstancesRequest) (*pluginv2.ConfigureInstancesResponse, error) {
	out := &pluginv2.ConfigureInstancesResponse{}
	for _, in := range r.GetInstances() {
		out.Resolved = append(out.Resolved, &pluginv2.ResolvedInstance{Instance: in.GetName(), SpiffeId: "spiffe://" + in.GetTrustDomain() + "/plugin/" + in.GetName()})
	}
	return out, nil
}

func (control) Health(_ context.Context, r *pluginv2.HealthRequest) (*pluginv2.HealthResponse, error) {
	// go-plugin hands the host's client certificate over only with AutoMTLS
	mtls := os.Getenv("PLUGIN_CLIENT_CERT") != ""
	return &pluginv2.HealthResponse{Serving: true, PublicMessage: fmt.Sprintf("ok %s mtls=%t", r.GetInstance(), mtls)}, nil
}

type target struct {
	pluginv2.UnimplementedTargetProviderPluginServer
}

type identity struct {
	pluginv2.UnimplementedIdentityProviderPluginServer
}

type store struct {
	pluginv2.UnimplementedSecretStoreProviderPluginServer
}

func main() {
	plugins := pluginsdk.Plugins{Control: control{}, Target: target{}}
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
