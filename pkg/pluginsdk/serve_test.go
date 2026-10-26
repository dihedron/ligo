package pluginsdk

import (
	"context"
	"testing"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type (
	control struct {
		pluginv2.UnimplementedPluginControlServer
	}
	identity struct {
		pluginv2.UnimplementedIdentityProviderPluginServer
	}
	target struct {
		pluginv2.UnimplementedTargetProviderPluginServer
	}
	store struct {
		pluginv2.UnimplementedSecretStoreProviderPluginServer
	}
)

// TestPluginsSet: PluginControl plus exactly one kind, all on one server.
func TestPluginsSet(t *testing.T) {
	for name, p := range map[string]Plugins{
		"identity": {Control: control{}, Identity: identity{}},
		"target":   {Control: control{}, Target: target{}},
		"store":    {Control: control{}, Store: store{}},
	} {
		set, err := p.Set()
		if err != nil || len(set) != 2 || set[name] == nil {
			t.Fatalf("%s: %v %v", name, set, err)
		}
		srv := grpc.NewServer()
		for _, s := range set {
			if err := s.(service).GRPCServer(nil, srv); err != nil {
				t.Fatal(err)
			}
		}
		if len(srv.GetServiceInfo()) != 2 {
			t.Errorf("%s: services %v", name, srv.GetServiceInfo())
		}
		direct := grpc.NewServer()
		if err := p.Register(direct); err != nil || len(direct.GetServiceInfo()) != 2 {
			t.Errorf("%s: Register: %v %v", name, err, direct.GetServiceInfo())
		}
	}
	for name, p := range map[string]Plugins{
		"no control": {Target: target{}},
		"no kind":    {Control: control{}},
		"two kinds":  {Control: control{}, Target: target{}, Store: store{}},
	} {
		if _, err := p.Set(); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if err := p.Register(grpc.NewServer()); err == nil {
			t.Errorf("%s: registered", name)
		}
	}
}

// TestClientSet: every service has its client.
func TestClientSet(t *testing.T) {
	conn, err := grpc.NewClient("passthrough:///unused", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	for name, s := range ClientSet() {
		c, err := s.(service).GRPCClient(context.Background(), nil, conn)
		if err != nil || c == nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
