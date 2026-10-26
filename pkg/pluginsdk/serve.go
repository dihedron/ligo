package pluginsdk

import (
	"context"
	"errors"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
)

// Handshake is the go-plugin handshake (§5.3 rule 1): protocol 1, that of
// the first plugin SDK; a plugin with another protocol is refused.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "LIGO_PLUGIN",
	MagicCookieValue: "l1g0-pl7g-v1",
}

// The names of the services in a plugin set.
const (
	ControlService  = "control"
	IdentityService = "identity"
	TargetService   = "target"
	StoreService    = "store"
)

// Plugins are a plugin binary's implementations: PluginControl and the
// service of exactly one kind.
type Plugins struct {
	Control  pluginv2.PluginControlServer
	Identity pluginv2.IdentityProviderPluginServer
	Target   pluginv2.TargetProviderPluginServer
	Store    pluginv2.SecretStoreProviderPluginServer
}

// Set is the go-plugin set serving p, every service on one gRPC server.
func (p Plugins) Set() (plugin.PluginSet, error) {
	if p.Control == nil {
		return nil, errors.New("a plugin must implement PluginControl")
	}
	set := plugin.PluginSet{ControlService: service{register: func(s *grpc.Server) { pluginv2.RegisterPluginControlServer(s, p.Control) }}}
	if p.Identity != nil {
		set[IdentityService] = service{register: func(s *grpc.Server) { pluginv2.RegisterIdentityProviderPluginServer(s, p.Identity) }}
	}
	if p.Target != nil {
		set[TargetService] = service{register: func(s *grpc.Server) { pluginv2.RegisterTargetProviderPluginServer(s, p.Target) }}
	}
	if p.Store != nil {
		set[StoreService] = service{register: func(s *grpc.Server) { pluginv2.RegisterSecretStoreProviderPluginServer(s, p.Store) }}
	}
	if len(set) != 2 {
		return nil, errors.New("a plugin must implement exactly one of the identity, target and store services")
	}
	return set, nil
}

// Serve runs a plugin binary until the host stops it; it panics on a set
// that is not one kind's.
func Serve(p Plugins) {
	set, err := p.Set()
	if err != nil {
		panic(err)
	}
	plugin.Serve(&plugin.ServeConfig{HandshakeConfig: Handshake, Plugins: set, GRPCServer: plugin.DefaultGRPCServer})
}

// ClientSet is the host's view of every service; the host dispenses
// PluginControl and the service of the plugin's kind.
func ClientSet() plugin.PluginSet {
	return plugin.PluginSet{
		ControlService:  service{client: func(c *grpc.ClientConn) any { return pluginv2.NewPluginControlClient(c) }},
		IdentityService: service{client: func(c *grpc.ClientConn) any { return pluginv2.NewIdentityProviderPluginClient(c) }},
		TargetService:   service{client: func(c *grpc.ClientConn) any { return pluginv2.NewTargetProviderPluginClient(c) }},
		StoreService:    service{client: func(c *grpc.ClientConn) any { return pluginv2.NewSecretStoreProviderPluginClient(c) }},
	}
}

// service is one gRPC service as a go-plugin plugin: register on the
// plugin side, client on the host side.
type service struct {
	plugin.NetRPCUnsupportedPlugin
	register func(*grpc.Server)
	client   func(*grpc.ClientConn) any
}

func (s service) GRPCServer(_ *plugin.GRPCBroker, srv *grpc.Server) error {
	s.register(srv)
	return nil
}

func (s service) GRPCClient(_ context.Context, _ *plugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return s.client(c), nil
}
