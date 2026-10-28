package pluginsdk

import (
	"context"
	"errors"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
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
	PlatformService = "platform"
	StoreService    = "store"
)

// Plugins are a plugin binary's implementations: PluginControl and the
// service of exactly one kind.
type Plugins struct {
	Control  pluginv1.PluginControlServer
	Identity pluginv1.IdentityProviderPluginServer
	Platform pluginv1.PlatformProviderPluginServer
	Store    pluginv1.SecretStorePluginServer
}

// Set is the go-plugin set serving p, every service on one gRPC server.
func (p Plugins) Set() (plugin.PluginSet, error) {
	if p.Control == nil {
		return nil, errors.New("a plugin must implement PluginControl")
	}
	set := plugin.PluginSet{ControlService: service{register: func(s *grpc.Server) { pluginv1.RegisterPluginControlServer(s, p.Control) }}}
	if p.Identity != nil {
		set[IdentityService] = service{register: func(s *grpc.Server) { pluginv1.RegisterIdentityProviderPluginServer(s, p.Identity) }}
	}
	if p.Platform != nil {
		set[PlatformService] = service{register: func(s *grpc.Server) { pluginv1.RegisterPlatformProviderPluginServer(s, p.Platform) }}
	}
	if p.Store != nil {
		set[StoreService] = service{register: func(s *grpc.Server) { pluginv1.RegisterSecretStorePluginServer(s, p.Store) }}
	}
	if len(set) != 2 {
		return nil, errors.New("a plugin must implement exactly one of the identity, target and store services")
	}
	return set, nil
}

// Register registers p's services on srv: how ligo serves its builtin
// plugins in-process.
func (p Plugins) Register(srv *grpc.Server) error {
	set, err := p.Set()
	if err != nil {
		return err
	}
	for _, s := range set {
		s.(service).register(srv)
	}
	return nil
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
		ControlService:  service{client: func(c *grpc.ClientConn) any { return pluginv1.NewPluginControlClient(c) }},
		IdentityService: service{client: func(c *grpc.ClientConn) any { return pluginv1.NewIdentityProviderPluginClient(c) }},
		PlatformService: service{client: func(c *grpc.ClientConn) any { return pluginv1.NewPlatformProviderPluginClient(c) }},
		StoreService:    service{client: func(c *grpc.ClientConn) any { return pluginv1.NewSecretStorePluginClient(c) }},
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
