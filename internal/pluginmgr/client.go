// Package pluginmgr hosts the external plugins (§5.2, §5.3).
package pluginmgr

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os/exec"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/internal/builtinplugins"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// kindServices maps a plugin kind to the name of its service.
var kindServices = map[pluginv1.PluginKind]string{
	pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER: pluginsdk.IdentityService,
	pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER: pluginsdk.PlatformService,
	pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE:      pluginsdk.StoreService,
}

// Client is one running plugin, a process or a builtin served in-process:
// PluginControl and the service of its kind (the others are nil).
type Client struct {
	process  *plugin.Client // nil for a builtin
	stop     func()         // a builtin's server and connection
	Control  pluginv1.PluginControlClient
	Identity pluginv1.IdentityProviderPluginClient
	Platform pluginv1.PlatformProviderPluginClient
	Store    pluginv1.SecretStorePluginClient
}

// Start launches cmd as a plugin of kind, over gRPC with AutoMTLS, after
// go-plugin checks the binary's SHA-256 against checksum (§5.3 rules 1, 2
// and 4; EXT-10, EXT-11). go-plugin's messages go to logger; what the plugin
// writes to its stdout and stderr once it serves goes to stdio (nil: dropped).
func Start(cmd *exec.Cmd, kind pluginv1.PluginKind, checksum []byte, logger hclog.Logger, stdio io.Writer) (*Client, error) {
	name, ok := kindServices[kind]
	if !ok {
		return nil, fmt.Errorf("plugin kind %v", kind)
	}
	if stdio == nil {
		stdio = io.Discard
	}
	process := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  pluginsdk.Handshake,
		Plugins:          pluginsdk.ClientSet(),
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
		SkipHostEnv:      true, // a plugin gets cmd.Env only, never ligo's environment
		SyncStdout:       stdio,
		SyncStderr:       stdio,
		SecureConfig:     &plugin.SecureConfig{Checksum: checksum, Hash: sha256.New()},
		Logger:           logger,
	})
	c := &Client{process: process}
	rpc, err := process.Client()
	if err != nil {
		process.Kill()
		return nil, fmt.Errorf("starting plugin %s: %w", cmd.Path, err)
	}
	control, err := rpc.Dispense(pluginsdk.ControlService)
	if err != nil {
		process.Kill()
		return nil, fmt.Errorf("plugin %s: %w", cmd.Path, err)
	}
	c.Control = control.(pluginv1.PluginControlClient)
	svc, err := rpc.Dispense(name)
	if err != nil {
		process.Kill()
		return nil, fmt.Errorf("plugin %s: %w", cmd.Path, err)
	}
	switch s := svc.(type) {
	case pluginv1.IdentityProviderPluginClient:
		c.Identity = s
	case pluginv1.PlatformProviderPluginClient:
		c.Platform = s
	case pluginv1.SecretStorePluginClient:
		c.Store = s
	}
	return c, nil
}

// Kill stops the plugin.
func (c *Client) Kill() {
	if c.process != nil {
		c.process.Kill()
	}
	if c.stop != nil {
		c.stop()
	}
}

// exited tells whether a plugin process has exited; a builtin never does.
func (c *Client) exited() bool { return c.process != nil && c.process.Exited() }

// startBuiltin serves the builtin plugin typ in-process, over an in-memory
// gRPC connection, so that it is called as external plugins are (§5.1).
func startBuiltin(typ string, kind pluginv1.PluginKind) (*Client, error) {
	p, ok := builtinplugins.Lookup(typ)
	if !ok {
		return nil, fmt.Errorf("%s is not a builtin plugin type", typ)
	}
	srv := grpc.NewServer()
	if err := p.Register(srv); err != nil {
		return nil, err
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///"+typ,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials())) // in-memory, never on a network
	if err != nil {
		srv.Stop()
		return nil, err
	}
	c := &Client{Control: pluginv1.NewPluginControlClient(conn), stop: func() { _ = conn.Close(); srv.Stop() }}
	switch kind {
	case pluginv1.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER:
		c.Identity = pluginv1.NewIdentityProviderPluginClient(conn)
	case pluginv1.PluginKind_PLUGIN_KIND_PLATFORM_PROVIDER:
		c.Platform = pluginv1.NewPlatformProviderPluginClient(conn)
	case pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE:
		c.Store = pluginv1.NewSecretStorePluginClient(conn)
	}
	return c, nil
}
