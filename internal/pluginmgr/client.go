// Package pluginmgr hosts the external plugins (§5.2, §5.3).
package pluginmgr

import (
	"crypto/sha256"
	"fmt"
	"os/exec"

	pluginv2 "github.com/dihedron/ligo/api/gen/plugin/v2"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-plugin"
)

// kindServices maps a plugin kind to the name of its service.
var kindServices = map[pluginv2.PluginKind]string{
	pluginv2.PluginKind_PLUGIN_KIND_IDENTITY_PROVIDER:     pluginsdk.IdentityService,
	pluginv2.PluginKind_PLUGIN_KIND_TARGET_PROVIDER:       pluginsdk.TargetService,
	pluginv2.PluginKind_PLUGIN_KIND_SECRET_STORE_PROVIDER: pluginsdk.StoreService,
}

// Client is one running plugin process: PluginControl and the service of its
// kind (the others are nil).
type Client struct {
	process  *plugin.Client
	Control  pluginv2.PluginControlClient
	Identity pluginv2.IdentityProviderPluginClient
	Target   pluginv2.TargetProviderPluginClient
	Store    pluginv2.SecretStoreProviderPluginClient
}

// Start launches cmd as a plugin of kind, over gRPC with AutoMTLS, after
// go-plugin checks the binary's SHA-256 against checksum (§5.3 rules 1, 2
// and 4; EXT-10, EXT-11).
func Start(cmd *exec.Cmd, kind pluginv2.PluginKind, checksum []byte, logger hclog.Logger) (*Client, error) {
	name, ok := kindServices[kind]
	if !ok {
		return nil, fmt.Errorf("plugin kind %v", kind)
	}
	process := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  pluginsdk.Handshake,
		Plugins:          pluginsdk.ClientSet(),
		Cmd:              cmd,
		AllowedProtocols: []plugin.Protocol{plugin.ProtocolGRPC},
		AutoMTLS:         true,
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
	c.Control = control.(pluginv2.PluginControlClient)
	svc, err := rpc.Dispense(name)
	if err != nil {
		process.Kill()
		return nil, fmt.Errorf("plugin %s: %w", cmd.Path, err)
	}
	switch s := svc.(type) {
	case pluginv2.IdentityProviderPluginClient:
		c.Identity = s
	case pluginv2.TargetProviderPluginClient:
		c.Target = s
	case pluginv2.SecretStoreProviderPluginClient:
		c.Store = s
	}
	return c, nil
}

// Kill stops the plugin process.
func (c *Client) Kill() { c.process.Kill() }
