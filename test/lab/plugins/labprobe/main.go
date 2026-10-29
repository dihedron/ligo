// Command labprobe is a lab plugin (test tooling, never shipped): a secret
// store whose instances select their SVID from the zone's SPIRE agent and
// whose Health reads the instance's bootstrap credential from Vault with it,
// answering with the user name only (.specs/ligo-test-environment.md,
// "Plugins on ligo1"). "labprobe -svids SOCKET" prints the SPIFFE IDs the
// agent issues to this binary, run as this user: what lab.sh deploy waits on.
package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/dihedron/ligo/test/lab/plugins/labkit"
	"google.golang.org/grpc/codes"
)

type probe struct {
	pluginv1.UnimplementedPluginControlServer
	mu        sync.Mutex
	instances map[string]*labkit.Instance
}

func (*probe) Describe(context.Context, *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	return &pluginv1.DescribeResponse{
		PluginType: "labprobe.v1", Kind: pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, PluginProtocolVersion: 1,
		InstanceConfigSchemaJson: `{"type":"object"}`, // the bootstrap settings, checked by the probe itself
		Capabilities:             &pluginv1.DescribeResponse_SecretStore{SecretStore: &pluginv1.SecretStoreCapabilities{ClientOutputSchemaJson: `{"type":"object"}`}},
	}, nil
}

func (p *probe) ConfigureInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (*pluginv1.ConfigureInstancesResponse, error) {
	instances, out, err := labkit.Configure(ctx, r)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.instances = instances
	p.mu.Unlock()
	return out, nil
}

func (p *probe) Health(ctx context.Context, r *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	p.mu.Lock()
	in := p.instances[r.GetInstance()]
	p.mu.Unlock()
	if in == nil {
		return nil, pluginsdk.Error(codes.NotFound, "UNKNOWN_INSTANCE", "no instance "+r.GetInstance(), false)
	}
	cred, err := in.Credential.Get(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap credential:", err) // statuses only: the host's log redacts the rest
		return nil, pluginsdk.Error(codes.Unavailable, "BOOTSTRAP_CREDENTIAL_UNAVAILABLE", "cannot read the bootstrap credential", true)
	}
	return &pluginv1.HealthResponse{Serving: true, PublicMessage: "credential for " + cred.Username}, nil
}

type store struct {
	pluginv1.UnimplementedSecretStorePluginServer
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-svids" {
		os.Exit(labkit.PrintSVIDs(os.Args[2]))
	}
	pluginsdk.Serve(pluginsdk.Plugins{Control: &probe{}, Store: store{}})
}
