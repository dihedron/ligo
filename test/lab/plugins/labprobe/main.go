// Command labprobe is a lab plugin (test tooling, never shipped): a secret
// store whose instances select their SVID from the zone's SPIRE agent and
// whose Health reads the instance's bootstrap credential from Vault with it,
// answering with the user name only (.specs/ligo-test-environment.md,
// "Plugins on ligo1"). "labprobe -svids SOCKET" prints the SPIFFE IDs the
// agent issues to this binary, run as this user: what lab.sh deploy waits on.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
)

// instanceConfig is an instance's config_json.
type instanceConfig struct {
	BootstrapCredential pluginsdk.BootstrapCredentialConfig `json:"bootstrap_credential"`
	CAFile              string                              `json:"ca_file"` // the CA of Vault's certificate
}

type probe struct {
	pluginv1.UnimplementedPluginControlServer
	mu    sync.Mutex
	creds map[string]*pluginsdk.BootstrapCredential
}

func (*probe) Describe(context.Context, *pluginv1.DescribeRequest) (*pluginv1.DescribeResponse, error) {
	return &pluginv1.DescribeResponse{
		PluginType: "labprobe.v1", Kind: pluginv1.PluginKind_PLUGIN_KIND_SECRET_STORE, PluginProtocolVersion: 1,
		InstanceConfigSchemaJson: `{"type":"object"}`, // the bootstrap settings, checked by the probe itself
		Capabilities:             &pluginv1.DescribeResponse_SecretStore{SecretStore: &pluginv1.SecretStoreCapabilities{ClientOutputSchemaJson: `{"type":"object"}`}},
	}, nil
}

func (p *probe) ConfigureInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (*pluginv1.ConfigureInstancesResponse, error) {
	// the client lives as long as the process
	client, err := workloadapi.New(context.Background(), workloadapi.WithAddr(r.GetSpiffeWorkloadSocket()))
	if err != nil {
		return nil, pluginsdk.Error(codes.Unavailable, "WORKLOAD_API_UNAVAILABLE", "cannot reach the SPIRE agent", true)
	}
	creds := map[string]*pluginsdk.BootstrapCredential{}
	out := &pluginv1.ConfigureInstancesResponse{}
	for _, in := range r.GetInstances() {
		sel, err := pluginsdk.NewInstanceSVIDSelector(client, in.GetName(), in.GetTrustDomain(), pluginsdk.SelectorConfig{
			MatchExpr: in.GetSvidSelector().GetMatchExpr(), JWTAudience: in.GetSvidSelector().GetJwtAudience(),
		})
		if err != nil {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_SELECTOR", err.Error(), false)
		}
		svid, err := sel.SelectX509SVID(ctx)
		if err != nil {
			return nil, pluginsdk.Error(codes.FailedPrecondition, "SVID_SELECTION_FAILED", err.Error(), false)
		}
		bc, err := bootstrap(in.GetConfigJson(), sel)
		if err != nil {
			return nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": "+err.Error(), false)
		}
		creds[in.GetName()] = bc
		out.Resolved = append(out.Resolved, &pluginv1.ResolvedInstance{Instance: in.GetName(), SpiffeId: svid.ID.String()})
	}
	p.mu.Lock()
	p.creds = creds
	p.mu.Unlock()
	return out, nil
}

func bootstrap(configJSON string, jwt pluginsdk.JWTSource) (*pluginsdk.BootstrapCredential, error) {
	var cfg instanceConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, err
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("no certificate in ca_file")
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	return pluginsdk.NewBootstrapCredential(cfg.BootstrapCredential, jwt, client)
}

func (p *probe) Health(ctx context.Context, r *pluginv1.HealthRequest) (*pluginv1.HealthResponse, error) {
	p.mu.Lock()
	bc := p.creds[r.GetInstance()]
	p.mu.Unlock()
	if bc == nil {
		return nil, pluginsdk.Error(codes.NotFound, "UNKNOWN_INSTANCE", "no instance "+r.GetInstance(), false)
	}
	cred, err := bc.Get(ctx)
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
		os.Exit(printSVIDs(os.Args[2]))
	}
	pluginsdk.Serve(pluginsdk.Plugins{Control: &probe{}, Store: store{}})
}

func printSVIDs(socket string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	svids, err := workloadapi.FetchX509SVIDs(ctx, workloadapi.WithAddr(socket))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for _, s := range svids {
		fmt.Println(s.ID)
	}
	return 0
}
