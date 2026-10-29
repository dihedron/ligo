// Package labkit is what the lab's plugins share (test tooling, never
// shipped): each instance selects its SVID from the zone's SPIRE agent and
// reads its bootstrap credential from OpenBao with it (§5.4, §5.5).
package labkit

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/dihedron/ligo/pkg/pluginsdk"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
)

// Common is the part of an instance's config_json every lab plugin has.
type Common struct {
	BootstrapCredential pluginsdk.BootstrapCredentialConfig `json:"bootstrap_credential"`
	CAFile              string                              `json:"ca_file"` // the lab CA, of OpenBao's and PostgreSQL's certificates
}

// Instance is a configured instance.
type Instance struct {
	Name       string
	ConfigJSON string
	Credential *pluginsdk.BootstrapCredential // nil without a bootstrap_credential
	JWT        pluginsdk.JWTSource            // the instance's JWT-SVID for OpenBao
	Roots      *x509.CertPool                 // the lab CA
}

// Configure selects each instance's SVID and prepares its bootstrap
// credential.
func Configure(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (map[string]*Instance, *pluginv1.ConfigureInstancesResponse, error) {
	// the client lives as long as the process
	client, err := workloadapi.New(context.Background(), workloadapi.WithAddr(r.GetSpiffeWorkloadSocket()))
	if err != nil {
		return nil, nil, pluginsdk.Error(codes.Unavailable, "WORKLOAD_API_UNAVAILABLE", "cannot reach the SPIRE agent", true)
	}
	instances := map[string]*Instance{}
	out := &pluginv1.ConfigureInstancesResponse{}
	for _, in := range r.GetInstances() {
		sel, err := pluginsdk.NewInstanceSVIDSelector(client, in.GetName(), in.GetTrustDomain(), pluginsdk.SelectorConfig{
			MatchExpr: in.GetSvidSelector().GetMatchExpr(), JWTAudience: in.GetSvidSelector().GetJwtAudience(),
		})
		if err != nil {
			return nil, nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_SELECTOR", err.Error(), false)
		}
		svid, err := sel.SelectX509SVID(ctx)
		if err != nil {
			return nil, nil, pluginsdk.Error(codes.FailedPrecondition, "SVID_SELECTION_FAILED", err.Error(), false)
		}
		inst, err := bootstrap(in, sel)
		if err != nil {
			return nil, nil, pluginsdk.Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": "+err.Error(), false)
		}
		instances[in.GetName()] = inst
		out.Resolved = append(out.Resolved, &pluginv1.ResolvedInstance{Instance: in.GetName(), SpiffeId: svid.ID.String()})
	}
	return instances, out, nil
}

func bootstrap(in *pluginv1.InstanceDescriptor, jwt pluginsdk.JWTSource) (*Instance, error) {
	var cfg Common
	if err := json.Unmarshal([]byte(in.GetConfigJson()), &cfg); err != nil {
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
	inst := &Instance{Name: in.GetName(), ConfigJSON: in.GetConfigJson(), JWT: jwt, Roots: roots}
	if cfg.BootstrapCredential.Source != "" {
		if inst.Credential, err = pluginsdk.NewBootstrapCredential(cfg.BootstrapCredential, jwt, HTTPClient(roots)); err != nil {
			return nil, err
		}
	}
	return inst, nil
}

// HTTPClient is a client that trusts the lab CA only.
func HTTPClient(roots *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
}

// PrintSVIDs prints the SPIFFE IDs the agent at socket issues to this
// binary, run as this user: what lab.sh deploy waits on ("NAME -svids").
func PrintSVIDs(socket string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	svids, err := workloadapi.FetchX509SVIDs(ctx, workloadapi.WithAddr(socket))
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		return 1
	}
	for _, s := range svids {
		_, _ = os.Stdout.WriteString(s.ID.String() + "\n")
	}
	return 0
}
