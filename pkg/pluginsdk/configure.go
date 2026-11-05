package pluginsdk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
)

// SelectInstances connects to the zone's agent, and selects each instance's
// SVID (§5.4): the selectors by instance, and the response that resolves them.
func SelectInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (map[string]*InstanceSVIDSelector, *pluginv1.ConfigureInstancesResponse, error) {
	// the client lives as long as the process
	client, err := workloadapi.New(context.Background(), workloadapi.WithAddr(r.GetSpiffeWorkloadSocket())) //nolint:contextcheck
	if err != nil {
		return nil, nil, Error(codes.Unavailable, "WORKLOAD_API_UNAVAILABLE", "cannot reach the SPIRE agent", true)
	}
	selectors := map[string]*InstanceSVIDSelector{}
	out := &pluginv1.ConfigureInstancesResponse{}
	for _, in := range r.GetInstances() {
		sel, err := NewInstanceSVIDSelector(client, in.GetName(), in.GetTrustDomain(), SelectorConfig{
			MatchExpr: in.GetSvidSelector().GetMatchExpr(), JWTAudience: in.GetSvidSelector().GetJwtAudience()})
		if err != nil {
			return nil, nil, Error(codes.InvalidArgument, "INVALID_SELECTOR", err.Error(), false)
		}
		svid, err := sel.SelectX509SVID(ctx)
		if err != nil {
			return nil, nil, Error(codes.FailedPrecondition, "SVID_SELECTION_FAILED", err.Error(), false)
		}
		selectors[in.GetName()] = sel
		out.Resolved = append(out.Resolved, &pluginv1.ResolvedInstance{Instance: in.GetName(), SpiffeId: svid.ID.String()})
	}
	return selectors, out, nil
}

// LoadRoots reads a PEM file of roots; no path gives nil, the system roots.
func LoadRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil //nolint:nilnil // nil is how crypto/tls spells the system roots
	}
	pem, err := os.ReadFile(path) // #nosec G304 -- the operator's configuration
	if err != nil {
		return nil, errors.New("ca_file cannot be read")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("ca_file has no certificate")
	}
	return roots, nil
}

// HTTPClient is a client that trusts roots, with a 30 s timeout.
func HTTPClient(roots *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
}
