package pluginsdk

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	pluginv1 "github.com/dihedron/ligo/api/gen/plugin/v1"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc/codes"
)

// clients are the Workload API clients of the process, one per socket: a
// plugin is configured again on every change of its instances (ligo-instances
// §7.1), and a client per call would leak a connection each time.
var clients = struct {
	sync.Mutex
	m map[string]*workloadapi.Client
}{m: map[string]*workloadapi.Client{}}

// WorkloadAPIClient returns the process's client for socket, opening it once.
func WorkloadAPIClient(socket string) (*workloadapi.Client, error) {
	clients.Lock()
	defer clients.Unlock()
	if c := clients.m[socket]; c != nil {
		return c, nil
	}
	// the client lives as long as the process
	c, err := workloadapi.New(context.Background(), workloadapi.WithAddr(socket)) //nolint:contextcheck
	if err != nil {
		return nil, Error(codes.Unavailable, "WORKLOAD_API_UNAVAILABLE", "cannot reach the SPIRE agent", true)
	}
	clients.m[socket] = c
	return c, nil
}

// SelectInstance selects one instance's SVID (§5.4): its selector and the
// SPIFFE ID it resolves.
func SelectInstance(ctx context.Context, socket string, in *pluginv1.InstanceDescriptor) (*InstanceSVIDSelector, string, error) {
	client, err := WorkloadAPIClient(socket)
	if err != nil {
		return nil, "", err
	}
	sel, err := NewInstanceSVIDSelector(client, in.GetName(), in.GetTrustDomain(), SelectorConfig{
		MatchExpr: in.GetSvidSelector().GetMatchExpr(), JWTAudience: in.GetSvidSelector().GetJwtAudience()})
	if err != nil {
		return nil, "", Error(codes.InvalidArgument, "INVALID_SELECTOR", err.Error(), false)
	}
	svid, err := sel.SelectX509SVID(ctx)
	if err != nil {
		return nil, "", Error(codes.FailedPrecondition, "SVID_SELECTION_FAILED", err.Error(), false)
	}
	return sel, svid.ID.String(), nil
}

// SelectInstances selects each instance's SVID (§5.4): the selectors by
// instance, and the response that resolves them.
func SelectInstances(ctx context.Context, r *pluginv1.ConfigureInstancesRequest) (map[string]*InstanceSVIDSelector, *pluginv1.ConfigureInstancesResponse, error) {
	selectors := map[string]*InstanceSVIDSelector{}
	out := &pluginv1.ConfigureInstancesResponse{}
	for _, in := range r.GetInstances() {
		sel, id, err := SelectInstance(ctx, r.GetSpiffeWorkloadSocket(), in)
		if err != nil {
			return nil, nil, err
		}
		selectors[in.GetName()] = sel
		out.Resolved = append(out.Resolved, &pluginv1.ResolvedInstance{Instance: in.GetName(), SpiffeId: id})
	}
	return selectors, out, nil
}

// ValidateInstance answers PluginControl.ValidateInstance (ligo-instances
// §7.1): check parses the instance's config without connecting anywhere and
// returns the endpoints it would use; the SVID is selected after, so a
// config that fails reaches no agent.
func ValidateInstance(ctx context.Context, r *pluginv1.ValidateInstanceRequest,
	check func(*pluginv1.InstanceDescriptor) ([]string, error)) (*pluginv1.ValidateInstanceResponse, error) {
	in := r.GetInstance()
	endpoints, err := check(in)
	if err != nil {
		return nil, Error(codes.InvalidArgument, "INVALID_CONFIG", "instance "+in.GetName()+": "+err.Error(), false)
	}
	_, id, err := SelectInstance(ctx, r.GetSpiffeWorkloadSocket(), in)
	if err != nil {
		return nil, err
	}
	return &pluginv1.ValidateInstanceResponse{SpiffeId: id, Endpoints: endpoints}, nil
}

// ParseRoots reads an instance's ca_pem; no text gives nil, the system roots.
func ParseRoots(text string) (*x509.CertPool, error) {
	if text == "" {
		return nil, nil //nolint:nilnil // nil is how crypto/tls spells the system roots
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(text)) {
		return nil, errors.New("ca_pem has no certificate")
	}
	return roots, nil
}

// defaultPorts are the ports of the URL schemes instances use.
var defaultPorts = map[string]string{"https": "443", "ldaps": "636", "ldap": "389"}

// Endpoint is the host:port a URL connects to, with its scheme's default
// port: what ValidateInstance reports, for ligo to check against the type's
// instance_bounds (ligo-instances §6 rule 5).
func Endpoint(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("%q is not a URL", rawURL)
	}
	port, known := defaultPorts[u.Scheme]
	if !known || u.Hostname() == "" {
		return "", fmt.Errorf("%q: want an https, ldaps or ldap URL with a host", rawURL)
	}
	if u.Port() != "" {
		port = u.Port()
	}
	return net.JoinHostPort(u.Hostname(), port), nil
}

// HTTPClient is a client that trusts roots, with a 30 s timeout.
func HTTPClient(roots *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
}
