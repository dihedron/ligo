package sealing

import (
	"context"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// WorkloadJWT fetches JWT-SVIDs from the SPIRE agent's Workload API: the
// JWTFetcher of ligo's core identity (§8.1 core_identity).
type WorkloadJWT struct {
	// Addr is the Workload API socket, such as
	// unix:///run/spire/prod/agent.sock.
	Addr string
}

// FetchJWT implements JWTFetcher.
func (w WorkloadJWT) FetchJWT(ctx context.Context, audience string) (string, error) {
	svid, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience}, workloadapi.WithAddr(w.Addr))
	if err != nil {
		return "", fmt.Errorf("workload API %s: %w", w.Addr, err)
	}
	return svid.Marshal(), nil
}
