package sealing

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

// fakeAgent is a Workload API that hands out one JWT-SVID (the client
// parses it without verifying the signature).
type fakeAgent struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	token string
}

func (a fakeAgent) FetchJWTSVID(context.Context, *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	return &workload.JWTSVIDResponse{Svids: []*workload.JWTSVID{{SpiffeId: "spiffe://prod.lab/ns/sys/sa/ligo", Svid: a.token}}}, nil
}

// fakeJWT: an ES256-shaped token for audience aud, with a dummy signature.
func fakeJWT(aud string) string {
	enc := base64.RawURLEncoding.EncodeToString
	claims := fmt.Sprintf(`{"sub":"spiffe://prod.lab/ns/sys/sa/ligo","aud":[%q],"exp":%d}`, aud, time.Now().Add(time.Hour).Unix())
	return enc([]byte(`{"alg":"ES256","kid":"k","typ":"JWT"}`)) + "." + enc([]byte(claims)) + "." + enc(make([]byte, 64))
}

// TestWorkloadJWT fetches a JWT-SVID from a fake agent on a Unix socket (the
// real agent is tested on ligo1, TestLabWorkloadJWT).
func TestWorkloadJWT(t *testing.T) {
	sock := t.TempDir() + "/agent.sock"
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	token := fakeJWT("bao")
	workload.RegisterSpiffeWorkloadAPIServer(srv, fakeAgent{token: token})
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(srv.Stop)

	got, err := WorkloadJWT{Addr: "unix://" + sock}.FetchJWT(context.Background(), "bao")
	if err != nil || got != token {
		t.Errorf("FetchJWT = (%q, %v), want the agent's token", got, err)
	}
}

// TestWorkloadJWTNoAgent: without an agent on the socket, FetchJWT fails.
func TestWorkloadJWTNoAgent(t *testing.T) {
	if _, err := (WorkloadJWT{Addr: "unix://" + t.TempDir() + "/agent.sock"}).FetchJWT(context.Background(), "x"); err == nil {
		t.Error("a missing socket gave a JWT")
	}
}
