package sealing

import (
	"context"
	"testing"
)

// TestWorkloadJWTNoAgent: without an agent on the socket, FetchJWT fails
// (the fetch itself is tested on ligo1, TestLabWorkloadJWT).
func TestWorkloadJWTNoAgent(t *testing.T) {
	if _, err := (WorkloadJWT{Addr: "unix://" + t.TempDir() + "/agent.sock"}).FetchJWT(context.Background(), "x"); err == nil {
		t.Error("a missing socket gave a JWT")
	}
}
