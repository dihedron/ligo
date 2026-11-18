package flowcheck_test

import (
	"context"
	"fmt"
	"log"

	"github.com/dihedron/ligo/pkg/client"
	"github.com/dihedron/ligo/pkg/client/flowcheck"
)

// A workload checks the flows of its binding to a database before it connects.
func Example() {
	ctx := context.Background()
	c, err := client.New(ctx, client.Config{Address: "ligo.example.com:8443", ServerID: "spiffe://example.com/ns/sys/sa/ligo"})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	results, err := flowcheck.CheckClient(ctx, c, client.Filter{Target: "orders-db"})
	if err != nil {
		log.Fatal(err)
	}
	for _, r := range results.Unreachable() {
		fmt.Printf("blocked: %s to %s:%d: %s\n", r.Flow, r.Destination, r.Port, r.Reason)
	}
}
