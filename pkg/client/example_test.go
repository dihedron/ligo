package client_test

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/dihedron/ligo/pkg/client"
)

// A workload reads its binding to a database, takes its credential, and
// follows the credential's rotation (the Developer's Guide, Part 1).
func Example() {
	ctx := context.Background()
	c, err := client.New(ctx, client.Config{
		Address:       "ligo.example.com:8443",
		ServerID:      "spiffe://example.com/ns/sys/sa/ligo",
		AllowedStores: []string{"https://vault.example.com:8200"},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	bindings, err := c.Bindings(ctx, client.Filter{Target: "orders-db"})
	if err != nil || len(bindings) == 0 {
		log.Fatal(errors.Join(err, errors.New("no binding to orders-db")))
	}
	cred, err := c.Credential(ctx, bindings[0])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(bindings[0].Endpoint(), cred.Username, cred) // the password is hidden

	err = c.Watch(ctx, client.Filter{Target: "orders-db", WatchCredentials: true}, func(ev client.Event) {
		switch ev.Kind {
		case client.CredentialRotated:
			// open new connections with ev.Credential; let the old ones finish
		case client.Removed:
			// close the connections of ev.Previous
		}
	})
	log.Println(err) // the context's error, when it ends
}
