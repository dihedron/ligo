package adminclient_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/dihedron/ligo/pkg/adminclient"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// A tool that runs as a workload of the platform team: its SVID authenticates
// it, and ligo is accepted only with its exact SPIFFE ID (the Developer's
// Guide, Part 3).
func ExampleNew() {
	ctx := context.Background()
	source, err := workloadapi.NewX509Source(ctx) // SPIFFE_ENDPOINT_SOCKET
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = source.Close() }()

	c, err := adminclient.New(adminclient.Config{
		ServerURL:  "https://ligo.example.com:9443",
		ServerID:   "spiffe://example.com/ns/sys/sa/ligo",
		X509Source: source, // the client SVID, and the bundle that verifies ligo
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
}

// A person's tool, with LDAP credentials: the server is verified by a CA pool
// (here the system's), the password is a Secret that prints as [redacted].
func ExampleBasicAuth() {
	roots, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	c, err := adminclient.New(adminclient.Config{
		ServerURL: "https://ligo.example.com:9443",
		RootCAs:   roots,
		Basic:     &adminclient.BasicAuth{Username: "olivia", Password: adminclient.Secret("from-your-secret-manager")},
	})
	fmt.Println(c, err) // never shows the password
}

// Reading: every list is an iterator over all the pages.
func ExampleClient_ListTargets() {
	ctx := context.Background()
	var c *adminclient.Client // see New

	for t, err := range c.ListTargets(ctx, adminclient.TargetFilter{PlatformType: "postgres", State: "ACTIVE"}) {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(t.Metadata.Name, t.Metadata.Jurisdiction, t.Metadata.Revision)
	}
}

// Filing a change: the call returns the change request, which waits for the
// approval of a person; WaitChangeRequest follows it to its end.
func ExampleClient_WaitChangeRequest() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var c *adminclient.Client // see New

	var spec adminclient.SourceSpec
	spec.Metadata.Name = "orders-workers"
	spec.Identity.TrustDomain = "example.com"
	spec.Identity.SvidRegex = "^spiffe://example.com/ns/orders/sa/worker$"

	cr, err := c.CreateSource(ctx, spec, adminclient.Options{ApprovalReference: "CHG-1042"})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("filed", cr.Id, "awaiting", cr.AwaitingApproval)

	cr, err = c.WaitChangeRequest(ctx, cr.Id.String(), adminclient.WaitOptions{})
	switch {
	case err != nil:
		log.Fatal(err) // the context ended (cr is the last state read), or the request cannot be read
	case !adminclient.IsApplied(cr):
		log.Fatalf("not applied: %s", cr.Status) // REJECTED, WITHDRAWN, EXPIRED or FAILED_TO_APPLY
	}
}

// Changing what exists needs the revision the change is based on: read it,
// change it, file the update. A concurrent change is ErrConflict, and the
// client never retries a mutation.
func ExampleClient_UpdateSource() {
	ctx := context.Background()
	var c *adminclient.Client // see New

	cur, err := c.GetSource(ctx, "orders-workers")
	if err != nil {
		log.Fatal(err)
	}
	var spec adminclient.SourceSpec
	spec.Metadata.Name = cur.Metadata.Name
	spec.Identity.TrustDomain = cur.Identity.TrustDomain
	spec.Identity.SvidRegex = "^spiffe://example.com/ns/orders/sa/worker-[0-9]+$"
	spec.DisplayName = cur.DisplayName

	_, err = c.UpdateSource(ctx, cur.Metadata.Name, spec, cur.Metadata.Revision, adminclient.Options{})
	if errors.Is(err, adminclient.ErrConflict) {
		log.Print("someone changed it first: read it again")
	}
}

// An instance is filed as a definition; the change needs the approval of a
// person of its jurisdiction, so the store does not exist until the request
// is APPLIED.
func ExampleClient_CreateSecretStore() {
	ctx := context.Background()
	var c *adminclient.Client // see New

	var def adminclient.Definition
	err := json.Unmarshal([]byte(`{
		"kind": "SecretStore",
		"metadata": {"name": "vault-prod", "jurisdiction": "example/platform", "realm": "prod"},
		"type": "vault.v1",
		"config": {"address": "https://vault.example.com:8200"}
	}`), &def)
	if err != nil {
		log.Fatal(err)
	}
	cr, err := c.CreateSecretStore(ctx, def, adminclient.Options{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cr.Status, cr.AwaitingApproval) // PENDING [OWNER]
}
