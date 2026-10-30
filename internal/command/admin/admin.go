// Package admin holds the CLI commands of the admin API (§8.4): each
// connects with client.Options and prints its result in the global
// output format.
package admin

import (
	"context"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/dihedron/ligo/internal/client"
)

// Base is what every admin command embeds: the connection options and the
// global options, which main hands over before Execute.
type Base struct {
	client.Options
	globals *client.Globals
	out     io.Writer // stdout unless a test sets it
}

// SetGlobals receives the root's GlobalOptions.
func (b *Base) SetGlobals(g *client.Globals) { b.globals = g }

func (b *Base) format() string {
	if b.globals == nil {
		return "table"
	}
	return b.globals.Format
}

// call connects, runs fn, and prints what it returns with columns.
func (b *Base) call(fn func(ctx context.Context, c *client.Client) (any, []client.Column, error)) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	c, err := b.Connect(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	v, columns, err := fn(ctx, c)
	if err != nil {
		return err
	}
	out := b.out
	if out == nil {
		out = os.Stdout
	}
	return client.Print(out, b.format(), v, columns...)
}

// get prints the answer of GET path.
func (b *Base) get(path string, query url.Values, columns ...client.Column) error {
	return b.call(func(ctx context.Context, c *client.Client) (any, []client.Column, error) {
		var v any
		return v, columns, c.Do(ctx, "GET", path, query, nil, &v)
	})
}

// Page is the keyset paging of the list commands.
type Page struct {
	PageSize  int    `long:"page-size" default:"50" description:"Maximum items per page (<= 200)."`
	PageToken string `long:"page-token" description:"Keyset cursor token from previous page."`
}

// query is the page's parameters plus the non-empty pairs of kv.
func (p Page) query(kv ...string) url.Values {
	q := url.Values{}
	if p.PageSize > 0 {
		q.Set("pageSize", strconv.Itoa(p.PageSize))
	}
	if p.PageToken != "" {
		q.Set("pageToken", p.PageToken)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			q.Set(kv[i], kv[i+1])
		}
	}
	return q
}

// ResourceArgs names one resource: ligo get binding NAME.
type ResourceArgs struct {
	Kind string `positional-arg-name:"kind" choice:"source" choice:"target" choice:"binding" description:"Resource kind."`
	Name string `positional-arg-name:"name" description:"Resource name."`
}

// NameArg names a platform, a target or a binding.
type NameArg struct {
	Name string `positional-arg-name:"name" description:"Resource name."`
}

func path(segments ...string) string {
	p := "/v1/admin"
	for _, s := range segments {
		p += "/" + url.PathEscape(s)
	}
	return p
}

func col(header, path string) client.Column { return client.Column{Header: header, Path: path} }

// columns of each resource kind in tables.
var columns = map[string][]client.Column{
	"source": {col("NAME", "metadata.name"), col("SCOPE", "metadata.scope"), col("TRUST DOMAIN", "identity.trustDomain"), col("STATE", "metadata.state"),
		col("REVISION", "metadata.revision")},
	"target": {col("NAME", "metadata.name"), col("PLATFORM", "metadata.platform"), col("SCOPE", "metadata.scope"), col("STATE", "metadata.state"),
		col("REVISION", "metadata.revision")},
	"binding": {col("NAME", "metadata.name"), col("SOURCE", "source"), col("TARGET", "target"), col("LEVEL", "accessLevel"), col("PHASE", "status.phase"),
		col("REVISION", "metadata.revision"), col("EXPIRES", "expiresAt")},
	"request": {col("ID", "id"), col("TYPE", "resourceType"), col("NAME", "resourceName"), col("OPERATION", "operation"), col("KIND", "kind"),
		col("STATUS", "status"), col("AWAITING", "awaitingApproval"), col("REQUESTED BY", "requestedBy")},
	"platform": {col("NAME", "name"), col("TYPE", "type"), col("ZONE", "zone"), col("SCOPE", "scope"), col("SERVING", "health.serving")},
	"catalog":  {col("NAME", "name"), col("PLATFORM", "platform"), col("TYPE", "platformType"), col("SCOPE", "scope"), col("STATE", "state"), col("BOUND", "bound")},
	"audit":    {col("ID", "id"), col("AT", "occurredAt"), col("ACTION", "action"), col("ACTOR", "actor"), col("REVISION", "revision")},
	"flow": {col("NAME", "name"), col("PURPOSE", "purpose"), col("PROTOCOL", "protocol"), col("DESTINATION", "destination"), col("PORTS", "ports"),
		col("TLS", "tls"), col("DECLARED BY", "declaredBy")},
}
