// SPDX-License-Identifier: MIT

// Package adminraw is the way of the ligo CLI to the raw call of
// pkg/adminclient. The CLI prints whatever the server answers, so it reaches
// operations that the typed methods leave out, among them the decisions of
// people (.specs/ligo-adminclient.md §8.2, T-A4). The call is here and not in
// pkg/adminclient so that nothing outside this module can make it: Go lets
// only code of this module import an internal package, so the Terraform
// provider and the MCP server cannot call it, and the compiler, not a test
// or a promise, says so.
package adminraw

import (
	"context"
	"errors"
	"net/url"
)

// Func is the raw call of a client: the method and the path of the admin API
// (such as /v1/admin/maintenance, escaped, with no query), the query, a body
// to send as JSON, and out, which is nil, a pointer to decode the answer into
// or an io.Writer that the answer is copied to.
type Func func(ctx context.Context, client any, method, path string, query url.Values, body, out any) error

var do Func

// Register is called by pkg/adminclient when it is initialised.
func Register(f Func) { do = f }

// Do makes the raw call of client, a *adminclient.Client.
func Do(ctx context.Context, client any, method, path string, query url.Values, body, out any) error {
	if do == nil {
		return errors.New("adminraw: pkg/adminclient is not linked in")
	}
	return do(ctx, client, method, path, query, body, out)
}
