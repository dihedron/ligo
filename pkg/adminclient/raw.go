package adminclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
)

// Do makes a call the typed methods do not model, with everything else the
// package does for a call: the server's verification, the credentials, no
// redirect, the body limit, the mapping of problems to *Problem and the
// sentinels, and the retries of a GET. It is the way the ligo CLI, which
// prints whatever the server answers, reaches the operations and the decisions
// of people the package leaves out (T-A4).
//
// path is that of the admin API, such as /v1/admin/maintenance, already
// escaped, with no query. body, if not nil, is sent as JSON. out is nil (the
// answer is dropped), a pointer to decode the JSON answer into, or an
// io.Writer that the answer of any size is copied to as it arrives; such a
// call is not retried.
//
// The Terraform provider and the MCP server must not use Do: their calls are
// the typed methods, so that what each of them can do is a list a test reads
// (.specs/ligo-adminclient.md §8.2).
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "?#") {
		return fmt.Errorf("adminclient: path %q: an absolute path with no query or fragment is required", path)
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return fmt.Errorf("adminclient: encoding the request: %w", err)
		}
	}
	target := c.base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	return c.exec(ctx, func(ctx context.Context, editors ...gen.RequestEditorFn) (*http.Response, error) {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, rd)
		if err != nil {
			return nil, errors.New("the request cannot be made")
		}
		if payload != nil {
			req.Header.Set("Content-Type", contentJSON)
		}
		for _, edit := range editors {
			if err := edit(ctx, req); err != nil {
				return nil, err
			}
		}
		return c.http.Do(req)
	}, out)
}
