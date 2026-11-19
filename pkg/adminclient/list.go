// SPDX-License-Identifier: MIT

package adminclient

import (
	"context"
	"iter"
	"net/http"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
)

// maxPageSize is what the server accepts; a larger request is cut to it.
const maxPageSize = 200

// call is a generated operation with its parameters bound.
type call = func(context.Context, ...gen.RequestEditorFn) (*http.Response, error)

// fetch makes a call and decodes its answer.
func fetch[T any](ctx context.Context, c *Client, f call) (out T, err error) {
	err = c.exec(ctx, f, &out)
	return out, err
}

// pages follows nextPageToken from the first page to the last; it stops at
// the first error, which it yields, and when the caller stops.
func pages[T any](fetchPage func(token string) (Page[T], error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		token := ""
		for {
			p, err := fetchPage(token)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for _, item := range p.Items {
				if !yield(item, nil) {
					return
				}
			}
			if p.NextPageToken == "" {
				return
			}
			token = p.NextPageToken
		}
	}
}

// opt is nil for an empty string, so that the parameter is not sent.
func opt[T ~string](s string) *T {
	if s == "" {
		return nil
	}
	v := T(s)
	return &v
}

func optSize(n int) *int {
	if n <= 0 {
		return nil
	}
	n = min(n, maxPageSize)
	return &n
}

func optBool(b *bool) *bool { return b }

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
