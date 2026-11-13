package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// rest calls the workload API's REST endpoints.
type rest struct {
	base string
	http *http.Client
}

func newREST(address string, tlsConfig *tls.Config) *rest {
	return &rest{base: "https://" + address, http: &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}}}
}

func (r *rest) close() error {
	r.http.CloseIdleConnections()
	return nil
}

func (r *rest) bindings(ctx context.Context, f Filter, etag string) ([]Binding, string, bool, error) {
	q := url.Values{}
	if f.Target != "" {
		q.Set("target", f.Target)
	}
	if f.PlatformType != "" {
		q.Set("platformType", f.PlatformType)
	}
	return restGet(ctx, r, "/v1/bindings", q, etag, wireBinding.binding)
}

func (r *rest) flows(ctx context.Context, f Filter, etag string) ([]BindingFlows, string, bool, error) {
	q := url.Values{}
	if f.Target != "" {
		q.Set("target", f.Target)
	}
	return restGet(ctx, r, "/v1/flows", q, etag, wireFlows.flows)
}

// restGet makes one conditional GET and decodes the items of its answer.
func restGet[W, T any](ctx context.Context, r *rest, path string, q url.Values, etag string, convert func(W) T) ([]T, string, bool, error) {
	u := r.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", false, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		if errors.Is(err, ErrUnauthorized) {
			return nil, "", false, err
		}
		return nil, "", false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, etag, true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, "", false, fmt.Errorf("%w: %s", ErrUnauthorized, resp.Status)
	case http.StatusServiceUnavailable, http.StatusTooManyRequests:
		return nil, "", false, fmt.Errorf("%w: %s", ErrUnavailable, resp.Status)
	default:
		return nil, "", false, fmt.Errorf("unexpected answer: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, "", false, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if len(body) > maxBody {
		return nil, "", false, fmt.Errorf("the answer is larger than %d bytes", maxBody)
	}
	var doc struct {
		Items []W `json:"items"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, "", false, fmt.Errorf("the answer is not a bindings document: %w", err)
	}
	items := make([]T, len(doc.Items))
	for i, w := range doc.Items {
		items[i] = convert(w)
	}
	return items, resp.Header.Get("ETag"), false, nil
}
