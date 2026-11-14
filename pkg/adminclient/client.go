package adminclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
)

// maxBody is the most the client reads of a response (T-A3).
const maxBody = 8 << 20

// Client calls the admin API. It is safe for concurrent use, keeps no cache
// and starts no goroutine.
type Client struct {
	gen       *gen.Client
	base      string // the server URL without a trailing slash
	http      *http.Client
	log       *slog.Logger
	userAgent string
	// authorize sets the caller's credentials; a closure, so that no print of
	// a Client (not even of a copy's fields) shows a password
	authorize  func(*http.Request)
	maxRetries int
	sleep      func(context.Context, time.Duration) error
	jitter     func(time.Duration) time.Duration
	// getCR and getBinding are what WaitChangeRequest polls; the tests replace them
	getCR      func(context.Context, string) (ChangeRequest, error)
	getBinding func(context.Context, string) (BindingDetail, error)
}

// New validates the configuration and prepares the client. It does not call
// the server.
func New(cfg Config) (*Client, error) {
	u, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	h, err := cfg.httpClient()
	if err != nil {
		return nil, fmt.Errorf("adminclient: %w", err)
	}
	base := strings.TrimSuffix(u.String(), "/")
	g, err := gen.NewClient(base, gen.WithHTTPClient(h))
	if err != nil {
		return nil, fmt.Errorf("adminclient: %w", err)
	}
	c := &Client{gen: g, base: base, http: h, log: cfg.Logger, userAgent: cfg.userAgent(), maxRetries: cfg.MaxRetries, sleep: sleep, jitter: jitter}
	c.getCR, c.getBinding = c.GetChangeRequest, c.GetBinding
	if cfg.Basic != nil {
		user, password := cfg.Basic.Username, string(cfg.Basic.Password)
		c.authorize = func(req *http.Request) { req.SetBasicAuth(user, password) }
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	switch cfg.MaxRetries {
	case 0:
		c.maxRetries = defaultMaxRetries
	case -1:
		c.maxRetries = 0
	}
	return c, nil
}

// Close releases the idle connections.
func (c *Client) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

// String and GoString keep the credentials out of any print of the client.
func (c *Client) String() string   { return "adminclient.Client{}" }
func (c *Client) GoString() string { return c.String() }

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// editor sets the user agent and the credentials of a request.
func (c *Client) editor(_ context.Context, req *http.Request) error {
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "application/json, application/problem+json")
	if c.authorize != nil {
		c.authorize(req)
	}
	return nil
}

// exec makes a generated call and decodes a successful answer into out (nil
// for none); anything else is a *Problem, a redirect or ErrTooLarge. A GET
// that fails in a way that may pass (a busy or unreachable server) is
// repeated up to MaxRetries times with a backoff, honouring Retry-After; any
// other call is made once (T-A6). Only method, path and status are logged.
func (c *Client) exec(ctx context.Context, f call, out any) error {
	var method string
	_, streaming := out.(io.Writer) // part of the answer may be written already: not repeatable
	record := func(ctx context.Context, req *http.Request) error {
		method = req.Method
		return c.editor(ctx, req)
	}
	for attempt := 0; ; attempt++ {
		err := c.once(ctx, f, record, out)
		if err == nil || method != http.MethodGet || streaming || attempt >= c.maxRetries || !transient(ctx, err) {
			return err
		}
		d, ok := c.retryWait(err, attempt)
		if !ok {
			return err
		}
		c.log.LogAttrs(ctx, slog.LevelDebug, "admin API call failed, retrying", slog.Int("attempt", attempt+1), slog.Duration("after", d))
		if sleepErr := c.sleep(ctx, d); sleepErr != nil {
			return err
		}
	}
}

// once makes the call one time.
func (c *Client) once(ctx context.Context, f call, record gen.RequestEditorFn, out any) error {
	resp, err := f(ctx, record)
	if err != nil {
		return fmt.Errorf("adminclient: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	c.log.LogAttrs(ctx, slog.LevelDebug, "admin API call", slog.String("method", resp.Request.Method), slog.String("path", resp.Request.URL.Path), slog.Int("status", resp.StatusCode))

	if w, ok := out.(io.Writer); ok && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if _, err := io.Copy(w, resp.Body); err != nil {
			return fmt.Errorf("adminclient: copying the response: %w", err)
		}
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	switch {
	case err != nil:
		return fmt.Errorf("adminclient: reading the response: %w", err)
	case len(body) > maxBody:
		return fmt.Errorf("adminclient: %w (more than %d bytes)", ErrTooLarge, maxBody)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("adminclient: %w (%d)", ErrRedirect, resp.StatusCode)
	case resp.StatusCode >= 400 || resp.StatusCode < 200:
		return problemOf(resp, body)
	case out == nil || len(body) == 0:
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("adminclient: the response of %s %s is not what the contract says: %w", resp.Request.Method, resp.Request.URL.Path, err)
	}
	return nil
}
