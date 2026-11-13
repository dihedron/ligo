// Package client is the Go SDK for workloads that use ligo: it fetches the
// calling workload's bindings and network flows from ligo's workload API,
// over mTLS with the workload's SVID (.specs/ligo-client-sdk.md).
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	callTimeout = 15 * time.Second
	maxBody     = 8 << 20 // T-C7
)

// Transport selects how the client talks to ligo.
type Transport string

// REST is the default transport.
const REST Transport = "rest"

// X509Source gives the workload's SVID and the bundles to verify peers
// with; a *workloadapi.X509Source is one.
type X509Source interface {
	x509svid.Source
	x509bundle.Source
}

// Config configures a Client.
type Config struct {
	Address    string       // host:port of ligo's workload API; always TLS
	ServerID   string       // ligo's SPIFFE ID; any other peer is refused
	Transport  Transport    // REST when empty
	X509Source X509Source   // default: the Workload API at SPIFFE_ENDPOINT_SOCKET
	Logger     *slog.Logger // default: slog.Default()
}

// Client reads the calling workload's bindings. It is safe for concurrent use.
type Client struct {
	source    X509Source
	closer    io.Closer // the source, when New opened it
	transport transport
	log       *slog.Logger

	mu       sync.Mutex
	bindings map[Filter]cached[Binding]
	flows    map[Filter]cached[BindingFlows]
}

// cached is the last answer for a filter, sent back as a conditional request.
type cached[T any] struct {
	etag  string
	items []T
}

// transport is one way to call the workload API. With a matching etag it
// answers notModified and no items.
type transport interface {
	bindings(ctx context.Context, f Filter, etag string) (items []Binding, newETag string, notModified bool, err error)
	flows(ctx context.Context, f Filter, etag string) (items []BindingFlows, newETag string, notModified bool, err error)
	close() error
}

// New validates the configuration and opens the SVID source. It does not
// call ligo.
func New(ctx context.Context, cfg Config) (*Client, error) {
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("client: Address %q: host:port is required: %w", cfg.Address, err)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil || host == "" {
		return nil, fmt.Errorf("client: Address %q: host:port is required, with no scheme", cfg.Address)
	}
	id, err := spiffeid.FromString(cfg.ServerID)
	if err != nil {
		return nil, fmt.Errorf("client: ServerID: %w", err)
	}
	if cfg.Transport == "" {
		cfg.Transport = REST
	}
	if cfg.Transport != REST {
		return nil, fmt.Errorf("client: Transport %q: %q only", cfg.Transport, REST)
	}
	c := &Client{source: cfg.X509Source, log: cfg.Logger, bindings: map[Filter]cached[Binding]{}, flows: map[Filter]cached[BindingFlows]{}}
	if c.log == nil {
		c.log = slog.Default()
	}
	if c.source == nil {
		s, err := workloadapi.NewX509Source(ctx)
		if err != nil {
			return nil, fmt.Errorf("client: the SPIFFE Workload API: %w", err)
		}
		c.source, c.closer = s, s
	}
	c.transport = newREST(cfg.Address, c.TLSConfig(id))
	return c, nil
}

// Close releases the client's connections, and the SVID source if New
// opened it.
func (c *Client) Close() error {
	err := c.transport.close()
	if c.closer != nil {
		err = errors.Join(err, c.closer.Close())
	}
	return err
}

// TLSConfig is a client configuration for mTLS with the workload's SVID
// that accepts only serverID, for ligo and for targets that speak SPIFFE
// mTLS.
func (c *Client) TLSConfig(serverID spiffeid.ID) *tls.Config {
	authorize := tlsconfig.AuthorizeID(serverID)
	cfg := tlsconfig.MTLSClientConfig(c.source, c.source, func(id spiffeid.ID, chains [][]*x509.Certificate) error {
		if err := authorize(id, chains); err != nil {
			return fmt.Errorf("%w: %w", ErrUnauthorized, err)
		}
		return nil
	})
	cfg.MinVersion = tls.VersionTLS13
	return cfg
}

// Bindings returns the caller's bindings that match f. No binding is an
// empty list, not an error.
func (c *Client) Bindings(ctx context.Context, f Filter) ([]Binding, error) {
	items, err := fetch(ctx, c, c.bindings, f, c.transport.bindings)
	if err != nil {
		return nil, fmt.Errorf("client: bindings: %w", err)
	}
	return items, nil
}

// Flows returns the network flows of the caller's bindings to f.Target, or
// of all of them.
func (c *Client) Flows(ctx context.Context, f Filter) ([]BindingFlows, error) {
	f.PlatformType = ""
	items, err := fetch(ctx, c, c.flows, f, c.transport.flows)
	if err != nil {
		return nil, fmt.Errorf("client: flows: %w", err)
	}
	return items, nil
}

// fetch makes a conditional call with the remembered ETag and remembers
// the answer.
func fetch[T any](ctx context.Context, c *Client, cache map[Filter]cached[T], f Filter,
	call func(context.Context, Filter, string) ([]T, string, bool, error)) ([]T, error) {
	c.mu.Lock()
	last := cache[f]
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	items, etag, notModified, err := call(ctx, f, last.etag)
	if err != nil {
		return nil, err
	}
	if notModified {
		return last.items, nil
	}
	c.mu.Lock()
	cache[f] = cached[T]{etag: etag, items: items}
	c.mu.Unlock()
	return items, nil
}
