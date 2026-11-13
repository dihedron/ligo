// Package client is the Go SDK for workloads that use ligo: it fetches the
// calling workload's bindings and network flows from ligo's workload API,
// over mTLS with the workload's SVID, and reads each binding's credential
// from its secret store with a JWT-SVID (.specs/ligo-client-sdk.md).
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
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	callTimeout = 15 * time.Second
	maxBody     = 8 << 20 // T-C7
)

// Transport selects how the client talks to ligo.
type Transport string

// The transports; both return the same data. REST is the default.
const (
	REST Transport = "rest"
	GRPC Transport = "grpc"
)

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

	// For Credential:
	JWTSource     jwtsvid.Source // default: the Workload API at SPIFFE_ENDPOINT_SOCKET, opened at the first use
	StoreRoots    *x509.CertPool // the CAs of the secret stores' certificates; default: the system's
	AllowedStores []string       // https://host:port of the stores the client may log in to; empty: any a binding names

	PollInterval time.Duration // of Watch; default 30 s, at least 5 s
}

// Client reads the calling workload's bindings. It is safe for concurrent use.
type Client struct {
	source    X509Source
	closer    io.Closer // the source, when New opened it
	transport transport
	log       *slog.Logger

	storeHTTP     *http.Client
	allowedStores map[string]bool
	now           func() time.Time
	poll          time.Duration
	// readCredential is Credential; the tests of Watch replace it
	readCredential func(context.Context, Binding) (Credential, error)

	mu        sync.Mutex
	bindings  map[Filter]cached[Binding]
	flows     map[Filter]cached[BindingFlows]
	tokens    map[tokenKey]storeToken
	jwtSource jwtsvid.Source
	jwtCloser io.Closer // the JWT source, when the client opened it
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
	if cfg.Transport != REST && cfg.Transport != GRPC {
		return nil, fmt.Errorf("client: Transport %q: %q or %q", cfg.Transport, REST, GRPC)
	}
	c := &Client{source: cfg.X509Source, log: cfg.Logger, bindings: map[Filter]cached[Binding]{}, flows: map[Filter]cached[BindingFlows]{},
		storeHTTP: newStoreHTTP(cfg.StoreRoots), allowedStores: map[string]bool{}, now: time.Now, tokens: map[tokenKey]storeToken{}, jwtSource: cfg.JWTSource}
	c.readCredential = c.Credential
	switch {
	case cfg.PollInterval == 0:
		c.poll = defaultPoll
	case cfg.PollInterval < minPoll:
		return nil, fmt.Errorf("client: PollInterval %s: at least %s", cfg.PollInterval, minPoll)
	default:
		c.poll = cfg.PollInterval
	}
	for _, a := range cfg.AllowedStores {
		address, err := storeAddress(a)
		if err != nil {
			return nil, fmt.Errorf("client: AllowedStores: %w", err)
		}
		c.allowedStores[address] = true
	}
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
	if cfg.Transport == GRPC {
		if c.transport, err = newGRPC(cfg.Address, func(verified func(error)) *tls.Config { return c.tlsConfig(id, verified) }); err != nil {
			_ = c.closeSource()
			return nil, fmt.Errorf("client: gRPC: %w", err)
		}
		return c, nil
	}
	c.transport = newREST(cfg.Address, c.TLSConfig(id))
	return c, nil
}

// Close releases the client's connections, and the SVID source if New
// opened it.
func (c *Client) Close() error {
	c.mu.Lock()
	clear(c.tokens) // T-C4
	jwt := c.jwtCloser
	c.jwtSource, c.jwtCloser = nil, nil
	c.mu.Unlock()
	c.storeHTTP.CloseIdleConnections()
	err := errors.Join(c.transport.close(), c.closeSource())
	if jwt != nil {
		err = errors.Join(err, jwt.Close())
	}
	return err
}

func (c *Client) closeSource() error {
	if c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

// TLSConfig is a client configuration for mTLS with the workload's SVID
// that accepts only serverID, for ligo and for targets that speak SPIFFE
// mTLS.
func (c *Client) TLSConfig(serverID spiffeid.ID) *tls.Config {
	return c.tlsConfig(serverID, func(error) {})
}

// tlsConfig is TLSConfig; verified is told the outcome of each check of
// the server's identity (nil when accepted).
func (c *Client) tlsConfig(serverID spiffeid.ID, verified func(error)) *tls.Config {
	authorize := tlsconfig.AuthorizeID(serverID)
	cfg := tlsconfig.MTLSClientConfig(c.source, c.source, func(id spiffeid.ID, chains [][]*x509.Certificate) error {
		err := authorize(id, chains)
		if err != nil {
			err = fmt.Errorf("%w: %w", ErrUnauthorized, err)
		}
		verified(err)
		return err
	})
	cfg.MinVersion = tls.VersionTLS13
	return cfg
}

// Bindings returns the caller's bindings that match f. No binding is an
// empty list, not an error.
func (c *Client) Bindings(ctx context.Context, f Filter) ([]Binding, error) {
	f.WatchCredentials = false
	items, err := fetch(ctx, c, c.bindings, f, c.transport.bindings)
	if err != nil {
		return nil, fmt.Errorf("client: bindings: %w", err)
	}
	return items, nil
}

// Flows returns the network flows of the caller's bindings to f.Target, or
// of all of them.
func (c *Client) Flows(ctx context.Context, f Filter) ([]BindingFlows, error) {
	f.PlatformType, f.WatchCredentials = "", false
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
