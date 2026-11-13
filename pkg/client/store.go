package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Errors of Credential, for errors.Is.
var (
	// ErrNoCredential: the binding has no secret store; the workload authenticates with its SVID.
	ErrNoCredential = errors.New("the binding has no credential")
	// ErrUnsupportedStrategy: the SDK does not know the binding's secret storage strategy.
	ErrUnsupportedStrategy = errors.New("unsupported secret storage strategy")
	// ErrStoreNotAllowed: the binding's store address is not https, or is outside Config.AllowedStores.
	ErrStoreNotAllowed = errors.New("store address not allowed")
	// ErrStore: the store refused the login or the read, or the binding does not say how to reach it.
	ErrStore = errors.New("secret store")
)

const (
	strategyStatic  = "vault-static"
	strategyDynamic = "vault-dynamic"
	strategyNone    = "svid" // of the builtin none.v1 store: the SVID is the credential
)

// Credential is what a workload presents to its target.
type Credential struct {
	Username string
	Password string
	Expires  time.Time // zero when the store gives no lease
}

// String hides the password.
func (c Credential) String() string {
	return fmt.Sprintf("{Username:%s Password:[hidden] Expires:%s}", c.Username, c.Expires.Format(time.RFC3339))
}

// GoString hides the password from %#v.
func (c Credential) GoString() string { return "client.Credential" + c.String() }

// LogValue hides the password from slog.
func (c Credential) LogValue() slog.Value {
	return slog.GroupValue(slog.String("username", c.Username), slog.Time("expires", c.Expires))
}

// tokenKey identifies a store login; namespace is "" outside Vault
// Enterprise namespaces.
type tokenKey struct{ address, namespace, mount, role string }

type storeToken struct {
	value string
	until time.Time // 80 % of its TTL
}

// storeAddress checks a store address and returns it as https://host:port.
func storeAddress(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("%q: https://host:port is required", raw)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return "https://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port), nil
}

// newStoreHTTP is the HTTP client for secret stores. It follows no
// redirect: one would carry the JWT-SVID or the store token to another
// host (T-C2).
func newStoreHTTP(roots *x509.CertPool) *http.Client {
	return &http.Client{Timeout: callTimeout,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Credential reads the binding's credential from its secret store, logging
// in with a JWT-SVID. Every call reads the store: with vault-dynamic each
// read makes a new credential, so read once and follow Watch.
func (c *Client) Credential(ctx context.Context, b Binding) (Credential, error) {
	cred, err := c.credential(ctx, b)
	if err != nil {
		return Credential{}, fmt.Errorf("client: the credential of binding %s: %w", b.Name, err)
	}
	return cred, nil
}

func (c *Client) credential(ctx context.Context, b Binding) (Credential, error) {
	cfg := b.Auth.Config
	path := cfg["secretPath"]
	switch b.Auth.Strategy {
	case "", strategyNone:
		return Credential{}, ErrNoCredential
	case strategyStatic:
	case strategyDynamic:
		path = cfg["credsPath"]
	default:
		return Credential{}, fmt.Errorf("%w: %q", ErrUnsupportedStrategy, b.Auth.Strategy)
	}
	for _, k := range []string{"address", "audience", "authMount", "role"} {
		if cfg[k] == "" {
			return Credential{}, fmt.Errorf("%w: the binding names no %s", ErrStore, k)
		}
	}
	if path == "" {
		return Credential{}, fmt.Errorf("%w: the binding names no path", ErrStore)
	}
	address, err := storeAddress(cfg["address"])
	if err != nil {
		return Credential{}, fmt.Errorf("%w: %w", ErrStoreNotAllowed, err)
	}
	if len(c.allowedStores) > 0 && !c.allowedStores[address] {
		return Credential{}, fmt.Errorf("%w: %s is not in AllowedStores", ErrStoreNotAllowed, address)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	key := tokenKey{address, cfg["namespace"], cfg["authMount"], cfg["role"]}
	token, fresh, err := c.storeToken(ctx, b, key, cfg["audience"])
	if err != nil {
		return Credential{}, err
	}
	body, status, err := c.storeCall(ctx, http.MethodGet, key, path, token, nil)
	if status == http.StatusForbidden && !fresh { // the remembered token may be revoked: one new login
		c.dropToken(key)
		if token, _, err = c.storeToken(ctx, b, key, cfg["audience"]); err != nil {
			return Credential{}, err
		}
		body, _, err = c.storeCall(ctx, http.MethodGet, key, path, token, nil)
	}
	if err != nil {
		return Credential{}, fmt.Errorf("%w: read: %w", ErrStore, err)
	}
	cred, err := parseSecret(b.Auth.Strategy, body, c.now())
	if err != nil {
		return Credential{}, fmt.Errorf("%w: read: %w", ErrStore, err)
	}
	return cred, nil
}

// Invalidate forgets the store login of the binding. Call it when the
// target refuses the credential, then read the credential again.
func (c *Client) Invalidate(b Binding) {
	if address, err := storeAddress(b.Auth.Config["address"]); err == nil {
		c.dropToken(tokenKey{address, b.Auth.Config["namespace"], b.Auth.Config["authMount"], b.Auth.Config["role"]})
	}
}

func (c *Client) dropToken(key tokenKey) {
	c.mu.Lock()
	delete(c.tokens, key)
	c.mu.Unlock()
}

// storeToken returns the remembered store token for key, or logs in; fresh
// reports a new login.
func (c *Client) storeToken(ctx context.Context, b Binding, key tokenKey, audience string) (token string, fresh bool, err error) {
	c.mu.Lock()
	t, ok := c.tokens[key]
	c.mu.Unlock()
	if ok && c.now().Before(t.until) {
		return t.value, false, nil
	}
	jwt, err := c.jwt(ctx, audience)
	if err != nil {
		return "", false, fmt.Errorf("JWT-SVID: %w", err)
	}
	body, _, err := c.storeCall(ctx, http.MethodPost, key, "auth/"+key.mount+"/login", "", map[string]string{"role": key.role, "jwt": jwt})
	if err != nil {
		return "", false, fmt.Errorf("%w: login: %w", ErrStore, err)
	}
	value, ttl, err := parseLogin(body)
	if err != nil {
		return "", false, fmt.Errorf("%w: login: %w", ErrStore, err)
	}
	c.log.Debug("store login", "binding", b.Name, "target", b.Target, "store", key.address)
	c.mu.Lock()
	c.tokens[key] = storeToken{value: value, until: c.now().Add(ttl * 8 / 10)}
	c.mu.Unlock()
	return value, true, nil
}

// jwt fetches a JWT-SVID for audience, opening the Workload API on first
// use when no JWTSource was configured.
func (c *Client) jwt(ctx context.Context, audience string) (string, error) {
	c.mu.Lock()
	if c.jwtSource == nil {
		w, err := workloadapi.New(ctx)
		if err != nil {
			c.mu.Unlock()
			return "", fmt.Errorf("the SPIFFE Workload API: %w", err)
		}
		c.jwtSource, c.jwtCloser = w, w
	}
	source := c.jwtSource
	c.mu.Unlock()
	x, err := c.source.GetX509SVID()
	if err != nil {
		return "", err
	}
	// the same identity as the X.509-SVID that fetched the binding
	svid, err := source.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience, Subject: x.ID})
	if err != nil {
		return "", err
	}
	return svid.Marshal(), nil
}

// storeCall makes one call to a Vault-compatible store and returns the
// body of a 200. Its errors carry the status, never the body.
func (c *Client) storeCall(ctx context.Context, method string, store tokenKey, path, token string, in any) ([]byte, int, error) {
	var rd io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, 0, err
		}
		rd = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, store.address+"/v1/"+strings.TrimPrefix(path, "/"), rd)
	if err != nil {
		return nil, 0, errors.New("the binding's path is not usable") // the URL may hold the path only, but keep it out anyway
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if store.namespace != "" {
		req.Header.Set("X-Vault-Namespace", store.namespace)
	}
	resp, err := c.storeHTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // without the URL
		}
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, errors.New(resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > maxBody {
		return nil, resp.StatusCode, fmt.Errorf("the answer is larger than %d bytes", maxBody)
	}
	return body, resp.StatusCode, nil
}

// parseLogin reads a login answer: the token and its TTL.
func parseLogin(body []byte) (string, time.Duration, error) {
	var doc struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || doc.Auth.ClientToken == "" {
		return "", 0, errors.New("the answer has no token")
	}
	if doc.Auth.LeaseDuration < 0 || doc.Auth.LeaseDuration > int64(100*365*24*time.Hour/time.Second) {
		return "", 0, errors.New("the answer's lease is out of range")
	}
	return doc.Auth.ClientToken, time.Duration(doc.Auth.LeaseDuration) * time.Second, nil
}

// parseSecret reads a KV version 2 secret (vault-static) or database
// credentials (vault-dynamic).
func parseSecret(strategy string, body []byte, now time.Time) (Credential, error) {
	type userPass struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	var cred Credential
	if strategy == strategyStatic {
		var doc struct {
			Data struct {
				Data userPass `json:"data"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return Credential{}, errors.New("the answer is not a secret")
		}
		cred = Credential{Username: doc.Data.Data.Username, Password: doc.Data.Data.Password}
	} else {
		var doc struct {
			LeaseDuration int64    `json:"lease_duration"`
			Data          userPass `json:"data"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return Credential{}, errors.New("the answer is not a secret")
		}
		if doc.LeaseDuration <= 0 || doc.LeaseDuration > int64(100*365*24*time.Hour/time.Second) {
			return Credential{}, errors.New("the answer's lease is out of range")
		}
		cred = Credential{Username: doc.Data.Username, Password: doc.Data.Password, Expires: now.Add(time.Duration(doc.LeaseDuration) * time.Second)}
	}
	if cred.Username == "" || cred.Password == "" {
		return Credential{}, errors.New("the answer has no username and password")
	}
	return cred, nil
}
