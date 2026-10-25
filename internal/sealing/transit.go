package sealing

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TransitConfig is secret_sealing.vault_transit (§8.1). It works with Vault
// and OpenBao (EXT-17).
type TransitConfig struct {
	Address     string `yaml:"address"`
	Namespace   string `yaml:"namespace"`
	AuthMount   string `yaml:"auth_mount"`
	Role        string `yaml:"role"`
	JWTAudience string `yaml:"jwt_audience"`
	Mount       string `yaml:"mount"`
	KeyName     string `yaml:"key_name"`
}

// JWTFetcher provides the JWT-SVID ligo logs in to Vault with.
type JWTFetcher interface {
	FetchJWT(ctx context.Context, audience string) (string, error)
}

// TransitKEK wraps data keys with Vault Transit.
type TransitKEK struct {
	cfg    TransitConfig
	jwt    JWTFetcher
	client *http.Client

	mu    sync.Mutex
	token string
}

// errForbidden is a 403 from Vault: the token expired or was revoked.
var errForbidden = errors.New("permission denied")

// NewTransitKEK returns a Transit KEK. client may be nil.
func NewTransitKEK(cfg TransitConfig, jwt JWTFetcher, client *http.Client) (*TransitKEK, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("vault_transit.address %q must be an https URL", cfg.Address)
	}
	for key, value := range map[string]string{
		"auth_mount": cfg.AuthMount, "role": cfg.Role, "jwt_audience": cfg.JWTAudience,
		"mount": cfg.Mount, "key_name": cfg.KeyName,
	} {
		if value == "" {
			return nil, fmt.Errorf("vault_transit.%s is required", key)
		}
	}
	if client == nil {
		client = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		}
	}
	cfg.Address = strings.TrimSuffix(cfg.Address, "/")
	return &TransitKEK{cfg: cfg, jwt: jwt, client: client}, nil
}

// ID implements KEK.
func (k *TransitKEK) ID() string { return "vault-transit:" + k.cfg.KeyName }

// Wrap implements KEK.
func (k *TransitKEK) Wrap(ctx context.Context, dek []byte) (string, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	in := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(dek)}
	if err := k.call(ctx, "/v1/"+k.cfg.Mount+"/encrypt/"+k.cfg.KeyName, in, &out); err != nil {
		return "", fmt.Errorf("vault transit encrypt: %w", err)
	}
	if !strings.HasPrefix(out.Data.Ciphertext, "vault:v") {
		return "", errors.New("vault transit encrypt: unexpected ciphertext")
	}
	return out.Data.Ciphertext, nil
}

// Unwrap implements KEK.
func (k *TransitKEK) Unwrap(ctx context.Context, wrapped string) ([]byte, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := k.call(ctx, "/v1/"+k.cfg.Mount+"/decrypt/"+k.cfg.KeyName, map[string]string{"ciphertext": wrapped}, &out); err != nil {
		return nil, fmt.Errorf("vault transit decrypt: %w", err)
	}
	dek, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault transit decrypt: %w", err)
	}
	return dek, nil
}

// Check implements KEK.
func (k *TransitKEK) Check(ctx context.Context) error { return roundTrip(ctx, k) }

// call posts in to path with a token, logging in first if needed and once
// more if Vault refuses the token.
func (k *TransitKEK) call(ctx context.Context, path string, in, out any) error {
	for attempt := 0; ; attempt++ {
		token, err := k.currentToken(ctx)
		if err != nil {
			return err
		}
		err = k.post(ctx, path, token, in, out)
		if !errors.Is(err, errForbidden) || attempt > 0 {
			return err
		}
		k.mu.Lock()
		if k.token == token {
			k.token = ""
		}
		k.mu.Unlock()
	}
}

func (k *TransitKEK) currentToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" {
		return k.token, nil
	}
	jwt, err := k.jwt.FetchJWT(ctx, k.cfg.JWTAudience)
	if err != nil {
		return "", fmt.Errorf("vault login: fetch JWT-SVID: %w", err)
	}
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := k.post(ctx, "/v1/auth/"+k.cfg.AuthMount+"/login", "", map[string]string{"role": k.cfg.Role, "jwt": jwt}, &out); err != nil {
		return "", fmt.Errorf("vault login: %w", err)
	}
	if out.Auth.ClientToken == "" {
		return "", errors.New("vault login: no token in the response")
	}
	k.token = out.Auth.ClientToken
	return k.token, nil
}

// post sends a JSON request. Errors carry Vault's status and messages, never
// the request body.
func (k *TransitKEK) post(ctx context.Context, path, token string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.cfg.Address+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if k.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", k.cfg.Namespace)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(data, &e)
		if resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("%w (HTTP 403): %s", errForbidden, strings.Join(e.Errors, "; "))
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.Join(e.Errors, "; "))
	}
	return json.Unmarshal(data, out)
}
