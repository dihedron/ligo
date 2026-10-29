package pluginsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const redacted = "[REDACTED]"

// Secret is a value that never prints, logs or marshals; Reveal returns it.
type Secret string

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }
func (s Secret) Reveal() string             { return string(s) }

// Credential is a bootstrap credential: held in memory only (§5.5).
type Credential struct {
	Username string
	Password Secret
}

// BootstrapCredentialConfig is an instance's config.bootstrap_credential
// (§5.5).
type BootstrapCredentialConfig struct {
	Source       string `json:"source"         yaml:"source"`
	Address      string `json:"address"        yaml:"address"`
	Namespace    string `json:"namespace"      yaml:"namespace"`
	AuthMount    string `json:"auth_mount"     yaml:"auth_mount"`
	Role         string `json:"role"           yaml:"role"`
	JWTAudience  string `json:"jwt_audience"   yaml:"jwt_audience"`
	KVPath       string `json:"kv_path"        yaml:"kv_path"`
	DBStaticRole string `json:"db_static_role" yaml:"db_static_role"`
}

// Validate checks the shape of §5.5: Vault over https, the login, and
// exactly one of kv_path and db_static_role.
func (c BootstrapCredentialConfig) Validate() error {
	if c.Source != "vault" {
		return fmt.Errorf("bootstrap_credential.source %q: only vault is supported", c.Source)
	}
	if u, err := url.Parse(c.Address); err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("bootstrap_credential.address %q: must be an https URL", c.Address)
	}
	for name, v := range map[string]string{"auth_mount": c.AuthMount, "role": c.Role, "jwt_audience": c.JWTAudience} {
		if v == "" {
			return fmt.Errorf("bootstrap_credential.%s is required", name)
		}
	}
	if (c.KVPath == "") == (c.DBStaticRole == "") {
		return errors.New("bootstrap_credential: set exactly one of kv_path and db_static_role")
	}
	return nil
}

// JWTSource gives the instance's JWT-SVID for the Vault audience;
// *InstanceSVIDSelector implements it.
type JWTSource interface {
	FetchJWT(ctx context.Context) (string, error)
}

// kvRefresh is how long a KV v2 credential, which has no lease, is kept
// before it is read again.
const kvRefresh = 5 * time.Minute

// BootstrapCredential reads an instance's privileged credential from Vault
// with its JWT-SVID, and reads it again at 80% of its lease (§5.5).
type BootstrapCredential struct {
	cfg    BootstrapCredentialConfig
	jwt    JWTSource
	client *http.Client
	now    func() time.Time

	mu    sync.Mutex
	cred  Credential
	until time.Time
}

// NewBootstrapCredential validates cfg; client carries the TLS trust for
// Vault (nil: http.DefaultClient).
func NewBootstrapCredential(cfg BootstrapCredentialConfig, jwt JWTSource, client *http.Client) (*BootstrapCredential, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &BootstrapCredential{cfg: cfg, jwt: jwt, client: client, now: time.Now}, nil
}

// Get returns the credential, read again from Vault when it is due.
func (b *BootstrapCredential) Get(ctx context.Context) (Credential, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if b.cred.Username != "" && now.Before(b.until) {
		return b.cred, nil
	}
	jwt, err := b.jwt.FetchJWT(ctx)
	if err != nil {
		return Credential{}, fmt.Errorf("bootstrap credential: %w", err)
	}
	var login struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	body, _ := json.Marshal(map[string]string{"role": b.cfg.Role, "jwt": jwt})
	if err := b.call(ctx, http.MethodPost, "auth/"+b.cfg.AuthMount+"/login", "", body, &login); err != nil {
		return Credential{}, fmt.Errorf("bootstrap credential: vault login: %w", err)
	}
	var secret struct {
		Data struct {
			Data     map[string]string `json:"data"` // KV v2
			Username string            `json:"username"`
			Password string            `json:"password"`
			TTL      int               `json:"ttl"`
		} `json:"data"`
	}
	path := b.cfg.KVPath
	if b.cfg.DBStaticRole != "" {
		// shortcut: the database secrets engine at its default mount, "database"; add a mount setting when a deployment needs another
		path = "database/static-creds/" + b.cfg.DBStaticRole
	}
	if err := b.call(ctx, http.MethodGet, path, login.Auth.ClientToken, nil, &secret); err != nil {
		return Credential{}, fmt.Errorf("bootstrap credential: reading %s: %w", path, err)
	}
	cred := Credential{Username: secret.Data.Data["username"], Password: Secret(secret.Data.Data["password"])}
	until := now.Add(kvRefresh)
	if b.cfg.DBStaticRole != "" {
		cred = Credential{Username: secret.Data.Username, Password: Secret(secret.Data.Password)}
		until = now.Add(time.Duration(secret.Data.TTL) * time.Second * 8 / 10)
	}
	if cred.Username == "" || cred.Password == "" {
		return Credential{}, fmt.Errorf("bootstrap credential: %s has no username and password", path)
	}
	b.cred, b.until = cred, until
	return b.cred, nil
}

// call sends one Vault request and decodes its JSON answer into out; errors
// carry the status only, never the body.
func (b *BootstrapCredential) call(ctx context.Context, method, path, token string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(b.cfg.Address, "/")+"/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if b.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", b.cfg.Namespace)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
