package sealing

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"uuid"
)

var sc = Context{BindingID: uuid.MustParse("019286f8-7c80-7b2e-9f1a-4b5a6c7d8e9f"), Revision: 4, Attempt: 5, Stage: StageTarget}

// fakeTransit is a Vault Transit stand-in: JWT login and encrypt/decrypt
// with one AES-256-GCM key.
type fakeTransit struct {
	t           *testing.T
	aead        cipher.AEAD
	mu          sync.Mutex
	logins      int
	token       string
	unavailable bool
}

func newFakeTransit(t *testing.T) (*fakeTransit, *httptest.Server) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	f := &fakeTransit{t: t, aead: aead}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeTransit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unavailable {
		http.Error(w, `{"errors":["Vault is sealed"]}`, http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("X-Vault-Namespace") != "prod" {
		http.Error(w, `{"errors":["namespace"]}`, http.StatusBadRequest)
		return
	}
	var body map[string]string
	_ = json.NewDecoder(r.Body).Decode(&body)
	reply := func(data map[string]any) { _ = json.NewEncoder(w).Encode(data) }
	switch r.URL.Path {
	case "/v1/auth/jwt-spiffe/login":
		if body["role"] != "ligo-sealer" || body["jwt"] != "jwt-for-https://vault.prod.internal" {
			http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
			return
		}
		f.logins++
		f.token = "token-" + string(rune('0'+f.logins))
		reply(map[string]any{"auth": map[string]any{"client_token": f.token}})
		return
	}
	if r.Header.Get("X-Vault-Token") != f.token || f.token == "" {
		http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/v1/transit/encrypt/ligo-interstage":
		plain, _ := base64.StdEncoding.DecodeString(body["plaintext"])
		nonce := make([]byte, f.aead.NonceSize())
		_, _ = rand.Read(nonce)
		ct := f.aead.Seal(nonce, nonce, plain, nil)
		reply(map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(ct)}})
	case "/v1/transit/decrypt/ligo-interstage":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(body["ciphertext"], "vault:v1:"))
		if err != nil || len(raw) < f.aead.NonceSize() {
			http.Error(w, `{"errors":["invalid ciphertext"]}`, http.StatusBadRequest)
			return
		}
		plain, err := f.aead.Open(nil, raw[:f.aead.NonceSize()], raw[f.aead.NonceSize():], nil)
		if err != nil {
			http.Error(w, `{"errors":["cipher: message authentication failed"]}`, http.StatusBadRequest)
			return
		}
		reply(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plain)}})
	default:
		http.NotFound(w, r)
	}
}

type jwtSource struct{}

func (jwtSource) FetchJWT(_ context.Context, audience string) (string, error) {
	return "jwt-for-" + audience, nil
}

func newTransit(t *testing.T) (*fakeTransit, *TransitKEK) {
	f, srv := newFakeTransit(t)
	kek, err := NewTransitKEK(TransitConfig{
		Address: srv.URL, Namespace: "prod", AuthMount: "jwt-spiffe", Role: "ligo-sealer",
		JWTAudience: "https://vault.prod.internal", Mount: "transit", KeyName: "ligo-interstage",
	}, jwtSource{}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return f, kek
}

func newLocal(t *testing.T) *LocalKEK {
	path := filepath.Join(t.TempDir(), "kek")
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	if err := os.WriteFile(path, key, 0o600); err != nil {
		t.Fatal(err)
	}
	kek, err := NewLocalKEK(path, true)
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

func keks(t *testing.T) map[string]KEK {
	_, transit := newTransit(t)
	return map[string]KEK{"transit": transit, "local": newLocal(t)}
}

func TestRoundTrip(t *testing.T) {
	ctx := context.Background()
	for name, kek := range keks(t) {
		s := NewSealer(kek)
		secret := []byte("s3cr3t-password")
		env, err := s.Seal(ctx, sc, secret)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Contains([]byte(env.Ciphertext), secret) || env.KEK != kek.ID() || env.V != 1 {
			t.Errorf("%s: unexpected envelope %+v", name, env)
		}
		if want := sc.aad(env.WrappedDEK); env.AAD != want {
			t.Errorf("%s: aad %q, want %q", name, env.AAD, want)
		}
		got, err := s.Unseal(ctx, sc, env)
		if err != nil || string(got) != string(secret) {
			t.Errorf("%s: Unseal = (%q, %v)", name, got, err)
		}
		if err := kek.Check(ctx); err != nil {
			t.Errorf("%s: Check: %v", name, err)
		}
	}
}

// TestContextBinding checks that an envelope opens only in the workflow
// context it was sealed for, and only with its own wrapped key (ADR-07).
func TestContextBinding(t *testing.T) {
	ctx := context.Background()
	for name, kek := range keks(t) {
		s := NewSealer(kek)
		env, err := s.Seal(ctx, sc, []byte("secret"))
		if err != nil {
			t.Fatal(err)
		}
		other, err := s.Seal(ctx, sc, []byte("other"))
		if err != nil {
			t.Fatal(err)
		}
		if env.Nonce == other.Nonce || env.WrappedDEK == other.WrappedDEK {
			t.Errorf("%s: nonce or DEK reused", name)
		}
		wrong := map[string]Context{}
		c := sc
		c.BindingID = uuid.NewV7()
		wrong["binding"] = c
		c = sc
		c.Revision++
		wrong["revision"] = c
		c = sc
		c.Attempt++
		wrong["attempt"] = c
		c = sc
		c.Stage = StageIdentity
		wrong["stage"] = c
		for field, c := range wrong {
			if _, err := s.Unseal(ctx, c, env); !errors.Is(err, ErrSealedSecretUnavailable) {
				t.Errorf("%s: other %s: %v", name, field, err)
			}
		}
		swapped := env
		swapped.WrappedDEK = other.WrappedDEK
		if _, err := s.Unseal(ctx, sc, swapped); !errors.Is(err, ErrSealedSecretUnavailable) {
			t.Errorf("%s: swapped wrappedDek: %v", name, err)
		}
		swapped = env
		swapped.Ciphertext = other.Ciphertext
		if _, err := s.Unseal(ctx, sc, swapped); !errors.Is(err, ErrSealedSecretUnavailable) {
			t.Errorf("%s: swapped ciphertext: %v", name, err)
		}
		edited := env
		edited.AAD = "anything" // never trusted
		if got, err := s.Unseal(ctx, sc, edited); err != nil || string(got) != "secret" {
			t.Errorf("%s: edited aad: (%q, %v)", name, got, err)
		}
	}
}

func TestInvalidStage(t *testing.T) {
	c := sc
	c.Stage = "SECRET_STORE"
	if _, err := NewSealer(newLocal(t)).Seal(context.Background(), c, []byte("x")); err == nil {
		t.Error("sealed for a stage that emits no static secret")
	}
}

// TestTransitUnavailable is the unit part of AC-09.
func TestTransitUnavailable(t *testing.T) {
	ctx := context.Background()
	f, kek := newTransit(t)
	s := NewSealer(kek)
	env, err := s.Seal(ctx, sc, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.unavailable = true
	f.mu.Unlock()
	if _, err := s.Unseal(ctx, sc, env); !errors.Is(err, ErrSealedSecretUnavailable) {
		t.Errorf("Unseal with Transit down: %v", err)
	}
	if _, err := s.Seal(ctx, sc, []byte("secret")); err == nil {
		t.Error("Seal succeeded with Transit down")
	}
	if err := kek.Check(ctx); err == nil {
		t.Error("Check succeeded with Transit down")
	}
}

// TestTransitRelogin checks that an expired token is replaced once.
func TestTransitRelogin(t *testing.T) {
	ctx := context.Background()
	f, kek := newTransit(t)
	if err := kek.Check(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.token = "revoked"
	f.mu.Unlock()
	if err := kek.Check(ctx); err != nil {
		t.Fatalf("after token expiry: %v", err)
	}
	if f.logins != 2 {
		t.Errorf("logins = %d, want 2", f.logins)
	}
}

func TestTransitLoginRefused(t *testing.T) {
	_, srv := newFakeTransit(t)
	kek, err := NewTransitKEK(TransitConfig{
		Address: srv.URL, Namespace: "prod", AuthMount: "jwt-spiffe", Role: "wrong",
		JWTAudience: "https://vault.prod.internal", Mount: "transit", KeyName: "ligo-interstage",
	}, jwtSource{}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := kek.Check(context.Background()); err == nil || strings.Contains(err.Error(), "jwt-for") {
		t.Errorf("login refused: %v (the JWT must never appear in errors)", err)
	}
}

func TestTransitConfig(t *testing.T) {
	for _, cfg := range []TransitConfig{
		{},
		{Address: "http://vault:8200", AuthMount: "a", Role: "r", JWTAudience: "x", Mount: "m", KeyName: "k"},
		{Address: "https://vault:8200", AuthMount: "a", Role: "r", JWTAudience: "x", Mount: "m"},
	} {
		if _, err := NewTransitKEK(cfg, jwtSource{}, nil); err == nil {
			t.Errorf("%+v accepted", cfg)
		}
	}
}

// TestLocalKEKRefusals covers ADR-07: local-kek only with --insecure-dev,
// and a private 32-byte key file.
func TestLocalKEKRefusals(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	_ = os.WriteFile(good, make([]byte, 32), 0o600)
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, make([]byte, 16), 0o600)
	open := filepath.Join(dir, "open")
	_ = os.WriteFile(open, make([]byte, 32), 0o600)
	if err := os.Chmod(open, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalKEK(good, false); !errors.Is(err, ErrInsecureDevRequired) {
		t.Errorf("without --insecure-dev: %v", err)
	}
	for _, path := range []string{short, open, filepath.Join(dir, "missing")} {
		if _, err := NewLocalKEK(path, true); err == nil {
			t.Errorf("%s accepted", filepath.Base(path))
		}
	}
}
