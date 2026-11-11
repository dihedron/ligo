package sealing

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
)

// Signer signs audit checkpoints with a key the database does not hold
// (§4.3): whoever can write to the database cannot forge a checkpoint.
type Signer interface {
	// ID names the key, as recorded in audit_checkpoints.key_id.
	ID() string
	// Sign returns the key's ID and the signature of msg.
	Sign(ctx context.Context, msg []byte) (keyID, sig string, err error)
	// Verify returns nil, ErrBadSignature, or ErrSignerUnavailable when the
	// key needed cannot be had right now.
	Verify(ctx context.Context, keyID string, msg []byte, sig string) error
	// PublicKeys returns the key's public versions, "1", "2"..., for an
	// export to carry (ligo audit export).
	PublicKeys(ctx context.Context) (map[string]ed25519.PublicKey, error)
}

var (
	// ErrBadSignature: the signature does not match the message under this key.
	ErrBadSignature = errors.New("bad signature")
	// ErrSignerUnavailable: the key cannot be reached; nothing is known about the signature.
	ErrSignerUnavailable = errors.New("signing key unavailable")
)

// TransitSigner signs with an ed25519 key of Vault Transit, through the
// sealing KEK's connection and login, and verifies locally with the key's
// public versions, read once each.
type TransitSigner struct {
	kek *TransitKEK
	key string

	mu   sync.Mutex
	pubs map[string]ed25519.PublicKey // by version, "1", "2"...
}

// NewTransitSigner signs with the Transit key named key, in kek's mount.
func NewTransitSigner(kek *TransitKEK, key string) *TransitSigner {
	return &TransitSigner{kek: kek, key: key, pubs: map[string]ed25519.PublicKey{}}
}

// ID implements Signer.
func (s *TransitSigner) ID() string { return "vault-transit:" + s.key }

// Sign implements Signer.
func (s *TransitSigner) Sign(ctx context.Context, msg []byte) (string, string, error) {
	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	in := map[string]string{"input": base64.StdEncoding.EncodeToString(msg)}
	if err := s.kek.call(ctx, "/v1/"+s.kek.cfg.Mount+"/sign/"+s.key, in, &out); err != nil {
		return "", "", fmt.Errorf("%w: vault transit sign: %w", ErrSignerUnavailable, err)
	}
	if !strings.HasPrefix(out.Data.Signature, "vault:v") {
		return "", "", errors.New("vault transit sign: unexpected signature")
	}
	return s.ID(), out.Data.Signature, nil
}

// Verify implements Signer.
func (s *TransitSigner) Verify(ctx context.Context, keyID string, msg []byte, sig string) error {
	version, raw, ok := splitVaultSignature(sig)
	if keyID != s.ID() || !ok {
		return ErrBadSignature
	}
	pub, err := s.public(ctx, version)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, msg, raw) {
		return ErrBadSignature
	}
	return nil
}

// public returns a version's public key, reading the key's versions from
// Vault when it has not seen this one: after a rotation, or at startup.
func (s *TransitSigner) public(ctx context.Context, version string) (ed25519.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if pub, ok := s.pubs[version]; ok {
		return pub, nil
	}
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	pub, ok := s.pubs[version]
	if !ok {
		return nil, ErrBadSignature // a version Vault never had
	}
	return pub, nil
}

// PublicKeys implements Signer: every version, read from Vault afresh.
func (s *TransitSigner) PublicKeys(ctx context.Context) (map[string]ed25519.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(ctx); err != nil {
		return nil, err
	}
	return maps.Clone(s.pubs), nil
}

// load reads the key's public versions into s.pubs; s.mu is held.
func (s *TransitSigner) load(ctx context.Context) error {
	var out struct {
		Data struct {
			Type string `json:"type"`
			Keys map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if err := s.kek.call(ctx, "/v1/"+s.kek.cfg.Mount+"/keys/"+s.key, nil, &out); err != nil {
		return fmt.Errorf("%w: vault transit keys: %w", ErrSignerUnavailable, err)
	}
	if out.Data.Type != "ed25519" {
		return fmt.Errorf("vault transit key %s is %q, not ed25519", s.key, out.Data.Type)
	}
	for v, k := range out.Data.Keys {
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return fmt.Errorf("vault transit key %s: version %s has no ed25519 public key", s.key, v)
		}
		s.pubs[v] = pub
	}
	return nil
}

// splitVaultSignature parses "vault:v<N>:<base64>".
func splitVaultSignature(sig string) (version string, raw []byte, ok bool) {
	return splitSignature("vault", sig)
}

// splitSignature parses "<scheme>:v<N>:<base64>".
func splitSignature(scheme, sig string) (version string, raw []byte, ok bool) {
	rest, ok := strings.CutPrefix(sig, scheme+":v")
	if !ok {
		return "", nil, false
	}
	version, b64, ok := strings.Cut(rest, ":")
	if !ok || version == "" {
		return "", nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	return version, raw, err == nil
}

// LocalSigner signs with an ed25519 key derived from the local KEK: for
// local development only, like the KEK itself.
type LocalSigner struct {
	id  string
	key ed25519.PrivateKey
}

// NewLocalSigner derives its key from kek, so the same file gives the same key.
func NewLocalSigner(kek *LocalKEK) *LocalSigner {
	seed, err := hkdf.Key(sha256.New, kek.key, nil, "ligo audit checkpoint signing key", ed25519.SeedSize)
	if err != nil {
		panic(err) // only for a length SHA-256 cannot give
	}
	return &LocalSigner{id: kek.ID(), key: ed25519.NewKeyFromSeed(seed)}
}

// ID implements Signer.
func (s *LocalSigner) ID() string { return s.id }

// Sign implements Signer.
func (s *LocalSigner) Sign(_ context.Context, msg []byte) (string, string, error) {
	return s.id, "local:v1:" + base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, msg)), nil
}

// Verify implements Signer.
func (s *LocalSigner) Verify(_ context.Context, keyID string, msg []byte, sig string) error {
	b64, ok := strings.CutPrefix(sig, "local:v1:")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if keyID != s.id || !ok || err != nil || !ed25519.Verify(s.key.Public().(ed25519.PublicKey), msg, raw) {
		return ErrBadSignature
	}
	return nil
}

// PublicKeys implements Signer: one version, "1".
func (s *LocalSigner) PublicKeys(context.Context) (map[string]ed25519.PublicKey, error) {
	return map[string]ed25519.PublicKey{"1": s.key.Public().(ed25519.PublicKey)}, nil
}

// KeySet verifies checkpoint signatures with public keys alone, as an
// auditor does with an exported file: by key ID, then by version.
type KeySet map[string]map[string]ed25519.PublicKey

// Verify returns nil or ErrBadSignature: a key ID or version the set does
// not hold cannot verify.
func (k KeySet) Verify(keyID string, msg []byte, sig string) error {
	version, raw, ok := splitSignature("vault", sig)
	if !ok {
		version, raw, ok = splitSignature("local", sig)
	}
	pub := k[keyID][version]
	if !ok || pub == nil || !ed25519.Verify(pub, msg, raw) {
		return ErrBadSignature
	}
	return nil
}
