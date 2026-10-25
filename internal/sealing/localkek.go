package sealing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrInsecureDevRequired refuses the local-kek sealer without --insecure-dev
// (ADR-07, §8.2 rule 9).
var ErrInsecureDevRequired = errors.New("the local-kek sealer requires --insecure-dev")

const localPrefix = "local:v1:"

// LocalKEK wraps data keys with a key read from a file. It is for local
// development only.
type LocalKEK struct {
	id  string
	key []byte
}

// NewLocalKEK reads a 32-byte key from path, which must not be readable by
// group or others.
func NewLocalKEK(path string, insecureDev bool) (*LocalKEK, error) {
	if !insecureDev {
		return nil, ErrInsecureDevRequired
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("local-kek: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("local-kek: %s must not be accessible by group or others (mode %v)", path, info.Mode().Perm())
	}
	key, err := os.ReadFile(path) //nolint:gosec // the path comes from the operator's configuration
	if err != nil {
		return nil, fmt.Errorf("local-kek: %w", err)
	}
	if len(key) != 32 {
		clear(key)
		return nil, fmt.Errorf("local-kek: %s must hold exactly 32 bytes", path)
	}
	return &LocalKEK{id: "local-kek:" + filepath.Base(path), key: key}, nil
}

// ID implements KEK.
func (k *LocalKEK) ID() string { return k.id }

// Wrap implements KEK.
func (k *LocalKEK) Wrap(_ context.Context, dek []byte) (string, error) {
	aead, err := newGCM(k.key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return localPrefix + base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, dek, nil)), nil
}

// Unwrap implements KEK.
func (k *LocalKEK) Unwrap(_ context.Context, wrapped string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wrapped, localPrefix))
	if err != nil || !strings.HasPrefix(wrapped, localPrefix) {
		return nil, errors.New("local-kek: malformed wrapped key")
	}
	aead, err := newGCM(k.key)
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.NonceSize() {
		return nil, errors.New("local-kek: malformed wrapped key")
	}
	return aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
}

// Check implements KEK.
func (k *LocalKEK) Check(ctx context.Context) error { return roundTrip(ctx, k) }
