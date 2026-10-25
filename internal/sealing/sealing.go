// Package sealing seals the static secrets passed between provisioning
// stages, so that DBOS checkpoints never hold them in plaintext (ADR-07,
// Appendix C).
package sealing

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"uuid"
)

// ErrSealedSecretUnavailable makes the attempt fail terminally with
// SEALED_SECRET_UNAVAILABLE (ADR-07).
var ErrSealedSecretUnavailable = errors.New("SEALED_SECRET_UNAVAILABLE")

// Stages that emit a static secret.
const (
	StageIdentity = "IDENTITY"
	StageTarget   = "TARGET"
)

// KEK wraps data keys with a durable key-encryption key.
type KEK interface {
	// ID names the key in envelopes, such as "vault-transit:ligo-interstage".
	ID() string
	Wrap(ctx context.Context, dek []byte) (string, error)
	Unwrap(ctx context.Context, wrapped string) ([]byte, error)
	// Check verifies that the key is available (§8.2, startup step 4).
	Check(ctx context.Context) error
}

// Envelope is the sealed form of a secret (Appendix C).
type Envelope struct {
	V          int    `json:"v"`
	KEK        string `json:"kek"`
	WrappedDEK string `json:"wrappedDek"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	// AAD is recorded for diagnosis only: Unseal recomputes it.
	AAD string `json:"aad"`
}

// Context is the trusted workflow context an envelope is bound to.
type Context struct {
	BindingID uuid.UUID
	Revision  int64
	Attempt   int64
	Stage     string
}

func (c Context) aad(wrappedDEK string) string {
	return fmt.Sprintf("%s|r%d|a%d|%s|%s", c.BindingID, c.Revision, c.Attempt, c.Stage, wrappedDEK)
}

// Sealer seals and unseals secrets with a KEK.
type Sealer struct {
	kek KEK
}

// NewSealer returns a sealer using kek.
func NewSealer(kek KEK) *Sealer { return &Sealer{kek: kek} }

// Seal encrypts plaintext for the workflow context sc (Appendix C, seal
// steps 1 to 4).
func (s *Sealer) Seal(ctx context.Context, sc Context, plaintext []byte) (Envelope, error) {
	if sc.Stage != StageIdentity && sc.Stage != StageTarget {
		return Envelope{}, fmt.Errorf("sealing: stage %q emits no static secret", sc.Stage)
	}
	dek := make([]byte, 32)
	defer clear(dek)
	nonce := make([]byte, 12)
	if _, err := rand.Read(dek); err != nil {
		return Envelope{}, fmt.Errorf("sealing: data key: %w", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, fmt.Errorf("sealing: nonce: %w", err)
	}
	wrapped, err := s.kek.Wrap(ctx, dek)
	if err != nil {
		return Envelope{}, fmt.Errorf("sealing: wrap data key: %w", err)
	}
	aead, err := newGCM(dek)
	if err != nil {
		return Envelope{}, err
	}
	aad := sc.aad(wrapped)
	return Envelope{
		V:          1,
		KEK:        s.kek.ID(),
		WrappedDEK: wrapped,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, []byte(aad))),
		AAD:        aad,
	}, nil
}

// Unseal opens env in the workflow context sc. Every failure wraps
// ErrSealedSecretUnavailable.
func (s *Sealer) Unseal(ctx context.Context, sc Context, env Envelope) ([]byte, error) {
	fail := func(what string, err error) ([]byte, error) {
		return nil, fmt.Errorf("%w: %s: %w", ErrSealedSecretUnavailable, what, err)
	}
	if env.V != 1 || env.KEK != s.kek.ID() {
		return fail("envelope", fmt.Errorf("version %d with key %q cannot be opened with %q", env.V, env.KEK, s.kek.ID()))
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return fail("nonce", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return fail("ciphertext", err)
	}
	dek, err := s.kek.Unwrap(ctx, env.WrappedDEK)
	if err != nil {
		return fail("unwrap data key", err)
	}
	defer clear(dek)
	aead, err := newGCM(dek)
	if err != nil {
		return fail("data key", err)
	}
	if len(nonce) != aead.NonceSize() {
		return fail("nonce", errors.New("wrong size"))
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(sc.aad(env.WrappedDEK)))
	if err != nil {
		return fail("open", err)
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("sealing: %w", err)
	}
	return cipher.NewGCM(block)
}

// roundTrip wraps and unwraps a random key, to check that a KEK works.
func roundTrip(ctx context.Context, kek KEK) error {
	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		return err
	}
	wrapped, err := kek.Wrap(ctx, probe)
	if err != nil {
		return err
	}
	got, err := kek.Unwrap(ctx, wrapped)
	if err != nil {
		return err
	}
	if string(got) != string(probe) {
		return errors.New("unwrapped key differs from the wrapped one")
	}
	return nil
}
