package sealing

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newTransitSigner(t *testing.T) (*fakeTransit, *TransitSigner) {
	f, kek := newTransit(t)
	return f, NewTransitSigner(kek, "ligo-audit")
}

func signers(t *testing.T) map[string]Signer {
	_, transit := newTransitSigner(t)
	return map[string]Signer{"transit": transit, "local": NewLocalSigner(newLocal(t))}
}

func TestSignVerify(t *testing.T) {
	ctx := context.Background()
	for name, s := range signers(t) {
		t.Run(name, func(t *testing.T) {
			msg := []byte(`{"auditId":42,"entryHash":"ab"}`)
			keyID, sig, err := s.Sign(ctx, msg)
			if err != nil {
				t.Fatal(err)
			}
			if keyID != s.ID() {
				t.Errorf("key id %q, want %q", keyID, s.ID())
			}
			if err := s.Verify(ctx, keyID, msg, sig); err != nil {
				t.Errorf("verify: %v", err)
			}
			// another message, another key id, a forged signature
			if err := s.Verify(ctx, keyID, []byte(`{"auditId":43,"entryHash":"ab"}`), sig); !errors.Is(err, ErrBadSignature) {
				t.Errorf("another message: %v, want ErrBadSignature", err)
			}
			if err := s.Verify(ctx, "vault-transit:other", msg, sig); !errors.Is(err, ErrBadSignature) {
				t.Errorf("another key id: %v, want ErrBadSignature", err)
			}
			prefix := sig[:strings.LastIndex(sig, ":")+1]
			if err := s.Verify(ctx, keyID, msg, prefix+"AAAA"); !errors.Is(err, ErrBadSignature) {
				t.Errorf("forged: %v, want ErrBadSignature", err)
			}
		})
	}
}

// After a rotation, old checkpoints still verify and new ones use the new version.
func TestTransitSignerRotation(t *testing.T) {
	ctx := context.Background()
	f, s := newTransitSigner(t)
	msg := []byte("checkpoint")
	_, old, err := s.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(ctx, s.ID(), msg, old); err != nil { // caches v1
		t.Fatal(err)
	}
	f.rotate()
	_, sig, err := s.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sig, "vault:v2:") {
		t.Fatalf("signature %q, want version 2", sig)
	}
	for _, x := range []string{old, sig} {
		if err := s.Verify(ctx, s.ID(), msg, x); err != nil {
			t.Errorf("verify %.9s: %v", x, err)
		}
	}
}

// Verification needs Vault only for a key version it has not seen: once
// cached, a sealed Vault does not stop it. An unseen version with Vault
// away cannot be verified, which is not the same as a bad signature.
func TestTransitSignerUnavailable(t *testing.T) {
	ctx := context.Background()
	f, s := newTransitSigner(t)
	msg := []byte("checkpoint")
	_, sig, err := s.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(ctx, s.ID(), msg, sig); err != nil {
		t.Fatal(err)
	}
	f.rotate()
	_, sig2, err := s.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.unavailable = true
	f.mu.Unlock()
	if err := s.Verify(ctx, s.ID(), msg, sig); err != nil {
		t.Errorf("cached version with Vault sealed: %v", err)
	}
	if err := s.Verify(ctx, s.ID(), msg, sig2); !errors.Is(err, ErrSignerUnavailable) {
		t.Errorf("unseen version with Vault sealed: %v, want ErrSignerUnavailable", err)
	}
	if _, _, err := s.Sign(ctx, msg); !errors.Is(err, ErrSignerUnavailable) {
		t.Errorf("sign with Vault sealed: %v, want ErrSignerUnavailable", err)
	}
}

// The local signer's key comes from the local KEK: the same file gives the
// same key, so checkpoints survive a restart.
func TestLocalSignerStable(t *testing.T) {
	ctx := context.Background()
	kek := newLocal(t)
	msg := []byte("checkpoint")
	keyID, sig, err := NewLocalSigner(kek).Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewLocalSigner(kek).Verify(ctx, keyID, msg, sig); err != nil {
		t.Error(err)
	}
	if err := NewLocalSigner(newLocal(t)).Verify(ctx, keyID, msg, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("another KEK: %v, want ErrBadSignature", err)
	}
}

// Answers from Vault that are not an ed25519 key's, and signatures that do
// not parse, are refused, never trusted.
func TestTransitSignerMalformed(t *testing.T) {
	ctx := context.Background()
	msg := []byte("checkpoint")
	for _, c := range []struct{ misbehave, want string }{
		{"type", "not ed25519"},
		{"public", "has no ed25519 public key"},
	} {
		t.Run(c.misbehave, func(t *testing.T) {
			f, s := newTransitSigner(t)
			_, sig, err := s.Sign(ctx, msg)
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			f.misbehave = c.misbehave
			f.mu.Unlock()
			if err := s.Verify(ctx, s.ID(), msg, sig); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("verify: %v, want %q", err, c.want)
			}
		})
	}
	t.Run("signature", func(t *testing.T) {
		f, s := newTransitSigner(t)
		f.mu.Lock()
		f.misbehave = "signature"
		f.mu.Unlock()
		if _, _, err := s.Sign(ctx, msg); err == nil || errors.Is(err, ErrSignerUnavailable) {
			t.Errorf("sign: %v, want an unexpected signature", err)
		}
	})
	t.Run("unparsed", func(t *testing.T) {
		_, s := newTransitSigner(t)
		for _, sig := range []string{"nope", "vault:v1", "vault:v:AAAA", "vault:v1:!!!", "vault:v9:AAAA"} {
			if err := s.Verify(ctx, s.ID(), msg, sig); !errors.Is(err, ErrBadSignature) {
				t.Errorf("%q: %v, want ErrBadSignature", sig, err)
			}
		}
	})
}

// A KeySet built from PublicKeys verifies what the signer signed, across a
// rotation, with no signer at hand; anything else is ErrBadSignature.
func TestKeySet(t *testing.T) {
	ctx := context.Background()
	f, transit := newTransitSigner(t)
	msg := []byte("checkpoint")
	sigs := map[Signer][]string{}
	_, v1, err := transit.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	f.rotate()
	_, v2, err := transit.Sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	sigs[transit] = []string{v1, v2}
	local := NewLocalSigner(newLocal(t))
	_, l1, _ := local.Sign(ctx, msg)
	sigs[local] = []string{l1}

	keys := KeySet{}
	for s := range sigs {
		pubs, err := s.PublicKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		keys[s.ID()] = pubs
	}
	if len(keys[transit.ID()]) != 2 {
		t.Errorf("transit public keys: %d versions, want 2", len(keys[transit.ID()]))
	}
	for s, list := range sigs {
		for _, sig := range list {
			if err := keys.Verify(s.ID(), msg, sig); err != nil {
				t.Errorf("%s %.9s: %v", s.ID(), sig, err)
			}
			if err := keys.Verify(s.ID(), []byte("other"), sig); !errors.Is(err, ErrBadSignature) {
				t.Errorf("another message: %v", err)
			}
		}
	}
	for _, bad := range []struct{ keyID, sig string }{
		{"nobody", v1},                       // unknown key
		{transit.ID(), "vault:v9:" + v1[9:]}, // unknown version
		{transit.ID(), "nope"},               // unparsed
		{local.ID(), v1},                     // another key's signature
	} {
		if err := keys.Verify(bad.keyID, msg, bad.sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s %.12s: %v, want ErrBadSignature", bad.keyID, bad.sig, err)
		}
	}
	f.mu.Lock() // PublicKeys asks Vault afresh: sealed, it cannot answer
	f.unavailable = true
	f.mu.Unlock()
	if _, err := transit.PublicKeys(ctx); !errors.Is(err, ErrSignerUnavailable) {
		t.Errorf("PublicKeys with Vault away: %v, want ErrSignerUnavailable", err)
	}
}
