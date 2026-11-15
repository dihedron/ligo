package adminclient

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
)

// The writes of platforms, identity providers and secret stores: what the
// Terraform provider's resources need (.specs/ligo-adminclient.md §3.4a).
//
// A write is a filing. An instance change needs one OWNER approval, by a
// person, on the instance's jurisdiction (.specs/ligo-instances.md §5), so
// the change request comes back PENDING: the package never approves it, and a
// caller that must see the instance in force waits (WaitChangeRequest) or
// reports that the change awaits approval. An instance names a bootstrap
// credential, it does not hold one: the package never logs a definition, in
// case its config holds anything a user put there.
//
// The definition's kind must be the instance's kind; the server refuses
// platform-only fields in the other two.

func (c *Client) instanceKind(what string, def Definition, kind string) error {
	if def.Kind != gen.DefinitionKind(kind) {
		return fmt.Errorf("adminclient: %s: the definition's kind is %q, not %q", what, def.Kind, kind)
	}
	return nil
}

// CreatePlatform files the creation of a platform.
func (c *Client) CreatePlatform(ctx context.Context, def Definition, o Options) (ChangeRequest, error) {
	if err := c.instanceKind("CreatePlatform", def, "Platform"); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, def, 0, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.CreatePlatformWithBody(ctx, contentJSON, b, e...)
	})
}

// UpdatePlatform files a change of a platform based on revision.
func (c *Client) UpdatePlatform(ctx context.Context, name string, def Definition, revision int64, o Options) (ChangeRequest, error) {
	if err := require("UpdatePlatform", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	if err := c.instanceKind("UpdatePlatform", def, "Platform"); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, def, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.UpdatePlatformWithBody(ctx, name, contentJSON, b, e...)
	})
}

// RetirePlatform files the retirement of a platform; ErrState while it is in use.
func (c *Client) RetirePlatform(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	if err := require("RetirePlatform", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	b, err := encode(nil, 0, o)
	if err != nil {
		return ChangeRequest{}, err
	}
	return c.filing(ctx, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RetirePlatformWithBody(ctx, name, &gen.RetirePlatformParams{ExpectedRevision: revision}, contentJSON, b, e...)
	})
}

// CreateIdentityProvider files the creation of an identity provider instance.
func (c *Client) CreateIdentityProvider(ctx context.Context, def Definition, o Options) (ChangeRequest, error) {
	if err := c.instanceKind("CreateIdentityProvider", def, "IdentityProvider"); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, def, 0, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.CreateIdentityProviderWithBody(ctx, contentJSON, b, e...)
	})
}

// UpdateIdentityProvider files a change of an identity provider based on revision.
func (c *Client) UpdateIdentityProvider(ctx context.Context, name string, def Definition, revision int64, o Options) (ChangeRequest, error) {
	if err := require("UpdateIdentityProvider", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	if err := c.instanceKind("UpdateIdentityProvider", def, "IdentityProvider"); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, def, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.UpdateIdentityProviderWithBody(ctx, name, contentJSON, b, e...)
	})
}

// RetireIdentityProvider files the retirement of an identity provider; ErrState while a platform uses it.
func (c *Client) RetireIdentityProvider(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	if err := require("RetireIdentityProvider", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	b, err := encode(nil, 0, o)
	if err != nil {
		return ChangeRequest{}, err
	}
	return c.filing(ctx, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RetireIdentityProviderWithBody(ctx, name, &gen.RetireIdentityProviderParams{ExpectedRevision: revision}, contentJSON, b, e...)
	})
}

// CreateSecretStore files the creation of a secret store instance. The change
// request is returned; the store does not exist until it is APPLIED.
func (c *Client) CreateSecretStore(ctx context.Context, def Definition, o Options) (ChangeRequest, error) {
	if err := c.instanceKind("CreateSecretStore", def, "SecretStore"); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, def, 0, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.CreateSecretStoreWithBody(ctx, contentJSON, b, e...)
	})
}

// UpdateSecretStore files a change of a secret store based on revision.
func (c *Client) UpdateSecretStore(ctx context.Context, name string, def Definition, revision int64, o Options) (ChangeRequest, error) {
	if err := require("UpdateSecretStore", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	if err := c.instanceKind("UpdateSecretStore", def, "SecretStore"); err != nil {
		return ChangeRequest{}, err
	}
	return c.file(ctx, def, revision, o, func(ctx context.Context, b io.Reader, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.UpdateSecretStoreWithBody(ctx, name, contentJSON, b, e...)
	})
}

// RetireSecretStore files the retirement of a secret store; ErrState while a platform uses it.
func (c *Client) RetireSecretStore(ctx context.Context, name string, revision int64, o Options) (ChangeRequest, error) {
	if err := require("RetireSecretStore", name, revision); err != nil {
		return ChangeRequest{}, err
	}
	b, err := encode(nil, 0, o)
	if err != nil {
		return ChangeRequest{}, err
	}
	return c.filing(ctx, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.RetireSecretStoreWithBody(ctx, name, &gen.RetireSecretStoreParams{ExpectedRevision: revision}, contentJSON, b, e...)
	})
}
