// SPDX-License-Identifier: MIT

package adminclient

import (
	"context"
	"iter"
	"net/http"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
)

// The reads of platforms, identity providers and secret stores: what the
// Terraform provider's data sources need (.specs/ligo-adminclient.md §3.4a).
// Their writes are in instances_write.go.
//
// Every viewer sees an instance's summary and, for a platform, its health.
// Only a person who may file or decide on its jurisdiction also gets Revision
// and Definition: for anyone else they are nil, and a data source must say
// so. Quarantined is true for an instance whose stored row does not verify,
// which is not in force.

// ListPlatforms is the platforms in force, with their health, by name.
func (c *Client) ListPlatforms(ctx context.Context) ([]Platform, error) {
	r, err := fetch[gen.PlatformPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListPlatforms(ctx, e...)
	})
	return r.Items, err
}

// GetPlatform is a platform with its health and the forms of its plugin; a
// quarantined one is shown, as stored, to those who may file its fix.
func (c *Client) GetPlatform(ctx context.Context, name string) (Platform, error) {
	return fetch[Platform](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetPlatform(ctx, name, e...)
	})
}

// PlatformAuditPage is one page of a platform's audit entries, newest first.
func (c *Client) PlatformAuditPage(ctx context.Context, name string, pageSize int, pageToken string) (Page[AuditEntry], error) {
	r, err := fetch[gen.AuditPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.PlatformAudit(ctx, name, &gen.PlatformAuditParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[AuditEntry]{r.Items, deref(r.NextPageToken)}, err
}

// PlatformAudit iterates over a platform's audit entries, newest first.
func (c *Client) PlatformAudit(ctx context.Context, name string, pageSize int) iter.Seq2[AuditEntry, error] {
	return pages(func(t string) (Page[AuditEntry], error) { return c.PlatformAuditPage(ctx, name, pageSize, t) })
}

// ListIdentityProviders is the identity provider instances in force, by name.
func (c *Client) ListIdentityProviders(ctx context.Context) ([]Instance, error) {
	r, err := fetch[gen.InstancePage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListIdentityProviders(ctx, e...)
	})
	return r.Items, err
}

// GetIdentityProvider is an identity provider instance.
func (c *Client) GetIdentityProvider(ctx context.Context, name string) (Instance, error) {
	return fetch[Instance](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetIdentityProvider(ctx, name, e...)
	})
}

// IdentityProviderAuditPage is one page of an identity provider's audit entries, newest first.
func (c *Client) IdentityProviderAuditPage(ctx context.Context, name string, pageSize int, pageToken string) (Page[AuditEntry], error) {
	r, err := fetch[gen.AuditPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.IdentityProviderAudit(ctx, name, &gen.IdentityProviderAuditParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[AuditEntry]{r.Items, deref(r.NextPageToken)}, err
}

// IdentityProviderAudit iterates over an identity provider's audit entries, newest first.
func (c *Client) IdentityProviderAudit(ctx context.Context, name string, pageSize int) iter.Seq2[AuditEntry, error] {
	return pages(func(t string) (Page[AuditEntry], error) { return c.IdentityProviderAuditPage(ctx, name, pageSize, t) })
}

// ListSecretStores is the secret store instances in force, by name.
func (c *Client) ListSecretStores(ctx context.Context) ([]Instance, error) {
	r, err := fetch[gen.InstancePage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListSecretStores(ctx, e...)
	})
	return r.Items, err
}

// GetSecretStore is a secret store instance.
func (c *Client) GetSecretStore(ctx context.Context, name string) (Instance, error) {
	return fetch[Instance](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetSecretStore(ctx, name, e...)
	})
}

// SecretStoreAuditPage is one page of a secret store's audit entries, newest first.
func (c *Client) SecretStoreAuditPage(ctx context.Context, name string, pageSize int, pageToken string) (Page[AuditEntry], error) {
	r, err := fetch[gen.AuditPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.SecretStoreAudit(ctx, name, &gen.SecretStoreAuditParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[AuditEntry]{r.Items, deref(r.NextPageToken)}, err
}

// SecretStoreAudit iterates over a secret store's audit entries, newest first.
func (c *Client) SecretStoreAudit(ctx context.Context, name string, pageSize int) iter.Seq2[AuditEntry, error] {
	return pages(func(t string) (Page[AuditEntry], error) { return c.SecretStoreAuditPage(ctx, name, pageSize, t) })
}
