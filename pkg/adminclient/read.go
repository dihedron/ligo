package adminclient

import (
	"context"
	"fmt"
	"iter"
	"net/http"
	"time"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
	"github.com/google/uuid"
)

// The reads of the admin API: sources, targets, bindings, the catalog,
// change requests and accounts. Every list is an iterator over all the pages
// (PageSize is the size of each, 0 for the server's default) and has a
// ...Page form for one page.

// SourceFilter selects sources.
type SourceFilter struct {
	Jurisdiction string // a jurisdiction pattern
	TrustDomain  string
	State        string // ACTIVE, DEPRECATED or RETIRED; empty: every state but RETIRED
	Label        string // key=value
	Q            string // matched in names, display names and descriptions
	PageSize     int
}

func (f SourceFilter) params(token string) *gen.ListSourcesParams {
	return &gen.ListSourcesParams{Jurisdiction: opt[string](f.Jurisdiction), TrustDomain: opt[string](f.TrustDomain), State: opt[gen.ListSourcesParamsState](f.State),
		Label: opt[string](f.Label), Q: opt[string](f.Q), PageSize: optSize(f.PageSize), PageToken: opt[string](token)}
}

// ListSourcesPage is one page of the sources the caller sees.
func (c *Client) ListSourcesPage(ctx context.Context, f SourceFilter, pageToken string) (Page[Source], error) {
	r, err := fetch[gen.SourcePage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListSources(ctx, f.params(pageToken), e...)
	})
	return Page[Source]{r.Items, deref(r.NextPageToken)}, err
}

// ListSources iterates over the sources the caller sees.
func (c *Client) ListSources(ctx context.Context, f SourceFilter) iter.Seq2[Source, error] {
	return pages(func(t string) (Page[Source], error) { return c.ListSourcesPage(ctx, f, t) })
}

// GetSource is a source with its last 20 audit entries.
func (c *Client) GetSource(ctx context.Context, name string) (SourceDetail, error) {
	return fetch[SourceDetail](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetSource(ctx, name, e...)
	})
}

// SourceAuditPage is one page of a source's audit entries, newest first.
func (c *Client) SourceAuditPage(ctx context.Context, name string, pageSize int, pageToken string) (Page[AuditEntry], error) {
	r, err := fetch[gen.AuditPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.SourceAudit(ctx, name, &gen.SourceAuditParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[AuditEntry]{r.Items, deref(r.NextPageToken)}, err
}

// SourceAudit iterates over a source's audit entries, newest first.
func (c *Client) SourceAudit(ctx context.Context, name string, pageSize int) iter.Seq2[AuditEntry, error] {
	return pages(func(t string) (Page[AuditEntry], error) { return c.SourceAuditPage(ctx, name, pageSize, t) })
}

// ListSourceBindingsPage is one page of the bindings of a source.
func (c *Client) ListSourceBindingsPage(ctx context.Context, name string, pageSize int, pageToken string) (Page[Binding], error) {
	r, err := fetch[gen.BindingPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListSourceBindings(ctx, name, &gen.ListSourceBindingsParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[Binding]{r.Items, deref(r.NextPageToken)}, err
}

// ListSourceBindings iterates over the bindings of a source.
func (c *Client) ListSourceBindings(ctx context.Context, name string, pageSize int) iter.Seq2[Binding, error] {
	return pages(func(t string) (Page[Binding], error) { return c.ListSourceBindingsPage(ctx, name, pageSize, t) })
}

// TargetFilter selects targets.
type TargetFilter struct {
	Q            string
	Platform     string
	PlatformType string
	Jurisdiction string // a jurisdiction pattern
	Label        string // key=value
	State        string // ACTIVE, DEPRECATED or RETIRED; empty: every state but RETIRED
	PageSize     int
}

// ListTargetsPage is one page of the targets the caller owns or administers.
func (c *Client) ListTargetsPage(ctx context.Context, f TargetFilter, pageToken string) (Page[Target], error) {
	p := &gen.ListTargetsParams{Q: opt[string](f.Q), Platform: opt[string](f.Platform), PlatformType: opt[string](f.PlatformType), Jurisdiction: opt[string](f.Jurisdiction),
		Label: opt[string](f.Label), State: opt[gen.ListTargetsParamsState](f.State), PageSize: optSize(f.PageSize), PageToken: opt[string](pageToken)}
	r, err := fetch[gen.TargetPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListTargets(ctx, p, e...)
	})
	return Page[Target]{r.Items, deref(r.NextPageToken)}, err
}

// ListTargets iterates over the targets the caller owns or administers.
func (c *Client) ListTargets(ctx context.Context, f TargetFilter) iter.Seq2[Target, error] {
	return pages(func(t string) (Page[Target], error) { return c.ListTargetsPage(ctx, f, t) })
}

// GetTarget is a target with its last 20 audit entries.
func (c *Client) GetTarget(ctx context.Context, name string) (TargetDetail, error) {
	return fetch[TargetDetail](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetTarget(ctx, name, e...)
	})
}

// TargetAuditPage is one page of a target's audit entries, newest first.
func (c *Client) TargetAuditPage(ctx context.Context, name string, pageSize int, pageToken string) (Page[AuditEntry], error) {
	r, err := fetch[gen.AuditPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.TargetAudit(ctx, name, &gen.TargetAuditParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[AuditEntry]{r.Items, deref(r.NextPageToken)}, err
}

// TargetAudit iterates over a target's audit entries, newest first.
func (c *Client) TargetAudit(ctx context.Context, name string, pageSize int) iter.Seq2[AuditEntry, error] {
	return pages(func(t string) (Page[AuditEntry], error) { return c.TargetAuditPage(ctx, name, pageSize, t) })
}

// ListTargetBindingsPage is one page of the bindings on a target.
func (c *Client) ListTargetBindingsPage(ctx context.Context, name string, pageSize int, pageToken string) (Page[Binding], error) {
	r, err := fetch[gen.BindingPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListTargetBindings(ctx, name, &gen.ListTargetBindingsParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[Binding]{r.Items, deref(r.NextPageToken)}, err
}

// ListTargetBindings iterates over the bindings on a target.
func (c *Client) ListTargetBindings(ctx context.Context, name string, pageSize int) iter.Seq2[Binding, error] {
	return pages(func(t string) (Page[Binding], error) { return c.ListTargetBindingsPage(ctx, name, pageSize, t) })
}

// BindingFilter selects bindings.
type BindingFilter struct {
	Source, Target, AccessLevel, Platform, PlatformType, Phase, TrustDomain, Realm string
	Jurisdiction                                                                   string     // a pattern, matched against any of the binding's three jurisdictions
	ExpiringBefore                                                                 *time.Time // only bindings that expire before it
	PropagationPending                                                             *bool
	PageSize                                                                       int
}

// ListBindingsPage is one page of the bindings the caller sees.
func (c *Client) ListBindingsPage(ctx context.Context, f BindingFilter, pageToken string) (Page[Binding], error) {
	p := &gen.ListBindingsParams{Source: opt[string](f.Source), Target: opt[string](f.Target), AccessLevel: opt[string](f.AccessLevel), Platform: opt[string](f.Platform),
		PlatformType: opt[string](f.PlatformType), Phase: opt[string](f.Phase), TrustDomain: opt[string](f.TrustDomain), Realm: opt[string](f.Realm),
		Jurisdiction: opt[string](f.Jurisdiction), ExpiringBefore: f.ExpiringBefore, PropagationPending: optBool(f.PropagationPending),
		PageSize: optSize(f.PageSize), PageToken: opt[string](pageToken)}
	r, err := fetch[gen.BindingPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListBindings(ctx, p, e...)
	})
	return Page[Binding]{r.Items, deref(r.NextPageToken)}, err
}

// ListBindings iterates over the bindings the caller sees.
func (c *Client) ListBindings(ctx context.Context, f BindingFilter) iter.Seq2[Binding, error] {
	return pages(func(t string) (Page[Binding], error) { return c.ListBindingsPage(ctx, f, t) })
}

// GetBinding is a binding with its stage states (no secrets) and its last 20 audit entries.
func (c *Client) GetBinding(ctx context.Context, name string) (BindingDetail, error) {
	return fetch[BindingDetail](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetBinding(ctx, name, e...)
	})
}

// BindingAuditPage is one page of a binding's audit entries, newest first.
func (c *Client) BindingAuditPage(ctx context.Context, name string, pageSize int, pageToken string) (Page[AuditEntry], error) {
	r, err := fetch[gen.AuditPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.BindingAudit(ctx, name, &gen.BindingAuditParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[AuditEntry]{r.Items, deref(r.NextPageToken)}, err
}

// BindingAudit iterates over a binding's audit entries, newest first.
func (c *Client) BindingAudit(ctx context.Context, name string, pageSize int) iter.Seq2[AuditEntry, error] {
	return pages(func(t string) (Page[AuditEntry], error) { return c.BindingAuditPage(ctx, name, pageSize, t) })
}

// GetBindingFlows is the network flows the binding's workload needs, in order of declaration.
func (c *Client) GetBindingFlows(ctx context.Context, name string) ([]NetworkFlow, error) {
	r, err := fetch[gen.Flows](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetBindingFlows(ctx, name, e...)
	})
	return flowsOf(r), err
}

func flowsOf(f gen.Flows) []NetworkFlow {
	if f.NetworkFlows == nil {
		return nil
	}
	return *f.NetworkFlows
}

// CatalogFilter selects the targets of the catalog.
type CatalogFilter struct {
	Q, Platform, PlatformType string
	Jurisdiction              string // a pattern
	Label                     string // key=value
	IncludeDeprecated         bool
	ForSource                 string // only targets the charter allows for this source; those bound to it are marked
	PageSize                  int
}

// SearchCatalogPage is one page of the targets the caller could request.
func (c *Client) SearchCatalogPage(ctx context.Context, f CatalogFilter, pageToken string) (Page[CatalogTarget], error) {
	p := &gen.SearchCatalogParams{Q: opt[string](f.Q), Platform: opt[string](f.Platform), PlatformType: opt[string](f.PlatformType), Jurisdiction: opt[string](f.Jurisdiction),
		Label: opt[string](f.Label), ForSource: opt[string](f.ForSource), PageSize: optSize(f.PageSize), PageToken: opt[string](pageToken)}
	if f.IncludeDeprecated {
		s := gen.SearchCatalogParamsStateDEPRECATED
		p.State = &s
	}
	r, err := fetch[gen.CatalogTargetPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.SearchCatalog(ctx, p, e...)
	})
	return Page[CatalogTarget]{r.Items, deref(r.NextPageToken)}, err
}

// SearchCatalog iterates over the targets the caller could request.
func (c *Client) SearchCatalog(ctx context.Context, f CatalogFilter) iter.Seq2[CatalogTarget, error] {
	return pages(func(t string) (Page[CatalogTarget], error) { return c.SearchCatalogPage(ctx, f, t) })
}

// GetCatalogTarget is a target with the charter outcome for each of the caller's sources.
func (c *Client) GetCatalogTarget(ctx context.Context, name string) (CatalogDetail, error) {
	return fetch[CatalogDetail](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetCatalogTarget(ctx, name, e...)
	})
}

// GetCatalogTargetFlows is the flows a binding to the target would need, before any binding exists.
func (c *Client) GetCatalogTargetFlows(ctx context.Context, name string) ([]NetworkFlow, error) {
	r, err := fetch[gen.Flows](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetCatalogTargetFlows(ctx, name, e...)
	})
	return flowsOf(r), err
}

// ListCatalogSourcesPage is one page of the sources visible to the caller beyond their own.
func (c *Client) ListCatalogSourcesPage(ctx context.Context, pageSize int, pageToken string) (Page[CatalogSource], error) {
	r, err := fetch[gen.CatalogSourcePage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListCatalogSources(ctx, &gen.ListCatalogSourcesParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[CatalogSource]{r.Items, deref(r.NextPageToken)}, err
}

// ListCatalogSources iterates over the sources visible to the caller beyond their own.
func (c *Client) ListCatalogSources(ctx context.Context, pageSize int) iter.Seq2[CatalogSource, error] {
	return pages(func(t string) (Page[CatalogSource], error) { return c.ListCatalogSourcesPage(ctx, pageSize, t) })
}

// ChangeRequestFilter selects change requests.
type ChangeRequestFilter struct {
	Status       string // PENDING, APPLIED, ...
	ResourceType string // SOURCE, TARGET, BINDING, PLATFORM, IDENTITY_PROVIDER or SECRET_STORE
	ResourceName string
	Realm        string
	Jurisdiction string
	AwaitingMe   *bool // only requests that wait for the caller's decision
	PageSize     int
}

// ListChangeRequestsPage is one page of the change requests the caller sees.
func (c *Client) ListChangeRequestsPage(ctx context.Context, f ChangeRequestFilter, pageToken string) (Page[ChangeRequest], error) {
	p := &gen.ListChangeRequestsParams{Status: opt[gen.ChangeRequestStatus](f.Status), ResourceType: opt[gen.ResourceType](f.ResourceType), ResourceName: opt[string](f.ResourceName),
		Realm: opt[string](f.Realm), Jurisdiction: opt[string](f.Jurisdiction), AwaitingMe: f.AwaitingMe, PageSize: optSize(f.PageSize), PageToken: opt[string](pageToken)}
	r, err := fetch[gen.ChangeRequestPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListChangeRequests(ctx, p, e...)
	})
	return Page[ChangeRequest]{r.Items, deref(r.NextPageToken)}, err
}

// ListChangeRequests iterates over the change requests the caller sees.
func (c *Client) ListChangeRequests(ctx context.Context, f ChangeRequestFilter) iter.Seq2[ChangeRequest, error] {
	return pages(func(t string) (Page[ChangeRequest], error) { return c.ListChangeRequestsPage(ctx, f, t) })
}

// GetChangeRequest is a change request with its sides and, for an update, a diff against the current revision.
func (c *Client) GetChangeRequest(ctx context.Context, id string) (ChangeRequest, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return ChangeRequest{}, fmt.Errorf("adminclient: change request ID %q: %w", id, err)
	}
	return fetch[ChangeRequest](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetChangeRequest(ctx, u, e...)
	})
}

// ListAccountsPage is one page of the accounts the caller sees.
func (c *Client) ListAccountsPage(ctx context.Context, pageSize int, pageToken string) (Page[Account], error) {
	r, err := fetch[gen.AccountPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListAccounts(ctx, &gen.ListAccountsParams{PageSize: optSize(pageSize), PageToken: opt[string](pageToken)}, e...)
	})
	return Page[Account]{r.Items, deref(r.NextPageToken)}, err
}

// ListAccounts iterates over the accounts the caller sees.
func (c *Client) ListAccounts(ctx context.Context, pageSize int) iter.Seq2[Account, error] {
	return pages(func(t string) (Page[Account], error) { return c.ListAccountsPage(ctx, pageSize, t) })
}

// GetAccount is an account with its counts of sources, targets and bindings.
func (c *Client) GetAccount(ctx context.Context, name string) (Account, error) {
	return fetch[Account](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.GetAccount(ctx, name, e...)
	})
}

// HoldFilter selects holds: the open ones, or every one with All.
type HoldFilter struct {
	Binding  string // by binding name
	All      bool   // lifted holds too
	PageSize int
}

// ListHoldsPage is one page of the holds on bindings the caller sees.
func (c *Client) ListHoldsPage(ctx context.Context, f HoldFilter, pageToken string) (Page[Hold], error) {
	p := &gen.ListHoldsParams{Binding: opt[string](f.Binding), PageSize: optSize(f.PageSize), PageToken: opt[string](pageToken)}
	if f.All {
		all := gen.All
		p.State = &all
	}
	r, err := fetch[gen.HoldPage](ctx, c, func(ctx context.Context, e ...gen.RequestEditorFn) (*http.Response, error) {
		return c.gen.ListHolds(ctx, p, e...)
	})
	return Page[Hold]{r.Items, deref(r.NextPageToken)}, err
}

// ListHolds iterates over the holds on bindings the caller sees. A hold
// stops everyone from creating the binding again until a person lifts it
// (a decision of people: the package has no method for it).
func (c *Client) ListHolds(ctx context.Context, f HoldFilter) iter.Seq2[Hold, error] {
	return pages(func(t string) (Page[Hold], error) { return c.ListHoldsPage(ctx, f, t) })
}
