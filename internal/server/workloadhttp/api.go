package workloadhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/flows"
	"github.com/dihedron/ligo/internal/jcs"
	"github.com/dihedron/ligo/internal/resolution"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Resolver is the resolution cache (§4.5).
type Resolver interface {
	Resolve(caller spiffeid.ID, target, platformType string) ([]resolution.Binding, error)
	TargetFlows(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]flows.Flow, error)
}

// Item is a binding as a workload receives it (§3.6).
type Item struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	Source       string          `json:"source"`
	Target       string          `json:"target"`
	AccessLevel  string          `json:"accessLevel"`
	PlatformType string          `json:"platformType"`
	Platform     string          `json:"platform"`
	Revision     int64           `json:"revision"`
	Auth         json.RawMessage `json:"auth"`
	Spec         json.RawMessage `json:"spec"`
	UpdatedAt    time.Time       `json:"updatedAt"`
}

// BindingFlows are the effective flows of one binding (§3.6, ADR-16).
type BindingFlows struct {
	Binding string       `json:"binding"`
	Source  string       `json:"source"`
	Target  string       `json:"target"`
	Flows   []flows.Flow `json:"flows"`
}

// Document is a workload response with its canonical bytes and ETag, the
// same for REST and gRPC (§7.1).
type Document[T any] struct {
	Caller string
	Items  []T
	Body   []byte // RFC 8785 canonical JSON
	ETag   string // "sha256:<hex>" of Body, quoted
}

func document[T any](caller spiffeid.ID, items []T) (*Document[T], error) {
	if items == nil {
		items = []T{}
	}
	body, err := jcs.Canonicalize(map[string]any{"callerSpiffeId": caller.String(), "items": items})
	if err != nil {
		return nil, fmt.Errorf("workloadhttp: canonical JSON: %w", err)
	}
	sum := sha256.Sum256(body)
	return &Document[T]{Caller: caller.String(), Items: items, Body: body, ETag: `"sha256:` + hex.EncodeToString(sum[:]) + `"`}, nil
}

// Bindings resolves the caller's bindings, optionally to target and of
// platformType (§4.5 rule 5).
func (s *Server) Bindings(caller spiffeid.ID, target, platformType string) (*Document[Item], []resolution.Binding, error) {
	list, err := s.Cache.Resolve(caller, target, platformType)
	if err != nil {
		return nil, nil, err
	}
	items := make([]Item, len(list))
	for i, b := range list {
		items[i] = Item{ID: b.ID.String(), Name: b.Name, Source: b.SourceName, Target: b.TargetName, AccessLevel: b.AccessLevel,
			PlatformType: b.PlatformType, Platform: b.Platform, Revision: b.ActiveRevision, Auth: b.AuthConfig, Spec: b.Spec,
			UpdatedAt: b.UpdatedAt.UTC()}
	}
	doc, err := document(caller, items)
	return doc, list, err
}

// Flows resolves the caller's bindings like Bindings, then adds each one's
// effective flows: its target's within the platform's allowed endpoints,
// its platform's, its secret store's and ligo's (§4.5 rule 6, ADR-16).
func (s *Server) Flows(ctx context.Context, caller spiffeid.ID, target string) (*Document[BindingFlows], []resolution.Binding, error) {
	list, err := s.Cache.Resolve(caller, target, "")
	if err != nil {
		return nil, nil, err
	}
	ids := make([]uuid.UUID, len(list))
	for i, b := range list {
		ids[i] = b.ID
	}
	byBinding, err := s.Cache.TargetFlows(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	items := make([]BindingFlows, len(list))
	for i, b := range list {
		store := b.SecretStoreInstance
		items[i] = BindingFlows{Binding: b.Name, Source: b.SourceName, Target: b.TargetName,
			Flows: flows.Effective(b.TargetName, s.Rules.Allow[b.Platform].Within(byBinding[b.ID]), b.Platform, s.Rules.PlatformFlows[b.Platform],
				store, s.Rules.StoreFlows[store], s.Rules.Ligo)}
	}
	doc, err := document(caller, items)
	return doc, list, err
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bindings", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		doc, list, err := s.Bindings(Caller(r), q.Get("target"), q.Get("platformType"))
		reply(s, w, r, doc, list, err)
	})
	mux.HandleFunc("GET /v1/flows", func(w http.ResponseWriter, r *http.Request) {
		doc, list, err := s.Flows(r.Context(), Caller(r), r.URL.Query().Get("target"))
		reply(s, w, r, doc, list, err)
	})
	return mux
}

// reply logs the resolution (T-13) and answers 200 with the canonical body,
// 304 for a matching If-None-Match, or 503 while the cache is stale.
func reply[T any](s *Server, w http.ResponseWriter, r *http.Request, doc *Document[T], list []resolution.Binding, err error) {
	if err != nil {
		if !errors.Is(err, resolution.ErrStale) {
			s.Logger.Error("resolution", "request_id", requestID(r), "caller", Caller(r).String(), "error", err)
		}
		w.Header().Set("Retry-After", "5")
		problem(w, http.StatusServiceUnavailable, "unavailable", "bindings cannot be resolved now")
		return
	}
	s.logResolution(r, list, doc.ETag)
	w.Header().Set("ETag", doc.ETag)
	w.Header().Set("Cache-Control", "private, no-store")
	if r.Header.Get("If-None-Match") == doc.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(doc.Body) //nolint:gosec // G705: canonical JSON, served as application/json with nosniff, never HTML
}

// logResolution records who received which bindings at which revisions
// (§7.1 controls, T-13).
func (s *Server) logResolution(r *http.Request, list []resolution.Binding, etag string) {
	served := make([]string, len(list))
	for i, b := range list {
		served[i] = fmt.Sprintf("%s@r%d", b.ID, b.ActiveRevision)
	}
	s.Logger.Info("resolution", "request_id", requestID(r), "caller", Caller(r).String(), "path", r.URL.Path, "bindings", served, "etag", etag)
}
