package adminhttp

import (
	"encoding/json"
	"net/http"

	"github.com/dihedron/ligo/internal/preview"
)

func (s *Server) governanceRoutes(mux *router) {
	mux.HandleFunc("GET /v1/admin/governance", s.getGovernance)
	mux.HandleFunc("POST /v1/admin/governance/evaluate", s.evaluate)
}

// getGovernance: the policy in force, as the canonical JSON its SHA-256
// is computed over (§8.2).
func (s *Server) getGovernance(w http.ResponseWriter, r *http.Request) {
	if !viewer(caller(r)) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	p := s.Requests.Policy
	canonical, err := p.Canonical()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, map[string]any{"policy": json.RawMessage(canonical), "sha256": p.SHA256()})
}

// evaluate is the dry run of a planned creation (internal/preview).
func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !viewer(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	b, err := body(r)
	var e *preview.Evaluation
	if err == nil {
		e, err = (&preview.Evaluator{Sources: s.Sources, Targets: s.Targets, Bindings: s.Bindings, Requests: s.Requests}).Evaluate(r.Context(), c, b)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, e)
}
