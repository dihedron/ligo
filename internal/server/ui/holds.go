package ui

import (
	"errors"
	"net/http"
	"strings"

	"github.com/dihedron/ligo/internal/bindings"
	"github.com/dihedron/ligo/internal/changerequests"
)

// openHolds are the holds the caller sees, for the dashboard's panel.
func (s *Server) openHolds(r *http.Request) ([]bindings.Hold, error) {
	holds, _, err := s.Bindings.ListHolds(r.Context(), session(r).Caller(), bindings.HoldFilter{Limit: 20})
	return holds, err
}

// liftHold is POST /ui/holds/{id}/lift: a person who approves a side of the
// removed binding lets its owner ask for it again
// (.specs/ligo-managed-resources.md §3.5).
func (s *Server) liftHold(w http.ResponseWriter, r *http.Request) {
	comment := strings.TrimSpace(r.PostFormValue("comment"))
	if comment == "" {
		s.alert(w, r, http.StatusUnprocessableEntity, "Say why the binding may be asked for again.")
		return
	}
	err := s.Bindings.LiftHold(r.Context(), session(r).Caller(), r.PathValue("id"), comment)
	var e *changerequests.Error
	switch {
	case errors.As(err, &e):
		s.alert(w, r, e.Status, e.Detail)
	case err != nil:
		s.fail(w, r, err)
	default:
		redirect(w, "/ui/bindings")
	}
}
