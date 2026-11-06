package adminhttp

import (
	"net/http"

	"github.com/dihedron/ligo/internal/accounts"
	"github.com/dihedron/ligo/internal/changerequests"
)

func (s *Server) accountRoutes(mux *router) {
	mux.HandleFunc("POST /v1/admin/accounts", s.registerAccount)
	mux.HandleFunc("GET /v1/admin/accounts", s.listAccounts)
	mux.HandleFunc("GET /v1/admin/accounts/{name}", s.getAccount)
	mux.HandleFunc("POST /v1/admin/accounts/{name}/retire", s.retireAccount)
}

func (s *Server) registerAccount(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	}
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := accounts.Register(r.Context(), s.DB, caller(r), b.Name, b.DisplayName)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusCreated, a)
}

func (s *Server) retireAccount(w http.ResponseWriter, r *http.Request) {
	a, err := accounts.Retire(r.Context(), s.DB, caller(r), r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, a)
}

// mayReadAccounts: resource readers, for the accounts they have a role in, and
// account_admin.
func mayReadAccounts(c changerequests.Caller) bool { return viewer(c) || c.Grants.AccountAdmin() }

func (s *Server) getAccount(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !mayReadAccounts(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer or account_admin role required")
		return
	}
	a, err := accounts.Get(r.Context(), s.DB, c, s.Config.Governance.Accounts, r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, a)
}

func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !mayReadAccounts(c) {
		problem(w, http.StatusForbidden, "forbidden", "viewer or account_admin role required")
		return
	}
	var cursor struct {
		AfterName string `json:"afterName"`
	}
	size, err := page(r, &cursor)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, more, err := accounts.List(r.Context(), s.DB, c, s.Config.Governance.Accounts, cursor.AfterName, size)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if more {
		cursor.AfterName = list[len(list)-1].Name
	}
	if list == nil {
		list = []*accounts.Account{}
	}
	reply(w, http.StatusOK, map[string]any{"items": list, "nextPageToken": token(more, cursor)})
}
