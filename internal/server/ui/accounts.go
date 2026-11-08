package ui

import (
	"net/http"

	"github.com/dihedron/ligo/internal/accounts"
	"github.com/dihedron/ligo/internal/authz"
	"github.com/dihedron/ligo/internal/changerequests"
)

// readsAccounts mirrors the admin API: resource readers, for the accounts they
// have a role in, and account_admin.
func readsAccounts(gs authz.Grants) bool { return gs.Viewer() || gs.AccountAdmin() }

// showsAccounts says whether the menu links to the page: ligo with no
// charter.accounts has no accounts to manage.
func (s *Server) showsAccounts(gs authz.Grants) bool {
	return s.Config.Charter.Accounts != nil && readsAccounts(gs)
}

// accountsReadable answers 403 to anyone else.
func (s *Server) accountsReadable(w http.ResponseWriter, r *http.Request) bool {
	if !readsAccounts(session(r).Grants) {
		s.fail(w, r, &changerequests.Error{Status: http.StatusForbidden, Slug: "forbidden", Detail: "A viewer or account_admin role is required to see this page."})
		return false
	}
	return true
}

// AccountsPage is the accounts list's data.
type AccountsPage struct {
	Accounts  []*accounts.Account
	Next      string
	CanChange bool
}

func (s *Server) accountList(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReadable(w, r) {
		return
	}
	c := session(r).Caller()
	list, more, err := accounts.List(r.Context(), s.DB, c, s.Config.Charter.Accounts, r.URL.Query().Get("after"), pageSize)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := AccountsPage{Accounts: list, CanChange: c.Grants.AccountAdmin()}
	if more {
		d.Next = list[len(list)-1].Name
	}
	p := s.frame(r, "Accounts", "/ui/accounts")
	p.Content = d
	s.page(w, r, http.StatusOK, "accounts", p)
}

// AccountPage is an account's data, with its counts.
type AccountPage struct {
	Account   *accounts.Account
	CanChange bool
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	if !s.accountsReadable(w, r) {
		return
	}
	c := session(r).Caller()
	a, err := accounts.Get(r.Context(), s.DB, c, s.Config.Charter.Accounts, r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := s.frame(r, a.Name, "/ui/accounts")
	p.Content = AccountPage{Account: a, CanChange: c.Grants.AccountAdmin()}
	s.page(w, r, http.StatusOK, "account", p)
}

func (s *Server) accountRegister(w http.ResponseWriter, r *http.Request) {
	a, err := accounts.Register(r.Context(), s.DB, session(r).Caller(), r.PostFormValue("name"), r.PostFormValue("displayName"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	redirect(w, "/ui/accounts/"+a.Name)
}

func (s *Server) accountRetire(w http.ResponseWriter, r *http.Request) {
	a, err := accounts.Retire(r.Context(), s.DB, session(r).Caller(), r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	redirect(w, "/ui/accounts/"+a.Name)
}
