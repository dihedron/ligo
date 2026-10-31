package ui

import (
	"errors"
	"net/http"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
)

// Decision is the fragment with a change request's sides and the controls
// the user may use on it (§7.4): approve and decline for the sides they
// may decide, with a side selector when there are several, and withdraw
// for their own request; disabled in maintenance mode.
type Decision struct {
	Request     *changerequests.Request
	Eligible    []string
	CanWithdraw bool
	Disabled    bool
}

// decision builds the fragment's data for the session's user.
func (s *Server) decision(r *http.Request, cr *changerequests.Request) Decision {
	sess := session(r)
	d := Decision{Request: cr}
	if cr.Status == "PENDING" {
		d.Eligible, _ = changerequests.SelectSides(cr, sess.Caller(), s.Requests.Policy, true, "") // an error is no eligible side
		d.CanWithdraw = cr.RequestedBy == sess.Username
	}
	var on bool
	if err := s.DB.QueryRow(r.Context(), `SELECT maintenance_mode FROM system_settings`).Scan(&on); err == nil {
		d.Disabled = on
	}
	return d
}

// decide is POST /ui/change-requests/{id}/{approve,decline,withdraw}: the
// service decides, and the answer is the updated fragment (§7.4); a busy
// binding says the request stays PENDING.
func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.alert(w, r, http.StatusNotFound, "No such change request.")
		return
	}
	ctx, c := r.Context(), session(r).Caller()
	side, comment := r.PostFormValue("side"), r.PostFormValue("comment")
	var cr *changerequests.Request
	switch r.PathValue("action") {
	case "approve":
		cr, err = s.Requests.Approve(ctx, c, id, r.PostFormValue("payloadSha256"), side, comment)
	case "decline":
		if comment == "" {
			s.alert(w, r, http.StatusUnprocessableEntity, "Say why you decline the request.")
			return
		}
		cr, err = s.Requests.Decline(ctx, c, id, side, comment)
	case "withdraw":
		if err = s.Requests.Withdraw(ctx, c, id, comment); err == nil {
			cr, err = s.Requests.Get(ctx, c, id)
		}
	default:
		http.NotFound(w, r)
		return
	}
	var e *changerequests.Error
	switch {
	case changerequests.IsBusy(err):
		s.alert(w, r, http.StatusConflict, "The binding is being provisioned or reconciled right now. The change request is still PENDING: "+
			"approve it again once that operation completes, and it will be applied.")
	case errors.As(err, &e):
		s.alert(w, r, e.Status, e.Detail)
	case err != nil:
		s.fail(w, r, err)
	default:
		s.fragment(w, r, http.StatusOK, "cr-decision", s.decision(r, cr))
	}
}
