package ui

import (
	"errors"
	"net/http"
	"slices"
	"uuid"

	"github.com/dihedron/ligo/internal/changerequests"
)

// Decision is the fragment with a change request's sides and the controls
// the user may use on it (§7.4): approve and decline for the sides they
// may decide, with a side selector when there are several, and withdraw
// for their own request; disabled in maintenance mode. For an applied
// break-glass change (ADR-12): ratify for the sides they may ratify, and
// revert while the change is still open on its binding.
type Decision struct {
	Request     *changerequests.Request
	Eligible    []string
	CanWithdraw bool
	Disabled    bool
	Ratifiable  []string
	CanRevert   bool
}

// decision builds the fragment's data for the session's user.
func (s *Server) decision(r *http.Request, cr *changerequests.Request) Decision {
	sess := session(r)
	d := Decision{Request: cr}
	if cr.Status == "PENDING" {
		d.Eligible, _ = changerequests.SelectSides(cr, sess.Caller(), s.Requests.Policy, true, "") // an error is no eligible side
		d.CanWithdraw = cr.RequestedBy == sess.Username
	}
	if cr.Kind == changerequests.KindBreakGlass && cr.Status == "APPLIED" {
		s.breakGlassControls(r, cr, &d)
	}
	var on bool
	if err := s.DB.QueryRow(r.Context(), `SELECT maintenance_mode FROM system_settings`).Scan(&on); err == nil {
		d.Disabled = on
	}
	return d
}

// breakGlassControls fills in ratify and revert; the services check again.
// A change is open while its binding references it; an emergency delete
// has no binding left, and is ratified but never reverted (ADR-12).
func (s *Server) breakGlassControls(r *http.Request, cr *changerequests.Request, d *Decision) {
	c := session(r).Caller()
	var open bool
	if err := s.DB.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM bindings WHERE break_glass_cr_id = $1)`, cr.ID).Scan(&open); err != nil {
		s.Logger.Error("ui: break-glass state", "error", err)
		return
	}
	if open || cr.Operation == "DELETE" {
		for _, sd := range cr.Sides {
			if _, err := changerequests.RatifiableSides(cr, c, sd.Name); err == nil { // the service's own rules, side by side
				d.Ratifiable = append(d.Ratifiable, sd.Name)
			}
		}
	}
	d.CanRevert = open && cr.Operation != "DELETE" && (cr.RequestedBy == c.ID() ||
		slices.ContainsFunc(cr.Sides, func(sd changerequests.Side) bool { return c.Grants.CanApprove(sd.Scope) }))
}

// decide is POST /ui/change-requests/{id}/{approve,decline,withdraw,ratify,revert}: the
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
	case "ratify":
		if comment == "" {
			s.alert(w, r, http.StatusUnprocessableEntity, "Say why you ratify the change.")
			return
		}
		cr, err = s.Bindings.Ratify(ctx, c, id, side, comment)
	case "revert":
		if _, err = s.Bindings.RevertNow(ctx, c, id); err == nil {
			cr, err = s.Requests.Get(ctx, c, id) // the break-glass change, now closed
		}
	default:
		http.NotFound(w, r)
		return
	}
	var e *changerequests.Error
	switch {
	case changerequests.IsBusy(err) && r.PathValue("action") == "revert":
		s.alert(w, r, http.StatusConflict, "The binding is being provisioned or reconciled right now: revert it again once that operation completes.")
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
