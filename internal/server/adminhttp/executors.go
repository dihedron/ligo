package adminhttp

import (
	"cmp"
	"encoding/json"
	"net/http"
	"slices"
	"time"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/store"
	"github.com/jackc/pgx/v5"
)

// executorDTO is an executor's pending workflows of one application version,
// or, with none pending, only its live sessions.
type executorDTO struct {
	Executor           string     `json:"executor"`
	ApplicationVersion string     `json:"applicationVersion,omitempty"`
	Pending            int        `json:"pending"`
	OldestPending      *time.Time `json:"oldestPending,omitempty"`
	LiveSessions       int        `json:"liveSessions"`
	Self               bool       `json:"self"`
}

// listExecutors shows what a replica gone for good left behind (§10.2).
func (s *Server) listExecutors(w http.ResponseWriter, r *http.Request) {
	if !viewer(caller(r)) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	pending, err := s.Workflows.Pending(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sessions, err := store.Sessions(r.Context(), s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	self := s.Workflows.ExecutorID()
	type key struct{ executor, version string }
	rows := map[key]*executorDTO{}
	shown := map[string]bool{}
	for _, wf := range pending {
		k := key{wf.ExecutorID, wf.ApplicationVersion}
		row := rows[k]
		if row == nil {
			row = &executorDTO{Executor: wf.ExecutorID, ApplicationVersion: wf.ApplicationVersion, LiveSessions: sessions[wf.ExecutorID], Self: wf.ExecutorID == self}
			rows[k] = row
			shown[wf.ExecutorID] = true
		}
		row.Pending++
		if row.OldestPending == nil || wf.CreatedAt.Before(*row.OldestPending) {
			row.OldestPending = &wf.CreatedAt
		}
	}
	for id, n := range sessions {
		if !shown[id] {
			rows[key{executor: id}] = &executorDTO{Executor: id, LiveSessions: n, Self: id == self}
		}
	}
	items := make([]executorDTO, 0, len(rows))
	for _, row := range rows {
		items = append(items, *row)
	}
	slices.SortFunc(items, func(a, b executorDTO) int {
		return cmp.Or(cmp.Compare(a.Executor, b.Executor), cmp.Compare(a.ApplicationVersion, b.ApplicationVersion))
	})
	reply(w, http.StatusOK, map[string]any{"items": items})
}

// recoverExecutor re-enqueues the pending workflows of a replica gone for
// good, for any replica of this application version to run (§10.2). It has
// no force: a live replica would run them a second time, and plugin calls
// are not checkpointed.
func (s *Server) recoverExecutor(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !c.Grants.FullAccess() {
		problem(w, http.StatusForbidden, "forbidden", "admin.full_access required")
		return
	}
	id := r.PathValue("id")
	if id == s.Workflows.ExecutorID() {
		problem(w, http.StatusConflict, "executor-self", "this replica is executor "+id+": it recovers its own workflows when it starts")
		return
	}
	sessions, err := store.Sessions(r.Context(), s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if sessions[id] > 0 {
		problem(w, http.StatusConflict, "executor-alive", "executor "+id+" still has database sessions; stop the replica, or end its sessions if its host is lost")
		return
	}
	pending, err := s.Workflows.Pending(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids := []string{}
	otherVersions := 0
	for _, wf := range pending {
		switch {
		case wf.ExecutorID != id:
		case wf.ApplicationVersion == s.Workflows.ApplicationVersion():
			ids = append(ids, wf.ID)
		default:
			otherVersions++
		}
	}
	if len(ids) > 0 {
		// audited first: resuming again after a failure is safe
		snapshot, err := json.Marshal(map[string]any{"executor": id, "workflows": ids, "otherVersions": otherVersions})
		if err == nil {
			err = pgx.BeginFunc(r.Context(), s.DB, func(tx pgx.Tx) error {
				_, err := audit.Append(r.Context(), tx, audit.Entry{Action: "SYSTEM_EXECUTOR_RECOVERED", Actor: c.ID(), ActorGroups: c.Principal.Groups, Snapshot: snapshot})
				return err
			})
		}
		if err == nil {
			err = s.Workflows.Resume(r.Context(), ids)
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	reply(w, http.StatusOK, map[string]any{"executor": id, "recovered": len(ids), "otherVersions": otherVersions})
}
