package adminhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/jackc/pgx/v5"
)

func (s *Server) opsRoutes(mux *router) {
	mux.HandleFunc("GET /v1/admin/maintenance", s.getMaintenance)
	mux.HandleFunc("PUT /v1/admin/maintenance", s.putMaintenance)
	mux.HandleFunc("GET /v1/admin/audit/verify", s.verifyAudit)
	for kind := range scopeQueries { // one route each: a {kind} wildcard would overlap /v1/admin/catalog/targets/{name}
		mux.HandleFunc("GET /v1/admin/"+kind+"/{name}/audit", s.resourceAudit)
	}
}

type maintenance struct {
	MaintenanceMode   bool       `json:"maintenanceMode"`
	Reason            string     `json:"reason"`
	ChangedBy         string     `json:"changedBy"`
	ChangedAt         *time.Time `json:"changedAt"`
	InFlight          int        `json:"inFlight"`
	PropagationQueued int        `json:"propagationQueued"`
}

// getMaintenance: the setting, and what the drain of §10.3 waits for.
func (s *Server) getMaintenance(w http.ResponseWriter, r *http.Request) {
	if !viewer(caller(r)) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	var m maintenance
	err := s.DB.QueryRow(r.Context(), `SELECT maintenance_mode, coalesce(maintenance_reason, ''), coalesce(changed_by, ''), changed_at,
		(SELECT count(*) FROM bindings WHERE phase IN ('PROVISIONING', 'DELETING')), (SELECT count(*) FROM binding_propagation_queue)
		FROM system_settings`).Scan(&m.MaintenanceMode, &m.Reason, &m.ChangedBy, &m.ChangedAt, &m.InFlight, &m.PropagationQueued)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	reply(w, http.StatusOK, m)
}

// putMaintenance turns maintenance mode on or off, for admin.full_access;
// the UPDATE waits for the changes that already passed the check (§10.3).
func (s *Server) putMaintenance(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !c.Grants.FullAccess() {
		problem(w, http.StatusForbidden, "forbidden", "admin.full_access required")
		return
	}
	var body struct {
		Enabled bool   `json:"enabled"`
		Reason  string `json:"reason"`
	}
	if err := decode(r, &body); err != nil {
		s.fail(w, r, err)
		return
	}
	if body.Enabled && body.Reason == "" || len(body.Reason) > 512 {
		s.fail(w, r, &changerequests.Error{Status: 422, Slug: "validation-failed", Detail: "reason: required to enable, at most 512 characters"})
		return
	}
	action := "SYSTEM_MAINTENANCE_DISABLED"
	if body.Enabled {
		action = "SYSTEM_MAINTENANCE_ENABLED"
	}
	err := pgx.BeginFunc(r.Context(), s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `UPDATE system_settings SET maintenance_mode = $1, maintenance_reason = nullif($2, ''),
			changed_by = $3, changed_at = now()`, body.Enabled, body.Reason, c.ID()); err != nil {
			return err
		}
		snap, _ := json.Marshal(map[string]string{"reason": body.Reason})
		_, err := audit.Append(r.Context(), tx, audit.Entry{Action: action, Actor: c.ID(), ActorGroups: c.Principal.Groups, Snapshot: snap})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.getMaintenance(w, r)
}

func (s *Server) verifyAudit(w http.ResponseWriter, r *http.Request) {
	if !viewer(caller(r)) {
		problem(w, http.StatusForbidden, "forbidden", "viewer role required")
		return
	}
	res, err := audit.Verify(r.Context(), s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"valid": res.Valid, "entries": res.Entries}
	if !res.Valid {
		out["firstBroken"] = res.FirstBroken
	}
	reply(w, http.StatusOK, out)
}

// scopes of a resource, by its kind in the path; only existing resources
// have an audit visible through the API.
var scopeQueries = map[string]struct{ typ, sql string }{
	"sources":  {"SOURCE", "SELECT ARRAY[scope] FROM sources WHERE name = $1 ORDER BY created_at DESC LIMIT 1"},
	"targets":  {"TARGET", "SELECT ARRAY[scope, platform_scope] FROM targets WHERE name = $1 ORDER BY created_at DESC LIMIT 1"},
	"bindings": {"BINDING", "SELECT ARRAY[source_scope, target_scope, platform_scope] FROM bindings WHERE name = $1"},
}

type auditDTO struct {
	ID              int64           `json:"id"`
	Action          string          `json:"action"`
	Actor           string          `json:"actor"`
	Approver        string          `json:"approver,omitempty"`
	ChangeRequestID *uuid.UUID      `json:"changeRequestId,omitempty"`
	Revision        *int64          `json:"revision,omitempty"`
	Attempt         *int64          `json:"attempt,omitempty"`
	WorkflowID      string          `json:"workflowId,omitempty"`
	RequestID       string          `json:"requestId,omitempty"`
	Snapshot        json.RawMessage `json:"snapshot,omitempty"`
	OccurredAt      time.Time       `json:"occurredAt"`
}

// resourceAudit lists a resource's audit entries, newest first, for a
// caller who sees its scopes (keyset on id).
func (s *Server) resourceAudit(w http.ResponseWriter, r *http.Request) {
	kind := strings.Split(r.Pattern, "/")[3] // GET /v1/admin/<kind>/{name}/audit
	q := scopeQueries[kind]
	name := r.PathValue("name")
	var scopes []string
	err := s.DB.QueryRow(r.Context(), q.sql, name).Scan(&scopes)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !caller(r).Grants.Sees(scopes...) {
		problem(w, http.StatusNotFound, "not-found", kind+" "+name)
		return
	}
	var cursor struct {
		BeforeID *int64 `json:"beforeId"`
	}
	size := 0
	if err == nil {
		size, err = page(r, &cursor)
	}
	var items []auditDTO
	var more bool
	if err == nil {
		items, more, err = s.auditPage(r.Context(), q.typ, name, cursor.BeforeID, size)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if more {
		cursor.BeforeID = &items[size-1].ID
	}
	reply(w, http.StatusOK, map[string]any{"items": items, "nextPageToken": token(more, cursor)})
}

// auditPage is a resource's audit entries before an id, newest first.
func (s *Server) auditPage(ctx context.Context, typ, name string, before *int64, size int) ([]auditDTO, bool, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, action, actor, coalesce(approver, ''), change_request_id, revision, attempt,
		coalesce(workflow_id, ''), coalesce(request_id, ''), snapshot, occurred_at FROM audit_log
		WHERE resource_type = $1 AND resource_name = $2 AND ($3::bigint IS NULL OR id < $3) ORDER BY id DESC LIMIT $4`,
		typ, name, before, size+1)
	if err != nil {
		return nil, false, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (auditDTO, error) {
		var a auditDTO
		return a, row.Scan(&a.ID, &a.Action, &a.Actor, &a.Approver, &a.ChangeRequestID, &a.Revision, &a.Attempt, &a.WorkflowID,
			&a.RequestID, &a.Snapshot, &a.OccurredAt)
	})
	more := len(items) > size
	if more {
		items = items[:size]
	}
	if items == nil {
		items = []auditDTO{}
	}
	return items, more, err
}
