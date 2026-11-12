package adminhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/dihedron/ligo/internal/sealing"
	"github.com/jackc/pgx/v5"
)

func (s *Server) opsRoutes(mux *router) {
	mux.HandleFunc("GET /v1/admin/maintenance", s.getMaintenance)
	mux.HandleFunc("PUT /v1/admin/maintenance", s.putMaintenance)
	mux.HandleFunc("GET /v1/admin/audit/verify", s.verifyAudit)
	mux.HandleFunc("GET /v1/admin/audit/export", s.exportAudit)
	mux.HandleFunc("POST /v1/admin/audit/exports", s.recordAuditExport)
	mux.HandleFunc("GET /v1/admin/executors", s.listExecutors)
	mux.HandleFunc("POST /v1/admin/executors/{id}/recover", s.recoverExecutor)
	for kind := range jurisdictionQueries { // one route each: a {kind} wildcard would overlap /v1/admin/catalog/targets/{name}
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
	if err := changerequests.SetMaintenance(r.Context(), s.DB, c.ID(), c.Principal.Groups, body.Enabled, body.Reason); err != nil {
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
	full := r.URL.Query().Get("full") == "true"
	res, err := audit.Verify(r.Context(), s.DB, s.Signer, full)
	if errors.Is(err, sealing.ErrSignerUnavailable) {
		problem(w, http.StatusServiceUnavailable, "unavailable", "the audit signing key cannot be reached")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"valid": res.Valid, "entries": res.Entries, "checkpoints": res.Checkpoints, "full": res.Full}
	if !res.Valid {
		out["firstBroken"] = res.FirstBroken
	}
	reply(w, http.StatusOK, out)
}

// exportAudit streams the chain through a checkpoint as JSON Lines
// (.specs/ligo-pruning.md §3.2). Full access only: it spans every
// jurisdiction.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	if !caller(r).Grants.FullAccess() {
		problem(w, http.StatusForbidden, "forbidden", "admin.full_access required")
		return
	}
	var through int64
	if v := r.URL.Query().Get("through"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			problem(w, http.StatusUnprocessableEntity, "validation-failed", "through: a positive audit entry id")
			return
		}
		through = n
	}
	out := &startWriter{w: w}
	_, err := audit.Export(r.Context(), s.DB, s.Signer, through, out)
	switch {
	case err == nil:
	case out.started: // the status is sent: the client's verification fails on the cut file
		s.Logger.Error("audit export cut", "request_id", w.Header().Get("X-Request-Id"), "error", err)
	case errors.Is(err, audit.ErrNotCheckpoint):
		problem(w, http.StatusUnprocessableEntity, "validation-failed", "through: "+err.Error())
	case errors.Is(err, sealing.ErrSignerUnavailable):
		problem(w, http.StatusServiceUnavailable, "unavailable", "the audit signing key cannot be reached")
	default:
		s.fail(w, r, err)
	}
}

// startWriter sets the content type on the first write, so an error before
// it can still be a problem.
type startWriter struct {
	w       http.ResponseWriter
	started bool
}

func (sw *startWriter) Write(p []byte) (int, error) {
	if !sw.started {
		sw.started = true
		sw.w.Header().Set("Content-Type", "application/x-ndjson")
		sw.w.WriteHeader(http.StatusOK)
	}
	return sw.w.Write(p)
}

// recordAuditExport records an export the caller took and verified; pruning
// never passes the newest one.
func (s *Server) recordAuditExport(w http.ResponseWriter, r *http.Request) {
	c := caller(r)
	if !c.Grants.FullAccess() {
		problem(w, http.StatusForbidden, "forbidden", "admin.full_access required")
		return
	}
	var body struct {
		Through int64  `json:"through"`
		SHA256  string `json:"sha256"`
	}
	if err := decode(r, &body); err != nil {
		s.fail(w, r, err)
		return
	}
	err := pgx.BeginFunc(r.Context(), s.DB, func(tx pgx.Tx) error {
		return audit.RecordExport(r.Context(), tx, body.Through, body.SHA256, c.ID(), c.Principal.Groups)
	})
	switch {
	case errors.Is(err, audit.ErrExported):
		problem(w, http.StatusConflict, "audit-export-recorded", err.Error())
	case errors.Is(err, audit.ErrNotCheckpoint), errors.Is(err, audit.ErrBadExport):
		problem(w, http.StatusUnprocessableEntity, "validation-failed", err.Error())
	case err != nil:
		s.fail(w, r, err)
	default:
		reply(w, http.StatusCreated, map[string]any{"through": body.Through, "sha256": body.SHA256})
	}
}

// id and jurisdictions of a resource, by its kind in the path; only existing
// resources have an audit visible through the API. A binding's jurisdictions include
// those of its additional parties (§7.2.4).
var jurisdictionQueries = map[string]string{
	"sources": "SELECT id, ARRAY[jurisdiction] FROM sources WHERE name = $1 ORDER BY created_at DESC LIMIT 1",
	"targets": "SELECT id, ARRAY[jurisdiction, platform_jurisdiction] FROM targets WHERE name = $1 ORDER BY created_at DESC LIMIT 1",
	"bindings": `SELECT b.id, ARRAY[b.source_jurisdiction, b.target_jurisdiction, b.platform_jurisdiction]::text[] || b.party_jurisdictions::text[]
		FROM bindings b WHERE b.name = $1`,
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
// caller who sees its jurisdictions (keyset on id).
func (s *Server) resourceAudit(w http.ResponseWriter, r *http.Request) {
	kind := strings.Split(r.Pattern, "/")[3] // GET /v1/admin/<kind>/{name}/audit
	name := r.PathValue("name")
	var id uuid.UUID
	var jurisdictions []string
	err := s.DB.QueryRow(r.Context(), jurisdictionQueries[kind], name).Scan(&id, &jurisdictions)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !caller(r).Grants.Sees(jurisdictions...) {
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
		items, more, err = s.auditPage(r.Context(), id, cursor.BeforeID, size)
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

// auditPage is a resource's audit entries before an id, newest first: those
// of the resource and of its change requests, never those of a namesake.
func (s *Server) auditPage(ctx context.Context, id uuid.UUID, before *int64, size int) ([]auditDTO, bool, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, action, actor, coalesce(approver, ''), change_request_id, revision, attempt,
		coalesce(workflow_id, ''), coalesce(request_id, ''), snapshot, occurred_at FROM audit_log
		WHERE (resource_id = $1 OR change_request_id IN (SELECT id FROM change_requests WHERE resource_id = $1))
		AND ($2::bigint IS NULL OR id < $2) ORDER BY id DESC LIMIT $3`,
		id, before, size+1)
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
