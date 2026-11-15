package changerequests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/dihedron/ligo/internal/audit"
	"github.com/dihedron/ligo/internal/metrics"
	"github.com/jackc/pgx/v5"
)

// violationWindow is how often the same principal's refusals on the same
// resource are audited (.specs/ligo-managed-resources.md T-M9): the metric
// counts every one.
const violationWindow = time.Minute

// recentViolations remembers, per principal and resource, when a refusal was
// last audited. shortcut: per process, so n replicas audit up to n entries a
// window; move it to the database if that ever matters.
var recentViolations = struct {
	sync.Mutex
	at map[string]time.Time
}{at: map[string]time.Time{}}

// auditable says whether the refusal of key, at now, is to be audited, and
// remembers it.
func auditable(key string, now time.Time) bool {
	recentViolations.Lock()
	defer recentViolations.Unlock()
	if last, ok := recentViolations.at[key]; ok && now.Sub(last) < violationWindow {
		return false
	}
	if len(recentViolations.at) >= 4096 { // forget what is out of its window
		for k, t := range recentViolations.at {
			if now.Sub(t) >= violationWindow {
				delete(recentViolations.at, k)
			}
		}
	}
	recentViolations.at[key] = now
	return true
}

// lockAudit is the audit entry of a lock set or released by r, applied in tx
// for the resource id whose owner was curOwner, or nil when the lock does not
// change hands (an owner that keeps its lock, a release of what is not locked).
func lockAudit(r *Request, curOwner string) *audit.Entry {
	snap := map[string]any{"operation": r.Operation}
	var action string
	switch {
	case r.Managed == nil:
		return nil
	case *r.Managed && curOwner != r.RequestedBy:
		action, snap["owner"] = "RESOURCE_MANAGED", r.RequestedBy
		if curOwner != "" {
			snap["previousOwner"] = curOwner
		}
	case !*r.Managed && curOwner != "" && r.ReleaseJustification != "":
		action, snap["previousOwner"], snap["justification"] = "RESOURCE_RELEASED_BY_ADMIN", curOwner, r.ReleaseJustification
	case !*r.Managed && curOwner != "":
		action, snap["previousOwner"] = "RESOURCE_RELEASED", curOwner
	default:
		return nil
	}
	b, _ := json.Marshal(snap) // strings only
	e := entry(r, action, r.RequestedBy, "", nil)
	e.Snapshot = b
	return &e
}

// refused counts a refusal of the lock and, once per window and principal
// and resource, audits it (LOCK_VIOLATION_REFUSED). It returns err.
func (s *Service) refused(ctx context.Context, c Caller, r *Request, err error) error {
	var e *Error
	if !errors.As(err, &e) || e.Slug != "resource-managed" {
		return err
	}
	metrics.LockViolations.WithLabelValues(strings.ToLower(r.ResourceType)).Inc()
	if !auditable(c.ID()+"\x00"+r.ResourceType+"\x00"+r.ResourceName, time.Now()) {
		return err
	}
	var js []string
	for _, j := range []string{r.OwnerJurisdiction, r.SourceJurisdiction, r.TargetJurisdiction, r.PlatformJurisdiction} {
		if j != "" {
			js = append(js, j)
		}
	}
	snap, _ := json.Marshal(map[string]any{"operation": r.Operation, "owner": r.LockOwner, "jurisdictions": js})
	if aerr := pgx.BeginFunc(ctx, s.DB, func(tx pgx.Tx) error {
		_, err := audit.Append(ctx, tx, audit.Entry{ResourceType: r.ResourceType, ResourceName: r.ResourceName, Action: "LOCK_VIOLATION_REFUSED",
			Actor: c.ID(), ActorGroups: c.Principal.Groups, Snapshot: snap})
		return err
	}); aerr != nil {
		return fmt.Errorf("changerequests: audit the refusal: %w (refused: %w)", aerr, err)
	}
	return err
}
