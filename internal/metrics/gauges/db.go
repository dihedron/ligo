// Package gauges collects the metrics of the database's state at each
// scrape (§10.1), apart from internal/metrics so that the packages it reads
// can count their events there.
package gauges

import (
	"context"
	"log/slog"
	"time"

	"github.com/dihedron/ligo/internal/changerequests"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

// DB collects the gauges that describe the database's state, by querying it
// at each scrape: always current, and the same on every replica.
type DB struct {
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	// Rotation is each platform's rotation_interval plus the reconciler's
	// interval and jitter, at each scrape: a static secret older than that
	// is overdue.
	Rotation func() map[string]time.Duration
	// Timeout bounds one scrape's queries.
	Timeout time.Duration
}

var (
	descBindings      = desc("ligo_bindings", "Bindings by phase and realm.", "phase", "realm")
	descRequests      = desc("ligo_change_requests", "Change requests by status and realm.", "status", "realm")
	descSidesPending  = desc("ligo_change_request_sides_pending", "Undecided sides of pending change requests.", "resource_type", "side_kind")
	descSources       = desc("ligo_sources", "Sources by state.", "state")
	descTargets       = desc("ligo_targets", "Targets by state.", "state")
	descQueueDepth    = desc("ligo_propagation_queue_depth", "Bindings waiting for propagation, by priority.", "priority")
	descQueueOldest   = desc("ligo_propagation_oldest_seconds", "Age of the oldest queued propagation, by priority.", "priority")
	descExpiring      = desc("ligo_bindings_expiring", "Bindings that expire within 24h or 7d.", "within")
	descBreakGlass    = desc("ligo_break_glass_open", "Open break-glass changes of bindings (ADR-12), by realm.", "realm")
	descRotationOver  = desc("ligo_rotation_overdue", "ACTIVE bindings with a static secret overdue for rotation.", "realm", "platform")
	descScrapeSuccess = desc("ligo_db_scrape_success", "1 when the last scrape of the database gauges succeeded, else 0.")
)

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(name, help, labels, nil)
}

// Describe sends the gauges' descriptions.
func (d *DB) Describe(ch chan<- *prometheus.Desc) {
	for _, x := range []*prometheus.Desc{descBindings, descRequests, descSidesPending, descSources, descTargets, descQueueDepth,
		descQueueOldest, descExpiring, descBreakGlass, descRotationOver, descScrapeSuccess} {
		ch <- x
	}
}

// query is one gauge's SQL: every row is the labels' values, then the value.
type query struct {
	desc   *prometheus.Desc
	sql    string
	labels int
	args   []any
}

// Collect runs every query; a failed one is logged and its gauge left out,
// and ligo_db_scrape_success says whether all of them succeeded.
func (d *DB) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()
	ok := 1.0
	for _, q := range d.queries() {
		if err := d.run(ctx, ch, q); err != nil {
			d.Logger.Warn("metrics: database gauge", "metric", q.desc.String(), "error", err)
			ok = 0
		}
	}
	ch <- prometheus.MustNewConstMetric(descScrapeSuccess, prometheus.GaugeValue, ok)
}

func (d *DB) queries() []query {
	platforms, seconds := []string{}, []float64{}
	if d.Rotation != nil {
		for p, t := range d.Rotation() {
			if t > 0 {
				platforms, seconds = append(platforms, p), append(seconds, t.Seconds())
			}
		}
	}
	return []query{
		{descBindings, `SELECT phase::text, realm, count(*) FROM bindings GROUP BY 1, 2`, 2, nil},
		{descRequests, `SELECT status::text, coalesce(realm, ''), count(*) FROM change_requests GROUP BY 1, 2`, 2, nil},
		{descSidesPending, `SELECT r.resource_type::text, split_part(s.side, ':', 1), count(*) FROM change_requests r
			JOIN change_request_sides s ON s.change_request_id = r.id WHERE r.status = 'PENDING' AND s.decision IS NULL GROUP BY 1, 2`, 2, nil},
		{descSources, `SELECT state::text, count(*) FROM sources GROUP BY 1`, 1, nil},
		{descTargets, `SELECT state::text, count(*) FROM targets GROUP BY 1`, 1, nil},
		{descQueueDepth, `SELECT p::text, (SELECT count(*) FROM binding_propagation_queue WHERE priority = p) FROM (VALUES (0), (1)) v(p)`, 1, nil},
		{descQueueOldest, `SELECT p::text, coalesce((SELECT extract(epoch FROM now() - min(enqueued_at)) FROM binding_propagation_queue
			WHERE priority = p), 0) FROM (VALUES (0), (1)) v(p)`, 1, nil},
		{descExpiring, `SELECT w, (SELECT count(*) FROM bindings WHERE expires_at > now() AND expires_at <= now() + i)
			FROM (VALUES ('24h', interval '24 hours'), ('7d', interval '7 days')) v(w, i)`, 1, nil},
		{descBreakGlass, `SELECT r.realm, count(DISTINCT r.id) FROM change_requests r JOIN change_request_sides s ON s.change_request_id = r.id
			WHERE ` + changerequests.OpenBreakGlass + ` GROUP BY 1`, 1, nil},
		// static secrets: the identity modes the reconciler rotates (workflows.Engine.reapply)
		{descRotationOver, `SELECT b.realm, b.platform, count(*) FILTER (WHERE b.last_rotated_at IS NULL
				OR b.last_rotated_at < now() - make_interval(secs => t.secs))
			FROM bindings b JOIN unnest($1::text[], $2::float8[]) AS t(platform, secs) ON t.platform = b.platform
			JOIN binding_stage_state st ON st.binding_id = b.id AND st.stage = 'IDENTITY'
			WHERE b.phase = 'ACTIVE' AND st.artifact->>'mode' IN ('IDENTITY_MODE_EXTERNAL_DIR', 'IDENTITY_MODE_TARGET_LOCAL')
			GROUP BY 1, 2`, 2, []any{platforms, seconds}},
	}
}

func (d *DB) run(ctx context.Context, ch chan<- prometheus.Metric, q query) error {
	rows, err := d.Pool.Query(ctx, q.sql, q.args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		labels := make([]string, q.labels)
		var value float64
		dest := make([]any, 0, q.labels+1)
		for i := range labels {
			dest = append(dest, &labels[i])
		}
		if err := rows.Scan(append(dest, &value)...); err != nil {
			return err
		}
		ch <- prometheus.MustNewConstMetric(q.desc, prometheus.GaugeValue, value, labels...)
	}
	return rows.Err()
}
