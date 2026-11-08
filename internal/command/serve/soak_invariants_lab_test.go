//go:build lab

package serve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The soak's checker (.specs/ligo-soak.md §5): SK-1 to SK-10, every minute
// while the load runs and once more after it, on everything. A violation goes
// to the history and fails the run at its end; the run goes on meanwhile. A
// check that cannot reach what it reads is recorded as skipped, not failed.

// revocation is a binding whose revocation was applied, to check after SK-1's
// limit.
type revocation struct {
	name, id, acct string
	at             time.Time
}

// sk1Limit, sk7Stuck, sk7BreakGlass, sk9Stale, sk10Limit: the spec's limits.
const (
	sk1Limit      = 2 * time.Minute
	sk7Stuck      = 10 * time.Minute
	sk7BreakGlass = 2 * time.Minute
	sk9Stale      = 30 * time.Minute
	sk10Limit     = 30 * time.Second
	sk2Sample     = 20
	sk10Silent    = 3 // checks in a row, a minute apart, with a replica not answering
)

// violation records a broken invariant.
func (s *soakRun) violation(id, detail string) {
	s.mu.Lock()
	s.violations++
	s.mu.Unlock()
	s.h.add(event{Kind: "violation", Res: id, Note: detail})
}

// skipped records a check that could not run.
func (s *soakRun) skipped(id string, err error) {
	s.h.add(event{Kind: "check:skipped", Res: id, Err: err.Error()})
}

// ligoDB connects to ligo's database, read-only, as its migrator: the soak
// reads every table, as no role of the application may.
func (s *soakRun) ligoDB(ctx context.Context) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(os.Getenv("LIGO_SOAK_DB_DSN"))
	if err != nil {
		return nil, err
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	return pgx.ConnectConfig(ctx, cfg)
}

// rows runs a query whose rows are each one line of text.
func rows(ctx context.Context, db *pgx.Conn, sql string, args ...any) ([]string, error) {
	r, err := db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(r, pgx.RowTo[string])
}

// check runs every invariant once; with final, SK-2 and SK-3 take every live
// binding rather than a sample.
func (s *soakRun) check(final bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	var revoked, credentials int
	defer func() {
		s.h.add(event{Kind: "check", MS: time.Since(start).Milliseconds(),
			Note: fmt.Sprintf("final %v, SK-1 on %d revocations, SK-2 and SK-3 on %d credentials", final, revoked, credentials)})
	}()
	db, err := s.ligoDB(ctx)
	if err != nil {
		s.skipped("SK-database", err)
	} else {
		defer func() { _ = db.Close(context.Background()) }()
		s.checkSQL(ctx, db)
		s.checkRoles(ctx, db)
		revoked = s.checkRevocations(ctx, db)
		credentials = s.checkCredentials(ctx, db, final)
	}
	s.checkAudit()
	s.checkReplicas()
}

// sqlChecks: each query returns the rows that break its invariant.
var sqlChecks = []struct{ id, what, sql string }{
	{"SK-4", "decided by its requester", `
		select cr.resource_name || ' ' || s.side || ' ' || s.decided_by from change_requests cr
		join change_request_sides s on s.change_request_id = cr.id
		where cr.status = 'APPLIED' and s.basis = 'HUMAN' and s.decided_by = cr.requested_by`},
	{"SK-4", "one person on two sides", `
		select cr.resource_name || ' ' || s.decided_by from change_requests cr
		join change_request_sides s on s.change_request_id = cr.id
		where cr.status = 'APPLIED' and cr.distinct_approvers_required and s.basis = 'HUMAN' and s.decided_by is not null
		group by cr.id, cr.resource_name, s.decided_by having count(*) > 1`},
	{"SK-5", "live on a retired account", `
		select 'source ' || s.name from sources s join accounts a on a.name = s.account where a.status = 'RETIRED' and s.state <> 'RETIRED'
		union all
		select 'target ' || t.name from targets t join accounts a on a.name = t.account where a.status = 'RETIRED' and t.state <> 'RETIRED'`},
	{"SK-7", "stuck", `
		select name || ' ' || phase from bindings
		where phase in ('PROVISIONING', 'DELETING') and last_transition_at < now() - make_interval(secs => ` + fmt.Sprint(sk7Stuck.Seconds()) + `)`},
	{"SK-7", "break-glass not reverted", `
		select name from bindings
		where break_glass_cr_id is not null and break_glass_expires_at < now() - make_interval(secs => ` + fmt.Sprint(sk7BreakGlass.Seconds()) + `)`},
	{"SK-9", "event neither delivered nor abandoned", `
		select event || ' ' || event_id from notification_outbox
		where delivered_at is null and abandoned_at is null and created_at < now() - make_interval(secs => ` + fmt.Sprint(sk9Stale.Seconds()) + `)`},
}

func (s *soakRun) checkSQL(ctx context.Context, db *pgx.Conn) {
	for _, c := range sqlChecks {
		bad, err := rows(ctx, db, c.sql)
		if err != nil {
			s.skipped(c.id, err)
			continue
		}
		for _, b := range bad {
			s.violation(c.id, c.what+": "+b)
		}
	}
}

// checkRoles is SK-6: the roles on the shared platform tagged with a binding
// id against the bindings. A role whose binding is gone, or an ACTIVE binding
// with no role, is suspect; seen twice in a row, it is a violation, since an
// apply or a delete may be between its two writes at one check.
func (s *soakRun) checkRoles(ctx context.Context, db *pgx.Conn) {
	all, err := rows(ctx, db, `select id::text from bindings`)
	if err != nil {
		s.skipped("SK-6", err)
		return
	}
	active, err := rows(ctx, db, `select b.id::text from bindings b join targets t on t.id = b.target_id
		where t.platform = 'pg-shared' and b.phase = 'ACTIVE'`)
	if err != nil {
		s.skipped("SK-6", err)
		return
	}
	tagged, err := s.taggedRoles(ctx)
	if err != nil {
		s.skipped("SK-6", err)
		return
	}
	suspects := map[string]string{}
	for _, id := range tagged {
		if !slices.Contains(all, id) {
			suspects["orphan "+id] = "a role of binding " + id + ", which is gone"
		}
	}
	for _, id := range active {
		if !slices.Contains(tagged, id) {
			suspects["missing "+id] = "ACTIVE binding " + id + " has no role"
		}
	}
	s.mu.Lock()
	prev := s.sk6
	s.sk6 = suspects
	s.mu.Unlock()
	for k, detail := range suspects {
		if _, again := prev[k]; again {
			s.violation("SK-6", detail)
		}
	}
}

// taggedRoles are the binding ids in the comments of the target's roles.
func (s *soakRun) taggedRoles(ctx context.Context) ([]string, error) {
	conn, err := ledgerConn(s.t, "lab_target_admin", os.Getenv("LIGO_TEST_TARGET_ADMIN_PASS"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close(context.Background()) }()
	return rows(ctx, conn, `select substring(shobj_description(oid, 'pg_authid') from 'ligo:binding_id=(.*)') from pg_roles
		where shobj_description(oid, 'pg_authid') like 'ligo:binding_id=%'`)
}

// checkRevocations is SK-1: SK-1's limit after a revocation was applied, its
// binding is gone from the database, its role from the target, and the binding
// from its workload's list.
func (s *soakRun) checkRevocations(ctx context.Context, db *pgx.Conn) (checked int) {
	s.mu.Lock()
	var due, later []revocation
	for _, r := range s.revoked {
		if time.Since(r.at) >= sk1Limit {
			due = append(due, r)
		} else {
			later = append(later, r)
		}
	}
	s.revoked = later
	s.mu.Unlock()
	if len(due) == 0 {
		return 0
	}
	tagged, err := s.taggedRoles(ctx)
	if err != nil {
		s.skipped("SK-1", err)
		s.requeue(due)
		return 0
	}
	lists := map[string][]string{}
	for _, r := range due {
		var n int
		if err := db.QueryRow(ctx, `select count(*) from bindings where name = $1`, r.name).Scan(&n); err != nil {
			s.skipped("SK-1", err)
			s.requeue([]revocation{r})
			continue
		}
		if n != 0 {
			s.violation("SK-1", r.name+" still in the database "+time.Since(r.at).Round(time.Second).String()+" after its revocation")
		}
		if slices.Contains(tagged, r.id) {
			s.violation("SK-1", r.name+"'s role still on the target "+time.Since(r.at).Round(time.Second).String()+" after its revocation")
		}
		names, ok := lists[r.acct]
		if !ok {
			if names, err = s.delivered(r.acct); err != nil {
				s.skipped("SK-1", err)
				s.requeue([]revocation{r})
				continue
			}
			lists[r.acct] = names
		}
		if slices.Contains(names, r.name) {
			s.violation("SK-1", r.name+" still delivered "+time.Since(r.at).Round(time.Second).String()+" after its revocation")
		}
		checked++
	}
	return checked
}

func (s *soakRun) requeue(rs []revocation) {
	s.mu.Lock()
	s.revoked = append(s.revoked, rs...)
	s.mu.Unlock()
}

// workloadOf is the workload of an account: soakw<i> for s<i>.
func workloadOf(acct string) string {
	i, _ := strconv.Atoi(acct[1:])
	return fmt.Sprintf("soakw%d", i)
}

// deliveredItems is what ligo delivers to an account's workload.
func (s *soakRun) deliveredItems(acct string) ([]map[string]any, error) {
	who := workloadOf(acct)
	cfg, err := ligoTLSConfig(os.Getenv("LIGO_E2E_DIR"), who)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	defer client.CloseIdleConnections()
	resp, err := client.Get(os.Getenv("LIGO_E2E_WORKLOAD") + "/v1/bindings")
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the workload API: %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return items(body), nil
}

func (s *soakRun) delivered(acct string) ([]string, error) {
	list, err := s.deliveredItems(acct)
	var names []string
	for _, it := range list {
		names = append(names, fmt.Sprint(it["name"]))
	}
	return names, err
}

// checkCredentials is SK-2 and SK-3, on a sample of the live bindings or, with
// final, on all: each one's credential, as its workload reads it, connects and
// reads its tenancy (SK-2), and is refused another account's (SK-3). A binding
// that left ACTIVE meanwhile proves nothing either way.
func (s *soakRun) checkCredentials(ctx context.Context, db *pgx.Conn, final bool) (checked int) {
	s.mu.Lock()
	var live []soakBinding
	for _, b := range s.bindings {
		live = append(live, b)
	}
	s.mu.Unlock()
	slices.SortFunc(live, func(a, b soakBinding) int { return strings.Compare(a.name, b.name) })
	if !final && len(live) > sk2Sample {
		s.checkRng.Shuffle(len(live), func(i, j int) { live[i], live[j] = live[j], live[i] })
		live = live[:sk2Sample]
	}
	lists := map[string][]map[string]any{}
	for _, b := range live {
		acct := accountOfTarget(b.source)
		list, ok := lists[acct]
		if !ok {
			var err error
			if list, err = s.deliveredItems(acct); err != nil {
				s.skipped("SK-2", err)
				continue
			}
			lists[acct] = list
		}
		var item map[string]any
		for _, it := range list {
			if it["name"] == b.name {
				item = it
			}
		}
		if item == nil {
			continue // not yet delivered, or being revoked: SK-1 and SK-6 watch those
		}
		s.checkCredential(ctx, db, b, item)
		checked++
	}
	return checked
}

func (s *soakRun) checkCredential(ctx context.Context, db *pgx.Conn, b soakBinding, item map[string]any) {
	stillActive := func() bool {
		var phase string
		err := db.QueryRow(ctx, `select phase::text from bindings where name = $1`, b.name).Scan(&phase)
		return err == nil && phase == "ACTIVE"
	}
	auth, _ := item["auth"].(map[string]any)
	cfg, _ := auth["config"].(map[string]any)
	who := workloadOf(accountOfTarget(b.source))
	user, password, err := storeFetch(cfg, filepath.Join(os.Getenv("LIGO_E2E_DIR"), who+"-store-jwt"), os.Getenv("LIGO_TEST_CA"),
		os.Getenv("LIGO_E2E_SECRETS"), "secretPath", kvCredential)
	if err != nil {
		if stillActive() {
			s.violation("SK-2", b.name+": its credential cannot be read: "+err.Error())
		}
		return
	}
	own := schemaOf(b.target)
	conn, err := ledgerConn(s.t, user, password)
	if err != nil {
		if stillActive() {
			s.violation("SK-2", b.name+": its credential does not connect: "+err.Error())
		}
		return
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var n int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM "+own+".entries").Scan(&n); err != nil && stillActive() {
		s.violation("SK-2", b.name+": its credential does not read "+own+": "+err.Error())
	}
	other := s.otherSchema(own)
	err = conn.QueryRow(ctx, "SELECT count(*) FROM "+other+".entries").Scan(&n)
	var pgErr *pgconn.PgError
	switch {
	case err == nil:
		s.violation("SK-3", b.name+": its credential reads "+other)
	case errors.As(err, &pgErr) && pgErr.Code == "42501":
	default:
		s.skipped("SK-3", fmt.Errorf("%s reading %s: %w", b.name, other, err))
	}
}

// schemaOf is a tenancy target's schema: s03-db1-<x> is s03_db1.
func schemaOf(target string) string {
	return strings.Replace(target[:strings.LastIndex(target, "-")], "-", "_", 1)
}

// otherSchema is a schema of another account than own's.
func (s *soakRun) otherSchema(own string) string {
	for {
		acct := s.accounts[s.checkRng.IntN(len(s.accounts))]
		db := 1 + s.checkRng.IntN(2)
		if other := fmt.Sprintf("%s_db%d", acct, db); !strings.HasPrefix(own, acct+"_") || len(s.accounts) == 1 {
			return other
		}
	}
}

// checkAudit is SK-8's chain: ligo audit verify, through the API.
func (s *soakRun) checkAudit() {
	code, body, err := s.ada.try("GET", "/v1/admin/audit/verify", nil)
	switch {
	case err != nil:
		s.skipped("SK-8", err)
	case code != http.StatusOK:
		s.skipped("SK-8", fmt.Errorf("audit verify: %d", code))
	case body["valid"] != true:
		s.violation("SK-8", fmt.Sprintf("the audit chain does not verify: %v", body))
	}
}

// checkReplicas is SK-10: ligo1 and ligo2 list the same accounts and bindings
// within SK-10's limit.
func (s *soakRun) checkReplicas() {
	for _, path := range []string{"/v1/admin/accounts", "/v1/admin/bindings"} {
		deadline := time.Now().Add(sk10Limit)
		for {
			one, err1 := s.names(s.ada, path)
			two, err2 := s.names(s.ada2, path)
			if err := errors.Join(err1, err2); err != nil {
				s.skipped("SK-10", err)
				s.mu.Lock()
				s.silent++
				silent := s.silent
				s.mu.Unlock()
				if silent == sk10Silent {
					s.violation("SK-10", fmt.Sprintf("a replica has not answered for %d checks in a row: %v", silent, err))
				}
				return
			}
			s.mu.Lock()
			s.silent = 0
			s.mu.Unlock()
			if slices.Equal(one, two) {
				break
			}
			if time.Now().After(deadline) {
				s.violation("SK-10", fmt.Sprintf("%s differs for over %v: %d names on ligo1, %d on ligo2", path, sk10Limit, len(one), len(two)))
				break
			}
			time.Sleep(2 * time.Second)
		}
	}
}

// names lists every name at path, page by page, sorted.
func (s *soakRun) names(who *admin, path string) ([]string, error) {
	var out []string
	token := ""
	for {
		p := path + "?pageSize=200"
		if token != "" {
			p += "&pageToken=" + token
		}
		code, body, err := who.try("GET", p, nil)
		if err != nil {
			return nil, err
		}
		if code != http.StatusOK {
			return nil, fmt.Errorf("GET %s: %d", p, code)
		}
		for _, it := range items(body) {
			out = append(out, fmt.Sprint(it["name"]))
		}
		token, _ = body["nextPageToken"].(string)
		if token == "" {
			break
		}
	}
	slices.Sort(out)
	return out, nil
}

// converge waits, after the load, until nothing is in PROVISIONING or
// DELETING, for at most SK-7's limit.
func (s *soakRun) converge() {
	deadline := time.Now().Add(sk7Stuck)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		db, err := s.ligoDB(ctx)
		if err == nil {
			var n int
			err = db.QueryRow(ctx, `select count(*) from bindings where phase in ('PROVISIONING', 'DELETING')`).Scan(&n)
			_ = db.Close(context.Background())
			if err == nil && n == 0 {
				cancel()
				s.h.add(event{Kind: "converged"})
				return
			}
		}
		cancel()
		time.Sleep(10 * time.Second)
	}
	s.h.add(event{Kind: "converged", Note: "not within SK-7's limit"})
}
