//go:build lab

package serve

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The soak's generator (.specs/ligo-soak.md §4), run by lab.sh soak run on
// ligo1 for LIGO_SOAK_DURATION: people of the soak's accounts file, decide,
// revoke and break glass, while workloads read their credentials and connect.
// Every action goes to the history, one JSON line each. Faults come from
// lab.sh, never from here; so every call tolerates an error and records it.

// soakEnv reads a soak setting, with a default.
func soakEnv(name, def string) string {
	if v := os.Getenv("LIGO_SOAK_" + name); v != "" {
		return v
	}
	return def
}

// history is the soak's record: one JSON object per line, in order.
type history struct {
	mu  sync.Mutex
	f   *os.File
	seq int64
}

// event is one line of the history. Credentials appear as their user only.
type event struct {
	T      string `json:"t"`
	Seq    int64  `json:"seq"`
	Kind   string `json:"kind"`
	Actor  string `json:"actor,omitempty"`
	Res    string `json:"res,omitempty"`
	Code   int    `json:"code,omitempty"`
	MS     int64  `json:"ms,omitempty"`
	Err    string `json:"err,omitempty"`
	Note   string `json:"note,omitempty"`
	Worker int    `json:"worker,omitempty"`
}

func (h *history) add(e event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	e.Seq, e.T = h.seq, time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")
	b, _ := json.Marshal(e)
	_, _ = h.f.Write(append(b, '\n'))
}

// soakBinding is what the generator knows of a binding it filed.
type soakBinding struct {
	name, source, target string
}

// soakRun is one run of the generator.
type soakRun struct {
	t        *testing.T
	x        string // the run's suffix, in every name it creates
	rng      *rand.Rand
	h        *history
	accounts []string // the soak's long-lived accounts, s00 ...
	// people: op files in every soak account, a and b approve there, bg breaks
	// glass; ada registers accounts and files in the ephemeral ones, rita
	// approves there; peter is the shared platform's approver.
	op, a, b, bg, ada, rita, peter *admin
	mu                             sync.Mutex
	bindings                       map[string]soakBinding // live, by name
	ephemeral                      []string               // registered, not yet retired
	next                           int                    // names
	ada2                           *admin                 // ada on ligo2, for SK-10
	revoked                        []revocation           // for SK-1, once its limit has passed
	sk6                            map[string]string      // SK-6's suspects at the last check
	violations                     int
	silent                         int        // SK-10's checks in a row with a replica not answering
	checkRng                       *rand.Rand // the checker's, apart from the generator's
}

// soakAdmin is an LDAP person of the soak, whose password lab.sh passes in.
func soakAdmin(t *testing.T, user string) *admin {
	t.Helper()
	cfg := ligoTLS(t, "")
	return &admin{t: t, base: e2eEnv(t, "LIGO_E2E_ADMIN"), user: user, pass: e2eEnv(t, "LIGO_SOAK_LDAP_"+strings.ToUpper(user)+"_PASS"),
		client: &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}}
}

// renewingAdmin is newAdmin for a person with a minted SVID that lab.sh
// renews during the soak: the SVID is read again at every TLS handshake.
func renewingAdmin(t *testing.T, who string) *admin {
	t.Helper()
	a := newAdmin(t, who)
	dir := e2eEnv(t, "LIGO_E2E_DIR")
	cfg := a.client.Transport.(*http.Transport).TLSClientConfig
	cfg.Certificates = nil
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		pair, err := tls.LoadX509KeyPair(filepath.Join(dir, who+"-svid.pem"), filepath.Join(dir, who+"-key.pem"))
		return &pair, err
	}
	return a
}

// call is admin.try, timed and recorded.
func (s *soakRun) call(who *admin, actor, kind, res, method, path string, body any) (int, map[string]any) {
	start := time.Now()
	code, out, err := who.try(method, path, body)
	e := event{Kind: kind, Actor: actor, Res: res, Code: code, MS: time.Since(start).Milliseconds()}
	if err != nil {
		e.Err = err.Error()
	} else if code/100 != 2 {
		e.Note = fmt.Sprint(out["type"])
	}
	s.h.add(e)
	return code, out
}

func (s *soakRun) name(kind string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return fmt.Sprintf("sk-%s-%s-%05d", kind, s.x, s.next)
}

// sourceOf, targetOf: the names of an account's source and tenancies.
func (s *soakRun) sourceOf(acct string) string { return acct + "-src-" + s.x }
func (s *soakRun) targetOf(acct string, db int) string {
	return fmt.Sprintf("%s-db%d-%s", acct, db, s.x)
}

// accountOfTarget is the account a target name belongs to.
func accountOfTarget(target string) string { return target[:strings.Index(target, "-")] }

// decider picks who decides side of a request between source account src and
// target account dst: distinct people on SOURCE and TARGET (INV-20).
func (s *soakRun) decider(side, src, dst string, ephemeral bool) (*admin, string) {
	switch {
	case side == "PLATFORM":
		return s.peter, "peter"
	case ephemeral:
		return s.rita, "rita"
	case side == "TARGET" && src != dst:
		return s.peter, "peter"
	case side == "TARGET":
		return s.b, "soakb"
	default: // OWNER, SOURCE
		return s.a, "soaka"
	}
}

// decideAll approves each pending side; false if any approval failed.
func (s *soakRun) decideAll(filed map[string]any, res, src, dst string, ephemeral bool) bool {
	cr, _ := filed["changeRequest"].(map[string]any)
	for cr != nil && cr["status"] == "PENDING" {
		awaiting, _ := cr["awaitingApproval"].([]any)
		if len(awaiting) == 0 {
			return false
		}
		side := fmt.Sprint(awaiting[0])
		who, actor := s.decider(side, src, dst, ephemeral)
		code, body := s.call(who, actor, "approve:"+side, res, "POST", "/v1/admin/change-requests/"+fmt.Sprint(cr["id"])+"/approve",
			map[string]any{"payloadSha256": cr["payloadSha256"], "side": side, "comment": "soak"})
		if code != http.StatusOK {
			return false
		}
		cr, _ = body["changeRequest"].(map[string]any)
	}
	return cr != nil && cr["status"] == "APPLIED"
}

// setup registers the soak's accounts and each one's source and two
// tenancies; failures here fail the run, since nothing else would mean much.
func (s *soakRun) setup() {
	t := s.t
	// every account first: an LDAP person's roles are read when its session
	// starts, so an account registered later counts only at the session's re-check
	for _, acct := range s.accounts {
		code, b := s.call(s.ada, "ada", "account:register", acct, "POST", "/v1/admin/accounts", map[string]any{"name": acct})
		if code != http.StatusCreated && code != http.StatusConflict {
			t.Fatalf("register %s: %d %v", acct, code, b)
		}
	}
	for _, acct := range s.accounts {
		// one exact SPIFFE ID: the store's strategy matches subjects exactly (OI-1)
		id := "spiffe://prod.lab/acct/" + acct + "/project/p1/sa/w0"
		code, filed := s.call(s.op, "soakop", "source:create", s.sourceOf(acct), "POST", "/v1/admin/sources", map[string]any{"kind": "Source",
			"metadata":   map[string]string{"name": s.sourceOf(acct)},
			"identity":   map[string]any{"trustDomain": "prod.lab", "svidRegex": "^" + strings.ReplaceAll(id, ".", `\.`) + "$", "sampleSpiffeIds": []string{id}},
			"visibility": map[string]string{"mode": "PUBLIC"}})
		if code != http.StatusAccepted || !s.decideAll(filed, s.sourceOf(acct), acct, acct, false) {
			t.Fatalf("source of %s: %d %v", acct, code, filed)
		}
		for db := 1; db <= 2; db++ {
			name, ns := s.targetOf(acct, db), fmt.Sprintf("%s_db%d", acct, db)
			code, filed := s.call(s.op, "soakop", "target:create", name, "POST", "/v1/admin/targets",
				accountTargetBody(name, fmt.Sprintf("tenants/%s/data/db%d", acct, db), ns, ns+"_read"))
			if code != http.StatusAccepted || !s.decideAll(filed, name, acct, acct, false) {
				t.Fatalf("target %s: %d %v", name, code, filed)
			}
		}
	}
}

// actions, with the weights of .specs/ligo-soak.md §4.2.
type soakAction struct {
	weight int
	name   string
	run    func(*soakRun)
}

var soakActions = []soakAction{
	{25, "workload", func(s *soakRun) { s.workload(s.rng.IntN(s.workloads())) }},
	{15, "binding:create", (*soakRun).createBinding},
	{10, "binding:revoke", (*soakRun).revokeBinding},
	{8, "binding:update", (*soakRun).updateBinding},
	{8, "source:extra", (*soakRun).extraSource},
	{6, "change:abandon", (*soakRun).abandon},
	{5, "binding:rotate", (*soakRun).rotate},
	{4, "break-glass", (*soakRun).breakGlass},
	{3, "account:register", (*soakRun).registerAccount},
	{2, "account:retire", (*soakRun).retireAccount},
	{3, "abuse", (*soakRun).abuse},
	{10, "read", (*soakRun).read},
}

func (s *soakRun) pick() soakAction {
	total := 0
	for _, a := range soakActions {
		total += a.weight
	}
	n := s.rng.IntN(total)
	for _, a := range soakActions {
		if n < a.weight {
			return a
		}
		n -= a.weight
	}
	return soakActions[0]
}

// workloads: one per account, the one its source names.
func (s *soakRun) workloads() int { return len(s.accounts) }

// randomBinding is a live binding, or false.
func (s *soakRun) randomBinding() (soakBinding, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.bindings) == 0 {
		return soakBinding{}, false
	}
	n := s.rng.IntN(len(s.bindings))
	for _, b := range s.bindings {
		if n == 0 {
			return b, true
		}
		n--
	}
	return soakBinding{}, false
}

// createBinding binds an account's source to one of its tenancies, or (one in
// three) to another account's, approved by the platform's approver. Over the
// cap of 200 live bindings, it revokes instead.
func (s *soakRun) createBinding() {
	s.mu.Lock()
	full := len(s.bindings) >= 200
	s.mu.Unlock()
	if full {
		s.revokeBinding()
		return
	}
	src := s.accounts[s.rng.IntN(len(s.accounts))]
	dst := src
	if s.rng.IntN(3) == 0 {
		dst = s.accounts[s.rng.IntN(len(s.accounts))]
	}
	b := soakBinding{name: s.name("b"), source: s.sourceOf(src), target: s.targetOf(dst, 1+s.rng.IntN(2))}
	if s.bound(b.source, b.target) {
		return // one binding per source, target and level: the next tick draws again
	}
	code, filed := s.call(s.op, "soakop", "binding:create", b.name, "POST", "/v1/admin/bindings",
		map[string]any{"name": b.name, "source": b.source, "target": b.target, "accessLevel": "read"})
	if code != http.StatusAccepted {
		return
	}
	if s.decideAll(filed, b.name, src, dst, false) {
		s.mu.Lock()
		s.bindings[b.name] = b
		s.mu.Unlock()
	}
}

// bound tells whether a live binding links source to target.
func (s *soakRun) bound(source, target string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.bindings {
		if b.source == source && b.target == target {
			return true
		}
	}
	return false
}

// revision is a resource's current revision, or 0.
func (s *soakRun) revision(kind, name string) int64 {
	r, _ := s.revisionAndID(kind, name)
	return r
}

// revisionAndID is a resource's current revision and its id, or 0.
func (s *soakRun) revisionAndID(kind, name string) (int64, string) {
	code, body := s.call(s.ada, "ada", kind+":get", name, "GET", "/v1/admin/"+kind+"s/"+name, nil)
	if code != http.StatusOK {
		return 0, ""
	}
	md, _ := body["metadata"].(map[string]any)
	r, _ := md["revision"].(float64)
	return int64(r), fmt.Sprint(md["id"])
}

// revokeBinding deletes a live binding, approved by its source side.
func (s *soakRun) revokeBinding() {
	b, ok := s.randomBinding()
	if !ok {
		return
	}
	rev, id := s.revisionAndID("binding", b.name)
	if rev == 0 {
		return
	}
	code, filed := s.call(s.op, "soakop", "binding:revoke", b.name, "DELETE", fmt.Sprintf("/v1/admin/bindings/%s?expectedRevision=%d", b.name, rev), nil)
	if code != http.StatusAccepted {
		return
	}
	src, dst := accountOfTarget(b.source), accountOfTarget(b.target)
	if s.decideAll(filed, b.name, src, dst, false) {
		s.mu.Lock()
		delete(s.bindings, b.name)
		s.revoked = append(s.revoked, revocation{name: b.name, id: id, acct: src, at: time.Now()})
		s.mu.Unlock()
		s.h.add(event{Kind: "binding:revoked", Res: b.name, Note: b.target})
	}
}

// updateBinding changes a live binding's purpose.
func (s *soakRun) updateBinding() {
	b, ok := s.randomBinding()
	if !ok {
		return
	}
	rev := s.revision("binding", b.name)
	if rev == 0 {
		return
	}
	code, filed := s.call(s.op, "soakop", "binding:update", b.name, "PUT", "/v1/admin/bindings/"+b.name, map[string]any{"name": b.name,
		"source": b.source, "target": b.target, "accessLevel": "read", "purpose": fmt.Sprintf("soak %d", s.rng.IntN(1000)), "expectedRevision": rev})
	if code == http.StatusAccepted {
		s.decideAll(filed, b.name, accountOfTarget(b.source), accountOfTarget(b.target), false)
	}
}

// extraSource registers a source matching no workload, and later retires it.
func (s *soakRun) extraSource() {
	acct := s.accounts[s.rng.IntN(len(s.accounts))]
	name := s.name("src")
	id := "spiffe://prod.lab/acct/" + acct + "/project/p1/sa/x" + strings.ReplaceAll(name, "-", "")
	code, filed := s.call(s.op, "soakop", "source:create", name, "POST", "/v1/admin/sources", map[string]any{"kind": "Source",
		"metadata":   map[string]string{"name": name},
		"identity":   map[string]any{"trustDomain": "prod.lab", "svidRegex": "^" + strings.ReplaceAll(id, ".", `\.`) + "$", "sampleSpiffeIds": []string{id}},
		"visibility": map[string]string{"mode": "PRIVATE"}})
	if code != http.StatusAccepted || !s.decideAll(filed, name, acct, acct, false) {
		return
	}
	rev := s.revision("source", name)
	if rev == 0 {
		return
	}
	code, filed = s.call(s.op, "soakop", "source:retire", name, "POST", "/v1/admin/sources/"+name+"/retire", map[string]any{"expectedRevision": rev})
	if code == http.StatusAccepted {
		s.decideAll(filed, name, acct, acct, false)
	}
}

// abandon files a binding, then declines it (as its source's approver) or
// withdraws it (as its requester).
func (s *soakRun) abandon() {
	acct := s.accounts[s.rng.IntN(len(s.accounts))]
	name := s.name("x")
	code, filed := s.call(s.op, "soakop", "binding:create", name, "POST", "/v1/admin/bindings",
		map[string]any{"name": name, "source": s.sourceOf(acct), "target": s.targetOf(acct, 1+s.rng.IntN(2)), "accessLevel": "read"})
	if code != http.StatusAccepted {
		return
	}
	id := fmt.Sprint(filed["changeRequest"].(map[string]any)["id"])
	if s.rng.IntN(2) == 0 {
		s.call(s.a, "soaka", "change:decline", name, "POST", "/v1/admin/change-requests/"+id+"/decline", map[string]any{"comment": "soak", "side": "SOURCE"})
	} else {
		s.call(s.op, "soakop", "change:withdraw", name, "POST", "/v1/admin/change-requests/"+id+"/withdraw", nil)
	}
}

// rotate rotates a live binding's credential (REAPPLY).
func (s *soakRun) rotate() {
	if b, ok := s.randomBinding(); ok {
		s.call(s.op, "soakop", "binding:rotate", b.name, "POST", "/v1/admin/bindings/"+b.name+"/rotate", nil)
	}
}

// breakGlass creates a binding at once; half are ratified by its sides, the
// others are left for the system to revert when their 5 minutes end.
func (s *soakRun) breakGlass() {
	acct := s.accounts[s.rng.IntN(len(s.accounts))]
	b := soakBinding{name: s.name("bg"), source: s.sourceOf(acct), target: s.targetOf(acct, 1+s.rng.IntN(2))}
	name := b.name
	if s.bound(b.source, b.target) {
		return
	}
	code, filed := s.call(s.bg, "soakbg", "break-glass", name, "POST", "/v1/admin/break-glass", map[string]any{"operation": "CREATE",
		"binding":       map[string]any{"name": name, "source": b.source, "target": b.target, "accessLevel": "read"},
		"justification": "the soak needs the tenancy now, by break-glass", "incidentReference": "INC" + strings.ReplaceAll(name, "-", ""), "ttl": "5m"})
	cr, _ := filed["changeRequest"].(map[string]any)
	if code/100 != 2 || cr == nil {
		return
	}
	if s.rng.IntN(2) == 0 {
		s.h.add(event{Kind: "break-glass:left", Res: name})
		return
	}
	sides, _ := cr["sides"].([]any)
	for _, sd := range sides {
		side := fmt.Sprint(sd.(map[string]any)["side"])
		who, actor := s.decider(side, acct, acct, false)
		s.call(who, actor, "ratify:"+side, name, "POST", "/v1/admin/change-requests/"+fmt.Sprint(cr["id"])+"/ratify",
			map[string]any{"side": side, "comment": "soak"})
	}
	s.mu.Lock()
	s.bindings[name] = b
	s.mu.Unlock()
}

// registerAccount registers an ephemeral account and a source in it, filed by
// ada (admin.full_access) and decided by rita (approver of tenants/*).
func (s *soakRun) registerAccount() {
	s.mu.Lock()
	s.next++
	acct := fmt.Sprintf("e%s%05d", s.x, s.next) // [a-z0-9]+, never reused
	s.mu.Unlock()
	if code, _ := s.call(s.ada, "ada", "account:register", acct, "POST", "/v1/admin/accounts", map[string]any{"name": acct}); code != http.StatusCreated {
		return
	}
	s.mu.Lock()
	s.ephemeral = append(s.ephemeral, acct)
	s.mu.Unlock()
	id := "spiffe://prod.lab/acct/" + acct + "/project/p1/sa/w0"
	code, filed := s.call(s.ada, "ada", "source:create", acct+"-src", "POST", "/v1/admin/sources", map[string]any{"kind": "Source",
		"metadata":   map[string]string{"name": acct + "-src"},
		"identity":   map[string]any{"trustDomain": "prod.lab", "svidRegex": "^" + strings.ReplaceAll(id, ".", `\.`) + "$", "sampleSpiffeIds": []string{id}},
		"visibility": map[string]string{"mode": "PRIVATE"}})
	if code == http.StatusAccepted {
		s.decideAll(filed, acct+"-src", acct, acct, true)
	}
}

// retireAccount retires an ephemeral account's source, then the account.
func (s *soakRun) retireAccount() {
	s.mu.Lock()
	if len(s.ephemeral) == 0 {
		s.mu.Unlock()
		return
	}
	acct := s.ephemeral[0]
	s.ephemeral = s.ephemeral[1:]
	s.mu.Unlock()
	if rev := s.revision("source", acct+"-src"); rev != 0 {
		code, filed := s.call(s.ada, "ada", "source:retire", acct+"-src", "POST", "/v1/admin/sources/"+acct+"-src/retire", map[string]any{"expectedRevision": rev})
		if code == http.StatusAccepted {
			s.decideAll(filed, acct+"-src", acct, acct, true)
		}
	}
	s.call(s.ada, "ada", "account:retire", acct, "POST", "/v1/admin/accounts/"+acct+"/retire", nil)
}

// abuse files a binding inside one account and tries what four-eyes forbids:
// its requester approving it, then its SOURCE approver approving TARGET too
// (INV-18). Each must be refused; if one is not, SK-4 is broken at once, and
// its SQL finds the change too. The binding is then decided properly.
func (s *soakRun) abuse() {
	acct := s.accounts[s.rng.IntN(len(s.accounts))]
	b := soakBinding{name: s.name("ab"), source: s.sourceOf(acct), target: s.targetOf(acct, 1+s.rng.IntN(2))}
	if s.bound(b.source, b.target) {
		return
	}
	code, filed := s.call(s.op, "soakop", "binding:create", b.name, "POST", "/v1/admin/bindings",
		map[string]any{"name": b.name, "source": b.source, "target": b.target, "accessLevel": "read"})
	cr, _ := filed["changeRequest"].(map[string]any)
	if code != http.StatusAccepted || cr == nil {
		return
	}
	approve := func(who *admin, actor, side string) (int, map[string]any) {
		return s.call(who, actor, "abuse:"+side, b.name, "POST", "/v1/admin/change-requests/"+fmt.Sprint(cr["id"])+"/approve",
			map[string]any{"payloadSha256": cr["payloadSha256"], "side": side, "comment": "soak: must be refused"})
	}
	if code, _ := approve(s.op, "soakop", "SOURCE"); code/100 == 2 {
		s.violation("SK-4", b.name+": its requester approved it")
	}
	if code, body := approve(s.a, "soaka", "SOURCE"); code == http.StatusOK {
		if code, _ := approve(s.a, "soaka", "TARGET"); code/100 == 2 {
			s.violation("SK-4", b.name+": one person approved SOURCE and TARGET")
		}
		filed = body
	}
	if s.decideAll(filed, b.name, acct, acct, false) {
		s.mu.Lock()
		s.bindings[b.name] = b
		s.mu.Unlock()
	}
}

// read is one of the read-only calls people make.
func (s *soakRun) read() {
	paths := []string{"/v1/admin/bindings?pageSize=50", "/v1/admin/accounts", "/v1/admin/change-requests?awaitingMe=true",
		"/v1/admin/charter", "/v1/admin/catalog/targets", "/v1/admin/sources?pageSize=50"}
	who, actor := s.a, "soaka"
	if s.rng.IntN(2) == 0 {
		who, actor = s.ada, "ada"
	}
	p := paths[s.rng.IntN(len(paths))]
	s.call(who, actor, "read", p, "GET", p, nil)
}

// workload is the workload of account s<i>: it asks ligo for its
// bindings with its X.509-SVID, takes one's credential from the store with its
// JWT-SVID, and reads that tenancy. The SVIDs are re-read on every call, since
// lab.sh renews them while the soak runs.
func (s *soakRun) workload(i int) {
	who := fmt.Sprintf("soakw%d", i)
	dir := os.Getenv("LIGO_E2E_DIR")
	e := event{Kind: "workload", Actor: who, Worker: i}
	defer func() { s.h.add(e) }()
	start := time.Now()
	cfg, err := ligoTLSConfig(dir, who)
	if err != nil {
		e.Err = "svid: " + err.Error()
		return
	}
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	defer client.CloseIdleConnections()
	resp, err := client.Get(os.Getenv("LIGO_E2E_WORKLOAD") + "/v1/bindings")
	if err != nil {
		e.Err, e.MS = "bindings: "+err.Error(), time.Since(start).Milliseconds()
		return
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	_ = resp.Body.Close()
	e.Code = resp.StatusCode
	list := items(body)
	if resp.StatusCode != http.StatusOK || len(list) == 0 {
		e.MS, e.Note = time.Since(start).Milliseconds(), "no binding"
		return
	}
	item := list[s.workerRand(i).IntN(len(list))]
	e.Res = fmt.Sprint(item["name"])
	auth, _ := item["auth"].(map[string]any)
	ac, _ := auth["config"].(map[string]any)
	if ac == nil {
		e.Err = "no auth config"
		return
	}
	user, password, err := storeFetch(ac, filepath.Join(dir, who+"-store-jwt"), os.Getenv("LIGO_TEST_CA"), os.Getenv("LIGO_E2E_SECRETS"), "secretPath", kvCredential)
	if err != nil {
		e.Err, e.MS = "store: "+err.Error(), time.Since(start).Milliseconds()
		return
	}
	e.Note = "user " + user
	target := fmt.Sprint(item["target"])
	schema := strings.Replace(target[:strings.LastIndex(target, "-")], "-", "_", 1)
	conn, err := ledgerConn(s.t, user, password)
	if err != nil {
		e.Err, e.MS = "connect: "+err.Error(), time.Since(start).Milliseconds()
		return
	}
	defer func() { _ = conn.Close(context.Background()) }()
	var n int
	if err := conn.QueryRow(context.Background(), "SELECT count(*) FROM "+schema+".entries").Scan(&n); err != nil {
		e.Err = "read " + schema + ": " + err.Error()
	}
	e.MS = time.Since(start).Milliseconds()
}

// workerRand is a workload loop's own source, from the seed, so that the loops
// do not share the generator's.
var (
	workerRands   = map[int]*rand.Rand{}
	workerRandsMu sync.Mutex
)

func (s *soakRun) workerRand(i int) *rand.Rand {
	workerRandsMu.Lock()
	defer workerRandsMu.Unlock()
	r, ok := workerRands[i]
	if !ok {
		seed, _ := strconv.ParseUint(soakEnv("SEED", "1"), 10, 64)
		r = rand.New(rand.NewPCG(seed, uint64(i)+1))
		workerRands[i] = r
	}
	return r
}

// TestSoak is the generator: setup, then actions every 2 seconds and the
// workload loops every 30, until LIGO_SOAK_DURATION ends.
func TestSoak(t *testing.T) {
	seed, err := strconv.ParseUint(soakEnv("SEED", ""), 10, 64)
	if err != nil {
		t.Fatalf("LIGO_SOAK_SEED: %v", err)
	}
	duration, err := time.ParseDuration(soakEnv("DURATION", "15m"))
	if err != nil {
		t.Fatalf("LIGO_SOAK_DURATION: %v", err)
	}
	n, err := strconv.Atoi(soakEnv("ACCOUNTS", "20"))
	if err != nil || n < 1 || n > 100 {
		t.Fatalf("LIGO_SOAK_ACCOUNTS: %q", soakEnv("ACCOUNTS", ""))
	}
	f, err := os.OpenFile(e2eEnv(t, "LIGO_SOAK_HISTORY"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	s := &soakRun{t: t, x: e2eEnv(t, "LIGO_E2E_SUFFIX"), rng: rand.New(rand.NewPCG(seed, 0)), h: &history{f: f},
		op: soakAdmin(t, "soakop"), a: soakAdmin(t, "soaka"), b: soakAdmin(t, "soakb"), bg: soakAdmin(t, "soakbg"),
		ada: renewingAdmin(t, "ada"), rita: renewingAdmin(t, "rita"), peter: renewingAdmin(t, "peter"), bindings: map[string]soakBinding{}}
	s.checkRng = rand.New(rand.NewPCG(seed, 1<<32))
	s.ada2 = renewingAdmin(t, "ada")
	s.ada2.base = e2eEnv(t, "LIGO_E2E_ADMIN2")
	for i := range n {
		s.accounts = append(s.accounts, fmt.Sprintf("s%02d", i))
	}
	s.h.add(event{Kind: "start", Note: fmt.Sprintf("seed %d, duration %v, accounts %d", seed, duration, n)})
	s.setup()
	s.h.add(event{Kind: "setup:done"})

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	var wg sync.WaitGroup
	for i := range s.workloads() {
		wg.Go(func() {
			tick := time.NewTicker(30 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					s.workload(i)
				}
			}
		})
	}
	wg.Go(func() { // the checker, every minute
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				s.check(false)
			}
		}
	})
	counts := map[string]int{}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
			a := s.pick()
			counts[a.name]++
			a.run(s)
		}
	}
	wg.Wait()
	s.converge()
	time.Sleep(sk1Limit) // the revocations of the last ticks reach their limit
	s.check(true)
	s.mu.Lock()
	live, violations := len(s.bindings), s.violations
	s.mu.Unlock()
	s.h.add(event{Kind: "end", Note: fmt.Sprintf("actions %v, live bindings %d, violations %d", counts, live, violations)})
	t.Logf("soak: actions %v, live bindings %d, violations %d", counts, live, violations)
	if violations > 0 {
		t.Errorf("%d violations: see the history", violations)
	}
}
