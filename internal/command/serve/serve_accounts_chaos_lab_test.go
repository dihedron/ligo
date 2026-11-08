//go:build lab

package serve

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The accounts under load and faults, run by lab.sh serve test-accounts-chaos,
// which kills replicas and stops PostgreSQL and the directory between and during
// these tests. Their numbers are in the log, for the record.

const scaleAccounts = 300

// try is do for a replica that may be down: an error, never a failed test. It
// waits out the API's limit per principal, which holds here as it should.
func (a *admin) try(method, path string, body any) (int, map[string]any, error) {
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(250 * time.Millisecond) {
		code, out, err := a.once(method, path, body)
		if err != nil || code != http.StatusTooManyRequests || time.Now().After(deadline) {
			return code, out, err
		}
	}
}

func (a *admin) once(method, path string, body any) (int, map[string]any, error) {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, a.base+path, bytes.NewReader(data))
	if a.user != "" {
		req.SetBasicAuth(a.user, a.pass)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, nil
}

// latency times n requests of path as who, and returns the 50th and 95th
// percentiles; a request that is not 200 fails the test.
func latency(t *testing.T, who *admin, path string, n int) (p50, p95 time.Duration) {
	t.Helper()
	times := make([]time.Duration, 0, n)
	for range n {
		time.Sleep(300 * time.Millisecond) // under the API's limit, which would otherwise be what this measures
		start := time.Now()
		if code, b := who.do("GET", path, nil); code != http.StatusOK {
			t.Fatalf("GET %s: %d %v", path, code, b)
		}
		times = append(times, time.Since(start))
	}
	slices.Sort(times)
	return times[n/2], times[n*95/100]
}

// TestAccountsChaosScale: hundreds of accounts, with a person in one and a
// person in all of them. Groups exist for each (lab.sh).
func TestAccountsChaosScale(t *testing.T) {
	ada, alan, sue := newAdmin(t, "ada"), newAdmin(t, "alan"), newAdmin(t, "sue")
	if code, b := ada.do("POST", "/v1/admin/accounts", map[string]any{"name": "acme"}); code != http.StatusCreated {
		t.Fatalf("register acme: %d %v", code, b)
	}
	before, _ := latency(t, alan, "/v1/admin/accounts", 20)

	names := make(chan string)
	var failed atomic.Int32
	var wg sync.WaitGroup
	start := time.Now()
	for range 8 {
		wg.Go(func() {
			for name := range names {
				if code, _, err := ada.try("POST", "/v1/admin/accounts", map[string]any{"name": name}); err != nil || code != http.StatusCreated {
					failed.Add(1)
				}
			}
		})
	}
	for i := range scaleAccounts {
		names <- fmt.Sprintf("scale%03d", i)
	}
	close(names)
	wg.Wait()
	if n := failed.Load(); n != 0 {
		t.Fatalf("%d registrations failed", n)
	}
	t.Logf("registered %d accounts in %v, 8 at a time, under the API's limit per principal", scaleAccounts, time.Since(start).Round(time.Millisecond))

	for _, base := range []string{e2eEnv(t, "LIGO_E2E_ADMIN"), e2eEnv(t, "LIGO_E2E_ADMIN2")} {
		sue.base = base
		// the registry takes a moment on the other replica
		var seen int
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(200 * time.Millisecond) {
			seen = 0
			for path := "/v1/admin/accounts?pageSize=200"; ; {
				code, b, err := sue.try("GET", path, nil)
				if err != nil || code != http.StatusOK {
					t.Fatalf("sue on %s: %d %v %v", base, code, b, err)
				}
				seen += len(b["items"].([]any))
				next, _ := b["nextPageToken"].(string)
				if next == "" {
					break
				}
				path = "/v1/admin/accounts?pageSize=200&pageToken=" + url.QueryEscape(next)
			}
			if seen >= scaleAccounts || time.Now().After(deadline) {
				break
			}
		}
		if seen < scaleAccounts {
			t.Errorf("sue on %s sees %d accounts, want %d", base, seen, scaleAccounts)
		}
	}
	sue.base = e2eEnv(t, "LIGO_E2E_ADMIN")
	after, afterP95 := latency(t, alan, "/v1/admin/accounts", 20)
	all, allP95 := latency(t, sue, "/v1/admin/accounts?pageSize=200", 20)
	t.Logf("a person in one account: p50 %v before, p50 %v p95 %v after", before.Round(time.Millisecond), after.Round(time.Millisecond), afterP95.Round(time.Millisecond))
	t.Logf("a person in all %d: p50 %v p95 %v, a page of 200", scaleAccounts, all.Round(time.Millisecond), allP95.Round(time.Millisecond))
	if afterP95 > 2*time.Second || allP95 > 2*time.Second {
		t.Errorf("a request takes over 2s at p95: %v, %v", afterP95, allP95)
	}
}

// TestAccountsChaosRace: registering, then approving a source while retiring
// its account, on either replica, with lab.sh killing replicas meanwhile. What
// must hold is checked from the database afterwards: no resource that is not
// retired on a retired account, and an intact audit chain.
func TestAccountsChaosRace(t *testing.T) {
	x := e2eEnv(t, "LIGO_E2E_SUFFIX")
	bases := []string{e2eEnv(t, "LIGO_E2E_ADMIN"), e2eEnv(t, "LIGO_E2E_ADMIN2")}
	on := func(who string, round int) *admin {
		a := newAdmin(t, who)
		a.client.Timeout = 15 * time.Second
		a.base = bases[round%2]
		return a
	}
	var complete, applied, retired, interrupted int
	start := time.Now()
	for round := 0; time.Since(start) < 5*time.Minute; round++ {
		name := fmt.Sprintf("r%sn%d", x, round)
		ada := on("ada", round)
		if code, _, err := ada.try("POST", "/v1/admin/accounts", map[string]any{"name": name}); err != nil || code != http.StatusCreated {
			interrupted++
			time.Sleep(time.Second)
			continue
		}
		id := "spiffe://prod.lab/acct/" + name + "/project/p/sa/w"
		code, filed, err := ada.try("POST", "/v1/admin/sources", map[string]any{"kind": "Source", "metadata": map[string]string{"name": "src-" + name},
			"identity":   map[string]any{"trustDomain": "prod.lab", "svidRegex": "^" + strings.ReplaceAll(id, ".", `\.`) + "$", "sampleSpiffeIds": []string{id}},
			"visibility": map[string]string{"mode": "PUBLIC"}})
		if err != nil || code != http.StatusAccepted {
			// the registry of a replica just restarted may lag; the refusal is correct
			interrupted++
			continue
		}
		cr := filed["changeRequest"].(map[string]any)
		rita := on("rita", round+1)
		var approve, retire int
		var wg sync.WaitGroup
		wg.Go(func() {
			approve, _, _ = rita.try("POST", "/v1/admin/change-requests/"+cr["id"].(string)+"/approve",
				map[string]any{"payloadSha256": cr["payloadSha256"], "side": "OWNER", "comment": "race"})
		})
		wg.Go(func() { retire, _, _ = ada.try("POST", "/v1/admin/accounts/"+name+"/retire", nil) })
		wg.Wait()
		switch {
		case approve == http.StatusOK && retire == http.StatusConflict:
			applied++
			complete++
		case retire == http.StatusOK && approve != http.StatusOK:
			retired++
			complete++
		case approve == http.StatusOK && retire == http.StatusOK:
			t.Errorf("%s: the source was approved and the account retired", name)
		default:
			interrupted++
		}
	}
	t.Logf("%d rounds complete: the source won %d, the retirement %d; %d interrupted by the kills", complete, applied, retired, interrupted)
	if complete < 200 {
		t.Errorf("only %d rounds completed", complete)
	}
}

// ivanCan waits until ivan's access to initech on both replicas is want.
func ivanCan(t *testing.T, want int, within time.Duration) {
	t.Helper()
	for _, base := range []string{e2eEnv(t, "LIGO_E2E_ADMIN"), e2eEnv(t, "LIGO_E2E_ADMIN2")} {
		ivan := newAdmin(t, "ivan")
		ivan.base = base
		start := time.Now()
		for {
			code, _, err := ivan.try("GET", "/v1/admin/accounts/initech", nil)
			if err == nil && code == want {
				t.Logf("%s: %d after %v", base, want, time.Since(start).Round(time.Millisecond))
				break
			}
			if time.Since(start) > within {
				t.Fatalf("%s: %d (%v), want %d", base, code, err, want)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

// TestAccountsChaosBeforeRestart registers initech before PostgreSQL restarts.
func TestAccountsChaosBeforeRestart(t *testing.T) {
	if code, b := newAdmin(t, "ada").do("POST", "/v1/admin/accounts", map[string]any{"name": "initech"}); code != http.StatusCreated {
		t.Fatalf("register: %d %v", code, b)
	}
	ivanCan(t, http.StatusOK, 10*time.Second)
}

// TestAccountsChaosAfterRestart: the registries' listeners came back: a
// retirement reaches both replicas well before the periodic reload.
func TestAccountsChaosAfterRestart(t *testing.T) {
	ada := newAdmin(t, "ada")
	start := time.Now()
	for {
		code, _, err := ada.try("POST", "/v1/admin/accounts/initech/retire", nil)
		if err == nil && code == http.StatusOK {
			break
		}
		if time.Since(start) > time.Minute {
			t.Fatalf("retire: %d %v", code, err)
		}
		time.Sleep(time.Second)
	}
	ivanCan(t, http.StatusForbidden, 15*time.Second)
}

func waitMarker(t *testing.T, name string) {
	t.Helper()
	path := filepath.Join(e2eEnv(t, "LIGO_E2E_DIR"), name)
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(200 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("lab.sh never wrote %s", name)
		}
	}
}

var preloginInput = regexp.MustCompile(`name="prelogin" value="([0-9a-f]{64})"`)

// TestAccountsChaosDirectory: lab.sh stops the directory and ages this session
// between the markers. A session due for its check is refused, not ended and
// not left with its roles; Basic credentials are refused; SVIDs keep working;
// with the directory back, the same session works again.
func TestAccountsChaosDirectory(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: ligoTLS(t, "")},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	base := e2eEnv(t, "LIGO_E2E_ADMIN")
	page := func(method, path string, form url.Values) (int, string) {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequest(method, base+path, body)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(data)
	}
	_, login := page("GET", "/ui/login", nil)
	m := preloginInput.FindStringSubmatch(login)
	if m == nil {
		t.Fatalf("no pre-login field: %s", login)
	}
	if code, body := page("POST", "/ui/login", url.Values{"prelogin": {m[1]}, "username": {"alan"}, "password": {e2eEnv(t, "LIGO_TEST_LDAP_ALAN_PASS")}}); code >= 400 {
		t.Fatalf("login: %d %s", code, body)
	}
	if code, body := page("GET", "/ui/accounts", nil); code != http.StatusOK || !strings.Contains(body, "acme") {
		t.Fatalf("alan's page before: %d %s", code, body)
	}
	if err := os.WriteFile(filepath.Join(e2eEnv(t, "LIGO_E2E_DIR"), "session-ready"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitMarker(t, "directory-down")

	if code, body := page("GET", "/ui/accounts", nil); code != http.StatusServiceUnavailable {
		t.Errorf("a session due for its check, directory down: %d %s", code, body)
	}
	if code, _, err := newAdmin(t, "alan").try("GET", "/v1/admin/accounts", nil); err == nil && code == http.StatusOK {
		t.Error("Basic credentials work with the directory down")
	}
	if code, b := newAdmin(t, "ada").do("GET", "/v1/admin/accounts", nil); code != http.StatusOK {
		t.Errorf("an SVID with the directory down: %d %v", code, b)
	}
	if err := os.WriteFile(filepath.Join(e2eEnv(t, "LIGO_E2E_DIR"), "session-checked"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitMarker(t, "directory-up")

	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(500 * time.Millisecond) {
		code, body := page("GET", "/ui/accounts", nil)
		if code == http.StatusOK && strings.Contains(body, "acme") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the session did not recover: %d %s", code, body)
		}
	}
}
