// SPDX-License-Identifier: MIT

package adminclient

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// scriptedClient is a client whose reads of change requests and bindings are
// scripted, whose sleeps are recorded and instant, and whose jitter is off.
type scriptedClient struct {
	*Client
	slept    []time.Duration
	crReads  int
	bindings int
}

func newScripted(t *testing.T, cr func(n int) (ChangeRequest, error), binding func(n int) (BindingDetail, error)) *scriptedClient {
	t.Helper()
	c, err := New(Config{ServerURL: "https://ligo.lab:9443", RootCAs: x509.NewCertPool(), Basic: &BasicAuth{Username: "a", Password: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	s := &scriptedClient{Client: c}
	c.jitter = func(d time.Duration) time.Duration { return d }
	c.sleep = func(ctx context.Context, d time.Duration) error {
		s.slept = append(s.slept, d)
		return ctx.Err()
	}
	c.getCR = func(context.Context, string) (ChangeRequest, error) { s.crReads++; return cr(s.crReads) }
	c.getBinding = func(context.Context, string) (BindingDetail, error) {
		s.bindings++
		return binding(s.bindings)
	}
	return s
}

func crWith(status string) ChangeRequest {
	var cr ChangeRequest
	cr.Status = ChangeRequestStatus(status)
	cr.ResourceType, cr.ResourceName, cr.Operation = "BINDING", "b", "CREATE"
	return cr
}

func bindingIn(phase, message string) BindingDetail {
	var b BindingDetail
	b.Status.Phase, b.Status.Message = BindingPhase(phase), message
	return b
}

func problemErr(status int, slug string, retryAfter time.Duration) error {
	return fmt.Errorf("adminclient: %w", &Problem{Status: status, Type: problemPrefix + slug, RetryAfter: retryAfter})
}

// TestWaitChangeRequest is AC-7: it returns at each terminal state, paces
// itself, backs off after failures, honours Retry-After, and returns the
// context's error with the last state when the context ends.
func TestWaitChangeRequest(t *testing.T) {
	ctx := context.Background()
	for _, status := range []string{"APPLIED", "REJECTED", "WITHDRAWN", "EXPIRED", "FAILED_TO_APPLY", "SOMETHING_NEW"} {
		s := newScripted(t, func(n int) (ChangeRequest, error) {
			if n < 3 {
				return crWith("PENDING"), nil
			}
			return crWith(status), nil
		}, nil)
		cr, err := s.WaitChangeRequest(ctx, someID, WaitOptions{})
		if err != nil || string(cr.Status) != status || s.crReads != 3 {
			t.Errorf("%s: %q after %d reads, %v", status, cr.Status, s.crReads, err)
		}
		if !slices.Equal(s.slept, []time.Duration{2 * time.Second, 2 * time.Second}) {
			t.Errorf("%s: slept %v", status, s.slept)
		}
		if IsApplied(cr) != (status == "APPLIED") || !IsTerminal(cr) {
			t.Errorf("%s: IsApplied %v, IsTerminal %v", status, IsApplied(cr), IsTerminal(cr))
		}
	}
	if IsTerminal(crWith("PENDING")) {
		t.Error("PENDING is not terminal")
	}

	// the floor of the interval, and a custom one
	s := newScripted(t, func(n int) (ChangeRequest, error) {
		if n < 3 {
			return crWith("PENDING"), nil
		}
		return crWith("APPLIED"), nil
	}, nil)
	if _, err := s.WaitChangeRequest(ctx, someID, WaitOptions{Interval: time.Millisecond}); err != nil || s.slept[0] != time.Second {
		t.Errorf("a 1 ms interval: %v, %v", s.slept, err)
	}

	// failures that may pass: the pause doubles to the ceiling, Retry-After raises it, a success resets it
	script := []error{nil, problemErr(503, "unavailable", 0), problemErr(503, "unavailable", 0), problemErr(503, "unavailable", 0), problemErr(503, "unavailable", 0),
		problemErr(429, "rate-limited", 7*time.Second), nil, nil}
	s = newScripted(t, func(n int) (ChangeRequest, error) {
		if n > len(script) {
			return crWith("APPLIED"), nil
		}
		if err := script[n-1]; err != nil {
			return ChangeRequest{}, err
		}
		return crWith("PENDING"), nil
	}, nil)
	if cr, err := s.WaitChangeRequest(ctx, someID, WaitOptions{Interval: 2 * time.Second, MaxInterval: 10 * time.Second}); err != nil || !IsApplied(cr) {
		t.Fatalf("%v, %v", cr.Status, err)
	}
	// seconds: a pending read; four failures (the pause doubles: 4, 8, then the ceiling 10, 10); a 429
	// asking 7 s, which does not lower the pause (10); two pending reads after the success (2, 2)
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second, 10 * time.Second, 2 * time.Second, 2 * time.Second}
	if !slices.Equal(s.slept, want) {
		t.Errorf("slept %v, want %v", s.slept, want)
	}

	// a Retry-After above the pause raises it, up to the ceiling
	s = newScripted(t, func(n int) (ChangeRequest, error) {
		if n == 1 {
			return ChangeRequest{}, problemErr(503, "maintenance", 25*time.Second)
		}
		return crWith("APPLIED"), nil
	}, nil)
	if _, err := s.WaitChangeRequest(ctx, someID, WaitOptions{Interval: 2 * time.Second, MaxInterval: 20 * time.Second}); err != nil || !slices.Equal(s.slept, []time.Duration{20 * time.Second}) {
		t.Errorf("Retry-After above the ceiling: %v, %v", s.slept, err)
	}
	s = newScripted(t, func(n int) (ChangeRequest, error) {
		if n == 1 {
			return ChangeRequest{}, problemErr(503, "maintenance", 9*time.Second)
		}
		return crWith("APPLIED"), nil
	}, nil)
	if _, err := s.WaitChangeRequest(ctx, someID, WaitOptions{Interval: 2 * time.Second, MaxInterval: 20 * time.Second}); err != nil || !slices.Equal(s.slept, []time.Duration{9 * time.Second}) {
		t.Errorf("Retry-After of 9 s: %v, %v", s.slept, err)
	}

	// a failure that cannot pass ends the wait
	for name, err := range map[string]error{
		"not found":       problemErr(404, "not-found", 0),
		"unauthenticated": problemErr(401, "unauthenticated", 0),
		"forbidden":       problemErr(403, "forbidden", 0),
		"a bad body":      errors.New("not what the contract says"),
	} {
		s = newScripted(t, func(n int) (ChangeRequest, error) {
			if n == 1 {
				return crWith("PENDING"), nil
			}
			return ChangeRequest{}, err
		}, nil)
		cr, got := s.WaitChangeRequest(ctx, someID, WaitOptions{})
		if got == nil || !strings.Contains(got.Error(), someID) || s.crReads != 2 || cr.Status != "PENDING" {
			t.Errorf("%s: %v after %d reads, last %q", name, got, s.crReads, cr.Status)
		}
	}

	// the context ends: its error, and the last state read
	cctx, cancel := context.WithCancel(ctx)
	s = newScripted(t, func(n int) (ChangeRequest, error) {
		if n == 3 {
			cancel()
		}
		return crWith("PENDING"), nil
	}, nil)
	cr, err := s.WaitChangeRequest(cctx, someID, WaitOptions{})
	if !errors.Is(err, context.Canceled) || cr.Status != "PENDING" || !strings.Contains(err.Error(), "PENDING") {
		t.Errorf("a cancelled context: %v, %q", err, cr.Status)
	}
}

// TestWaitUntilBindingActive: an applied binding is waited for until ACTIVE;
// a failed one is ErrBindingFailed; other resources and deletions are not.
func TestWaitUntilBindingActive(t *testing.T) {
	ctx := context.Background()
	applied := func(n int) (ChangeRequest, error) { return crWith("APPLIED"), nil }
	s := newScripted(t, applied, func(n int) (BindingDetail, error) {
		if n < 3 {
			return bindingIn("PROVISIONING", ""), nil
		}
		return bindingIn("ACTIVE", ""), nil
	})
	if cr, err := s.WaitChangeRequest(ctx, someID, WaitOptions{UntilBindingActive: true}); err != nil || !IsApplied(cr) || s.bindings != 3 {
		t.Errorf("%v, %d reads, %v", cr.Status, s.bindings, err)
	}

	s = newScripted(t, applied, func(n int) (BindingDetail, error) { return bindingIn("FAILED", "the database refused"), nil })
	cr, err := s.WaitChangeRequest(ctx, someID, WaitOptions{UntilBindingActive: true})
	if !errors.Is(err, ErrBindingFailed) || !strings.Contains(err.Error(), "the database refused") || !IsApplied(cr) {
		t.Errorf("a failed binding: %v", err)
	}

	for name, mutate := range map[string]func(*ChangeRequest){
		"a deletion":     func(cr *ChangeRequest) { cr.Operation = "DELETE" },
		"a target":       func(cr *ChangeRequest) { cr.ResourceType = "TARGET" },
		"not applied":    func(cr *ChangeRequest) { cr.Status = "REJECTED" },
		"no such option": nil,
	} {
		s = newScripted(t, func(int) (ChangeRequest, error) {
			cr := crWith("APPLIED")
			if mutate != nil {
				mutate(&cr)
			}
			return cr, nil
		}, func(int) (BindingDetail, error) { return bindingIn("PROVISIONING", ""), nil })
		if _, err := s.WaitChangeRequest(ctx, someID, WaitOptions{UntilBindingActive: mutate != nil}); err != nil || s.bindings != 0 {
			t.Errorf("%s: %d binding reads, %v", name, s.bindings, err)
		}
	}
}

// TestRetries: a GET is repeated after a busy or broken server, with a
// backoff and the server's Retry-After; nothing else is.
func TestRetries(t *testing.T) {
	ctx := context.Background()
	type result struct {
		err   error
		calls int
		slept []time.Duration
	}
	run := func(h func(n int, w http.ResponseWriter), maxRetries int, op func(*Client) error) result {
		var n atomic.Int32
		u, pool := serveTLS(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h(int(n.Add(1)), w) }))
		c, err := New(Config{ServerURL: u, RootCAs: pool, Basic: &BasicAuth{Username: "a", Password: "b"}, MaxRetries: maxRetries})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		var slept []time.Duration
		c.jitter = func(d time.Duration) time.Duration { return d }
		c.sleep = func(ctx context.Context, d time.Duration) error { slept = append(slept, d); return ctx.Err() }
		err = op(c)
		return result{err, int(n.Load()), slept}
	}
	get := func(c *Client) error { _, err := c.GetSource(ctx, "s"); return err }
	busy := func(code int, retryAfter string) func(int, http.ResponseWriter) {
		return func(n int, w http.ResponseWriter) {
			if n < 3 {
				if retryAfter != "" {
					w.Header().Set("Retry-After", retryAfter)
				}
				problem(w, code, "unavailable", "busy")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"metadata":{"name":"s"}}`))
		}
	}

	// 503, 502, 504 and 429 pass after two retries, with the doubling backoff
	for _, code := range []int{503, 502, 504, 429} {
		r := run(busy(code, ""), 0, get)
		if r.err != nil || r.calls != 3 || !slices.Equal(r.slept, []time.Duration{200 * time.Millisecond, 400 * time.Millisecond}) {
			t.Errorf("%d: %v after %d calls, slept %v", code, r.err, r.calls, r.slept)
		}
	}
	// Retry-After is honoured, up to 30 s; beyond that the client gives up and says so
	if r := run(busy(503, "3"), 0, get); r.err != nil || !slices.Equal(r.slept, []time.Duration{3 * time.Second, 3 * time.Second}) {
		t.Errorf("Retry-After 3: %v, %v", r.err, r.slept)
	}
	r := run(busy(503, "120"), 0, get)
	var p *Problem
	if !errors.As(r.err, &p) || p.RetryAfter != 2*time.Minute || r.calls != 1 || len(r.slept) != 0 {
		t.Errorf("Retry-After 120: %v after %d calls, slept %v", r.err, r.calls, r.slept)
	}
	// the number of retries is bounded, and can be turned off
	if r := run(func(n int, w http.ResponseWriter) { problem(w, 503, "unavailable", "down") }, 0, get); !errors.Is(r.err, ErrUnavailable) || r.calls != 3 {
		t.Errorf("always down: %v after %d calls", r.err, r.calls)
	}
	if r := run(func(n int, w http.ResponseWriter) { problem(w, 503, "unavailable", "down") }, 5, get); r.calls != 6 || len(r.slept) != 5 {
		t.Errorf("five retries: %d calls, slept %v", r.calls, r.slept)
	}
	if r := run(func(n int, w http.ResponseWriter) { problem(w, 503, "unavailable", "down") }, -1, get); r.calls != 1 {
		t.Errorf("no retries: %d calls", r.calls)
	}
	// a broken connection is repeated
	broken := func(n int, w http.ResponseWriter) {
		if n < 2 {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"metadata":{"name":"s"}}`))
	}
	if r := run(broken, 0, get); r.err != nil || r.calls != 2 {
		t.Errorf("a broken connection: %v after %d calls", r.err, r.calls)
	}
	// an answer that cannot change is not repeated
	for _, code := range []int{400, 401, 403, 404, 409, 422, 500} {
		if r := run(func(n int, w http.ResponseWriter) { problem(w, code, "x", "no") }, 0, get); r.calls != 1 {
			t.Errorf("%d was repeated: %d calls", code, r.calls)
		}
	}
	// a mutation is never repeated, whatever the answer
	for _, code := range []int{503, 502, 429} {
		r := run(func(n int, w http.ResponseWriter) { problem(w, code, "unavailable", "busy") }, 0, func(c *Client) error {
			_, err := c.CreateSource(ctx, someSource(), Options{})
			return err
		})
		if r.calls != 1 {
			t.Errorf("a creation answered %d was sent %d times", code, r.calls)
		}
	}
	// a caller who gave up is not retried
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if r := run(busy(503, ""), 0, func(c *Client) error { _, err := c.GetSource(cctx, "s"); return err }); r.calls != 0 || !errors.Is(r.err, context.Canceled) {
		t.Errorf("a cancelled context: %v, %d calls", r.err, r.calls)
	}
}

// TestBackoff: the pause doubles from 200 ms to 5 s and is jittered within half of it.
func TestBackoff(t *testing.T) {
	c := &Client{jitter: jitter}
	for attempt, base := range []time.Duration{200 * time.Millisecond, 400 * time.Millisecond, 800 * time.Millisecond, 1600 * time.Millisecond, 3200 * time.Millisecond, 5 * time.Second, 5 * time.Second} {
		for range 200 {
			if d := c.backoff(attempt); d < base/2 || d > base+base/2 {
				t.Fatalf("attempt %d: %s, want within [%s, %s]", attempt, d, base/2, base+base/2)
			}
		}
	}
	if d := c.backoff(1000); d > 8*time.Second {
		t.Errorf("a huge attempt number: %s", d)
	}
}
