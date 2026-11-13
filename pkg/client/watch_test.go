package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// scripted is a transport that answers each poll with the next step, and
// the last one for ever.
type scripted struct {
	steps []step
	polls []time.Time
	t     *testing.T
}

type step struct {
	items []Binding
	err   error
}

func (s *scripted) bindings(_ context.Context, f Filter, _ string) ([]Binding, string, bool, error) {
	if f.WatchCredentials || f.Target != "ledger" {
		s.t.Errorf("filter %+v", f)
	}
	st := s.steps[min(len(s.polls), len(s.steps)-1)]
	s.polls = append(s.polls, time.Now())
	return st.items, "", false, st.err
}

func (s *scripted) flows(context.Context, Filter, string) ([]BindingFlows, string, bool, error) {
	return nil, "", false, nil
}

func (s *scripted) close() error { return nil }

// watching runs Watch on a scripted transport for d, inside a synctest
// bubble, and returns its events as text and its logs.
func watching(t *testing.T, v *env, s *scripted, credential func(context.Context, Binding) (Credential, error), d time.Duration) ([]string, []Event, string) {
	t.Helper()
	s.t = t
	logs := &bytes.Buffer{}
	c, err := New(t.Context(), Config{Address: "ligo.lab:8443", ServerID: ligoID, X509Source: v.source, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	c.transport, c.readCredential = s, credential
	var said []string
	var events []Event
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- c.Watch(ctx, Filter{Target: "ledger", WatchCredentials: credential != nil}, func(ev Event) {
			name := ev.Binding.Name
			if ev.Kind == Removed {
				name = ev.Previous.Name
			}
			said, events = append(said, fmt.Sprintf("%s %s r%d %s", ev.Kind, name, ev.Binding.Revision, ev.Credential.Username)), append(events, ev)
		})
	}()
	time.Sleep(d)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("Watch returned %v", err)
	}
	return said, events, logs.String()
}

// TestWatch is CS-11.
func TestWatch(t *testing.T) {
	v := newEnv(t)
	a1, a2, b1 := Binding{ID: "1", Name: "a", Revision: 1}, Binding{ID: "1", Name: "a", Revision: 2}, Binding{ID: "2", Name: "b", Revision: 1}
	synctest.Test(t, func(t *testing.T) {
		s := &scripted{steps: []step{{items: []Binding{b1, a1}}, {items: []Binding{b1, a2}}, {items: []Binding{a2}}}}
		start, n := time.Now(), 0
		var reads []time.Duration
		said, events, logs := watching(t, v, s, func(_ context.Context, b Binding) (Credential, error) {
			if b.Name == "b" {
				return Credential{}, ErrNoCredential // an SVID-only binding
			}
			n++
			reads = append(reads, time.Since(start))
			return Credential{Username: fmt.Sprintf("u%d", n), Password: "p", Expires: time.Now().Add(90 * time.Second)}, nil
		}, 100*time.Second)
		want := []string{"Added b r1 ", "Added a r1 ", "CredentialRotated a r1 u1", "Changed a r2 ", "CredentialRotated a r2 u2", "Removed b r0 ", "CredentialRotated a r2 u3"}
		if !reflect.DeepEqual(said, want) {
			t.Fatalf("events\n got %q\nwant %q", said, want)
		}
		if events[3].Previous.Revision != 1 || events[5].Previous.ID != "2" || events[5].Binding.ID != "" {
			t.Errorf("Previous: %+v %+v", events[3], events[5])
		}
		// the third read is at two thirds of the 90 s lease after the second
		if len(reads) != 3 || reads[2]-reads[1] != 60*time.Second {
			t.Errorf("reads at %v", reads)
		}
		for i := 1; i < len(s.polls); i++ { // 30 s, plus up to 10 %
			if gap := s.polls[i].Sub(s.polls[i-1]); gap < 30*time.Second || gap >= 33*time.Second {
				t.Errorf("poll %d after %s", i, gap)
			}
		}
		if logs != "" {
			t.Errorf("logs %q", logs)
		}
	})
	// without WatchCredentials no credential is read
	synctest.Test(t, func(t *testing.T) {
		said, _, _ := watching(t, v, &scripted{steps: []step{{items: []Binding{a1}}}}, nil, 70*time.Second)
		if !reflect.DeepEqual(said, []string{"Added a r1 "}) {
			t.Errorf("events %q", said)
		}
	})
}

// TestWatchFailures is CS-12.
func TestWatchFailures(t *testing.T) {
	v := newEnv(t)
	a1 := Binding{ID: "1", Name: "a", Revision: 1}
	down := fmt.Errorf("%w: down", ErrUnavailable)
	synctest.Test(t, func(t *testing.T) {
		s := &scripted{steps: []step{{items: []Binding{a1}}, {err: down}, {err: down}, {err: retryError{down, 200 * time.Second}}, {items: []Binding{a1}}}}
		n := 0
		said, _, logs := watching(t, v, s, func(context.Context, Binding) (Credential, error) {
			if n++; n == 1 {
				return Credential{}, fmt.Errorf("%w: sealed", ErrStore)
			}
			return Credential{Username: "u", Password: "p"}, nil
		}, 400*time.Second)
		// the state survives the failed polls: no Removed, no second Added; the credential is read at the next poll
		if want := []string{"Added a r1 ", "CredentialRotated a r1 u"}; !reflect.DeepEqual(said, want) {
			t.Errorf("events %q", said)
		}
		if len(s.polls) < 6 {
			t.Fatalf("%d polls", len(s.polls))
		}
		gaps := make([]time.Duration, 4)
		for i := range gaps {
			gaps[i] = s.polls[i+2].Sub(s.polls[i+1])
		}
		// after a failure: the interval, doubled, then Retry-After; after the success the interval again
		if gaps[0] != 30*time.Second || gaps[1] != 60*time.Second || gaps[2] != 200*time.Second || gaps[3] < 30*time.Second || gaps[3] >= 33*time.Second {
			t.Errorf("gaps %v", gaps)
		}
		if strings.Count(logs, "poll failed") != 3 || strings.Count(logs, "credential not read") != 1 || !strings.Contains(logs, "sealed") {
			t.Errorf("logs %s", logs)
		}
	})
	// the backoff stops at 5 minutes
	synctest.Test(t, func(t *testing.T) {
		s := &scripted{steps: []step{{err: down}}}
		watching(t, v, s, nil, 2*time.Hour)
		last := s.polls[len(s.polls)-1].Sub(s.polls[len(s.polls)-2])
		if last != maxBackoff {
			t.Errorf("last gap %s", last)
		}
	})
	if Added.String() != "Added" || EventKind(9).String() != "EventKind(9)" {
		t.Error("EventKind.String")
	}
}
