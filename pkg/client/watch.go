package client

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"time"
)

const (
	defaultPoll = 30 * time.Second
	minPoll     = 5 * time.Second // T-C6
	maxBackoff  = 5 * time.Minute
	// maxRetryAfter is the longest wait the server may ask for
	maxRetryAfter = time.Hour
)

// EventKind says what Watch saw.
type EventKind int

// The kinds of events.
const (
	Added             EventKind = iota + 1 // a binding appeared; also every binding at the first poll
	Changed                                // a known binding has another revision
	Removed                                // a known binding is gone: revoked or expired
	CredentialRotated                      // a credential was read for the binding
)

func (k EventKind) String() string {
	switch k {
	case Added:
		return "Added"
	case Changed:
		return "Changed"
	case Removed:
		return "Removed"
	case CredentialRotated:
		return "CredentialRotated"
	}
	return fmt.Sprintf("EventKind(%d)", int(k))
}

// Event is one change seen by Watch.
type Event struct {
	Kind       EventKind
	Binding    Binding    // the binding now; zero for Removed
	Previous   Binding    // the binding before; set for Changed and Removed
	Credential Credential // set for CredentialRotated
}

// retryError is an ErrUnavailable answer that says when to come back.
type retryError struct {
	error
	after time.Duration
}

func (e retryError) Unwrap() error { return e.error }

// Watch polls the caller's bindings that match f and calls handle, on its
// own goroutine and one event at a time, for every change. With
// f.WatchCredentials it also reads the credential of each new or changed
// binding, and again at two thirds of a lease. A failed poll keeps the
// state and is tried again later. Watch returns when ctx ends, with its
// error.
func (c *Client) Watch(ctx context.Context, f Filter, handle func(Event)) error {
	known := map[string]Binding{}
	due := map[string]time.Time{} // when to read a binding's credential
	failures := 0
	nextPoll := c.now()
	for {
		now := c.now()
		if !now.Before(nextPoll) {
			wait := c.poll + rand.N(c.poll/10) //nolint:gosec // G404: jitter, not a secret
			items, err := c.Bindings(ctx, f)
			switch {
			case ctx.Err() != nil:
				return ctx.Err()
			case err != nil:
				wait = min(c.poll<<min(failures, 10), maxBackoff)
				var retry retryError
				if errors.As(err, &retry) {
					wait = max(wait, retry.after)
				}
				failures++
				c.log.Warn("watch: poll failed", "target", f.Target, "retry_in", wait, "error", err)
			default:
				failures = 0
				c.diff(known, due, items, f.WatchCredentials, now, handle)
			}
			nextPoll = now.Add(wait)
		}
		wake := nextPoll
		for _, b := range sorted(known) {
			at, ok := due[b.ID]
			if !ok {
				continue
			}
			if at.After(now) {
				wake = earliest(wake, at)
				continue
			}
			cred, err := c.readCredential(ctx, b)
			switch {
			case ctx.Err() != nil:
				return ctx.Err()
			case errors.Is(err, ErrNoCredential):
				delete(due, b.ID)
			case err != nil:
				due[b.ID] = nextPoll
				c.log.Warn("watch: credential not read", "binding", b.Name, "target", b.Target, "error", err)
			default:
				delete(due, b.ID)
				if !cred.Expires.IsZero() {
					due[b.ID] = now.Add(cred.Expires.Sub(now) * 2 / 3)
					wake = earliest(wake, due[b.ID])
				}
				handle(Event{Kind: CredentialRotated, Binding: b, Credential: cred})
			}
		}
		timer := time.NewTimer(wake.Sub(c.now()))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// diff emits the changes from known to items and updates known and due.
func (c *Client) diff(known map[string]Binding, due map[string]time.Time, items []Binding, credentials bool, now time.Time, handle func(Event)) {
	seen := make(map[string]bool, len(items))
	for _, b := range items {
		seen[b.ID] = true
		old, ok := known[b.ID]
		if ok && old.Revision == b.Revision {
			continue
		}
		known[b.ID] = b
		if credentials {
			due[b.ID] = now
		}
		if ok {
			handle(Event{Kind: Changed, Binding: b, Previous: old})
		} else {
			handle(Event{Kind: Added, Binding: b})
		}
	}
	for _, old := range sorted(known) {
		if !seen[old.ID] {
			delete(known, old.ID)
			delete(due, old.ID)
			handle(Event{Kind: Removed, Previous: old})
		}
	}
}

// sorted is the bindings by name, then ID, for a stable order of events.
func sorted(m map[string]Binding) []Binding {
	out := make([]Binding, 0, len(m))
	for _, b := range m {
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b Binding) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.ID, b.ID)) })
	return out
}

func earliest(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
