// SPDX-License-Identifier: MIT

package adminclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dihedron/ligo/pkg/adminclient/internal/gen"
)

// ErrBindingFailed is returned by WaitChangeRequest with UntilBindingActive
// when the binding the change request applied ended FAILED or DELETE_FAILED.
var ErrBindingFailed = errors.New("the binding failed to apply")

const (
	minWaitInterval     = time.Second
	defaultWaitInterval = 2 * time.Second
	defaultWaitMax      = 30 * time.Second
)

// WaitOptions tune WaitChangeRequest.
type WaitOptions struct {
	// Interval between two reads of the change request: 2 s by default, at
	// least 1 s, with jitter. It doubles after a failed read, up to MaxInterval.
	Interval time.Duration
	// MaxInterval caps the back-off after failures: 30 s by default.
	MaxInterval time.Duration
	// UntilBindingActive, for an applied change of a binding, goes on to wait
	// until the binding is ACTIVE (it settles asynchronously after the change
	// request is applied); a binding that ends FAILED or DELETE_FAILED is
	// ErrBindingFailed. It has no effect on other resources or on a deletion.
	UntilBindingActive bool
}

// IsTerminal reports whether a change request has reached its end: every
// state but PENDING is terminal (APPLIED, REJECTED, WITHDRAWN, EXPIRED,
// FAILED_TO_APPLY), and so is any state a later server adds.
func IsTerminal(cr ChangeRequest) bool { return cr.Status != gen.PENDING }

// IsApplied reports whether the change is in force.
func IsApplied(cr ChangeRequest) bool { return cr.Status == gen.APPLIED }

// WaitChangeRequest reads the change request until it is terminal, or the
// context ends, and returns it. A terminal state that is not APPLIED is not
// an error of the wait: the caller reads the state (IsApplied). The wait runs
// in the caller's goroutine. A failed read does not end it when the failure
// may pass (a busy or unreachable server); the pause then grows, up to
// MaxInterval, and follows the server's Retry-After. Any other failure, a
// request that is not found or a refused caller included, ends it.
//
// When the context ends the last change request read comes back with the
// context's error, so a caller can report "still PENDING, awaiting its owner".
func (c *Client) WaitChangeRequest(ctx context.Context, id string, o WaitOptions) (ChangeRequest, error) {
	interval, ceiling := o.Interval, o.MaxInterval
	if interval == 0 {
		interval = defaultWaitInterval
	}
	interval = max(interval, minWaitInterval)
	if ceiling == 0 {
		ceiling = defaultWaitMax
	}
	ceiling = max(ceiling, interval)

	var last ChangeRequest
	err := c.poll(ctx, interval, ceiling, func(ctx context.Context) (bool, error) {
		cr, err := c.getCR(ctx, id)
		if err != nil {
			return false, err
		}
		last = cr
		return IsTerminal(cr), nil
	})
	if err != nil {
		return last, c.waitError(id, last.Status, err)
	}
	if o.UntilBindingActive && IsApplied(last) && last.ResourceType == gen.ResourceTypeBINDING && last.Operation != gen.ChangeRequestOperationDELETE {
		err = c.poll(ctx, interval, ceiling, func(ctx context.Context) (bool, error) {
			b, err := c.getBinding(ctx, last.ResourceName)
			if err != nil {
				return false, err
			}
			switch b.Status.Phase {
			case gen.BindingPhaseACTIVE:
				return true, nil
			case gen.BindingPhaseFAILED, gen.BindingPhaseDELETEFAILED:
				return false, fmt.Errorf("%w: %s: %s", ErrBindingFailed, b.Status.Phase, b.Status.Message)
			}
			return false, nil
		})
		if err != nil {
			return last, c.waitError(id, last.Status, err)
		}
	}
	return last, nil
}

func (c *Client) waitError(id string, status gen.ChangeRequestStatus, err error) error {
	return fmt.Errorf("adminclient: waiting for change request %s (last status %q): %w", id, status, err)
}

// poll calls step until it is done or fails for good. After a failure that may
// pass it pauses longer each time; after a success it pauses the interval.
func (c *Client) poll(ctx context.Context, interval, ceiling time.Duration, step func(context.Context) (bool, error)) error {
	failures := 0
	for {
		done, err := step(ctx)
		pause := interval
		switch {
		case err == nil && done:
			return nil
		case err == nil:
			failures = 0
		case !pollable(ctx, err):
			return err
		default:
			failures++
			pause = interval
			for range failures {
				pause = min(pause*2, ceiling)
			}
			var p *Problem
			if errors.As(err, &p) && p.RetryAfter > 0 {
				pause = max(pause, min(p.RetryAfter, ceiling))
			}
		}
		if serr := c.sleep(ctx, c.jitter(pause)); serr != nil {
			return serr
		}
	}
}

// pollable is whether a failed read leaves the wait going: what exec would
// retry, and a server in maintenance, which ends.
func pollable(ctx context.Context, err error) bool {
	return transient(ctx, err) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrMaintenance)
}
