package adminclient

import (
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"syscall"
	"time"
)

const (
	retryBase    = 200 * time.Millisecond
	retryCap     = 5 * time.Second
	maxRetryWait = 30 * time.Second // a longer Retry-After is the caller's to honour, not the client's to sleep through
)

// backoff is the pause before retry number attempt+1: 200 ms doubling to 5 s,
// with jitter so that clients that failed together do not return together.
func (c *Client) backoff(attempt int) time.Duration {
	d := retryCap
	if attempt < 5 {
		d = min(retryBase<<attempt, retryCap)
	}
	return c.jitter(d)
}

// jitter spreads d over 50%..150%.
func jitter(d time.Duration) time.Duration {
	return d/2 + time.Duration(rand.Int64N(int64(d)+1)) //nolint:gosec // jitter of a pause, not a secret
}

// transient is whether a failed call may succeed if repeated: a server that
// is busy, behind a proxy that lost it, or a connection that broke. A
// refused certificate, a malformed answer and a caller's cancelled context
// are not.
func transient(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	var p *Problem
	if errors.As(err, &p) {
		switch p.Status {
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return true
		}
		return false
	}
	if errors.Is(err, ErrTooLarge) || errors.Is(err, ErrRedirect) {
		return false
	}
	var ne net.Error
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.As(err, &ne) && ne.Timeout()
}

// retryWait is how long to pause before the next attempt of a failed call: the
// server's Retry-After when it gave one, else the backoff. ok is false when
// the server asks for more than the client will sleep.
func (c *Client) retryWait(err error, attempt int) (d time.Duration, ok bool) {
	var p *Problem
	if errors.As(err, &p) && p.RetryAfter > 0 {
		return p.RetryAfter, p.RetryAfter <= maxRetryWait
	}
	return c.backoff(attempt), true
}
