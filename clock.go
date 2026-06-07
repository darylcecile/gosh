package gosh

import (
	"context"
	"sync"
	"time"
)

// Epoch is the deterministic instant returned by the default virtual clock's
// first Now call. It is fixed and in UTC so that script output (e.g. from date)
// never leaks host wall-clock time or timezone (S24). The value is
// 2000-01-01T00:00:00Z.
var Epoch = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

// Clock abstracts the passage of time for the sandbox. All time-reading
// commands (date, sleep, and any custom command) MUST read time through the
// injected Clock rather than time.Now, so the host can make execution fully
// deterministic and prevent host-state leakage (S24).
type Clock interface {
	// Now returns the current virtual time. Implementations should return a
	// UTC time unless the host explicitly opts into a timezone.
	Now() time.Time
	// Sleep advances time by d. It must honor context cancellation, returning
	// the context error if ctx is done before the sleep completes. A virtual
	// clock advances its internal time instead of blocking wall-clock.
	Sleep(ctx context.Context, d time.Duration) error
}

// VirtualClock is the default Clock: it starts at Epoch and advances only when
// Sleep is called (or when the time is manually advanced). It never blocks on
// wall-clock time, making runs deterministic and instant. It is safe for
// concurrent use.
type VirtualClock struct {
	mu  sync.Mutex
	now time.Time
}

// NewVirtualClock returns a VirtualClock starting at the given instant. If
// start is the zero value, Epoch is used.
func NewVirtualClock(start time.Time) *VirtualClock {
	if start.IsZero() {
		start = Epoch
	}
	return &VirtualClock{now: start.UTC()}
}

// Now returns the current virtual time.
func (c *VirtualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Sleep advances the virtual clock by d without blocking, while still
// respecting context cancellation. Negative durations are treated as zero.
func (c *VirtualClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d < 0 {
		d = 0
	}
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
	return nil
}

// Advance moves the virtual clock forward by d. It is a convenience for tests
// and host code; it is not part of the Clock interface.
func (c *VirtualClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// FixedClock is a Clock whose time never changes. Sleep is a no-op (other than
// honoring cancellation). Useful for fully reproducible tests.
type FixedClock struct {
	// At is the constant time returned by Now.
	At time.Time
}

// NewFixedClock returns a FixedClock pinned to the given instant (defaulting to
// Epoch when zero), converted to UTC.
func NewFixedClock(at time.Time) *FixedClock {
	if at.IsZero() {
		at = Epoch
	}
	return &FixedClock{At: at.UTC()}
}

// Now returns the fixed time.
func (c *FixedClock) Now() time.Time { return c.At }

// Sleep returns immediately, honoring context cancellation.
func (c *FixedClock) Sleep(ctx context.Context, d time.Duration) error {
	return ctx.Err()
}

// SystemClock is a Clock backed by the real wall clock. It is NOT a default and
// must be opted into via WithClock; using it leaks host time and makes runs
// non-deterministic. Sleep blocks for real, up to context cancellation.
type SystemClock struct{}

// Now returns the real current time in UTC.
func (SystemClock) Now() time.Time { return time.Now().UTC() }

// Sleep blocks for d or until ctx is done, whichever comes first.
func (SystemClock) Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
