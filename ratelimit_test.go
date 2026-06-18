package main

import (
	"testing"
	"time"
)

// newTestRateLimiter creates a RateLimiter with a synthetic clock for
// deterministic tests.
func newTestRateLimiter(limit int, window time.Duration, nowFn func() time.Time) *RateLimiter {
	rl := &RateLimiter{
		windows: make(map[string]*windowState),
		limit:   limit,
		window:  window,
		nowFn:   nowFn,
	}
	// Do not start the cleanup goroutine in tests.
	return rl
}

func TestRateLimiter_AllowsUnderLimit(t *testing.T) {
	now := time.Now()
	rl := newTestRateLimiter(3, time.Minute, func() time.Time { return now })

	for i := 0; i < 3; i++ {
		if !rl.Allow("192.0.2.1") {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
}

func TestRateLimiter_BlocksAtLimit(t *testing.T) {
	now := time.Now()
	rl := newTestRateLimiter(3, time.Minute, func() time.Time { return now })

	for i := 0; i < 3; i++ {
		rl.Allow("192.0.2.1")
	}
	if rl.Allow("192.0.2.1") {
		t.Fatal("4th attempt should be blocked")
	}
}

func TestRateLimiter_ResetsAfterWindow(t *testing.T) {
	now := time.Now()
	rl := newTestRateLimiter(3, time.Minute, func() time.Time { return now })

	for i := 0; i < 3; i++ {
		rl.Allow("192.0.2.1")
	}

	// Advance clock beyond the window.
	now = now.Add(2 * time.Minute)

	if !rl.Allow("192.0.2.1") {
		t.Fatal("attempt after window reset should be allowed")
	}
}

func TestRateLimiter_IsolatesKeys(t *testing.T) {
	now := time.Now()
	rl := newTestRateLimiter(2, time.Minute, func() time.Time { return now })

	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.1")

	if !rl.Allow("10.0.0.2") {
		t.Fatal("different IP should not be rate-limited")
	}
}

func TestRateLimiter_RetryAfterZeroWhenAllowed(t *testing.T) {
	now := time.Now()
	rl := newTestRateLimiter(3, time.Minute, func() time.Time { return now })

	rl.Allow("192.0.2.1")
	if d := rl.RetryAfter("192.0.2.1"); d != 0 {
		t.Fatalf("RetryAfter should be 0 when not limited, got %s", d)
	}
}

func TestRateLimiter_RetryAfterPositiveWhenLimited(t *testing.T) {
	now := time.Now()
	rl := newTestRateLimiter(2, time.Minute, func() time.Time { return now })

	rl.Allow("192.0.2.1")
	now = now.Add(10 * time.Second)
	rl.Allow("192.0.2.1")

	// Advance just a bit so the window has not expired.
	now = now.Add(5 * time.Second)

	d := rl.RetryAfter("192.0.2.1")
	if d <= 0 {
		t.Fatalf("RetryAfter should be positive when limited, got %s", d)
	}
}
