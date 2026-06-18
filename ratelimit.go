package main

import (
	"sync"
	"time"
)

// RateLimiter implements a per-key sliding-window rate limiter using only the
// standard library. It is safe for concurrent use.
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string]*windowState
	limit   int
	window  time.Duration
	nowFn   func() time.Time // injectable for tests
}

type windowState struct {
	attempts []time.Time
	lastSeen time.Time
}

// NewRateLimiter creates a RateLimiter that allows at most limit attempts per
// key within the given window duration.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		windows: make(map[string]*windowState),
		limit:   limit,
		window:  window,
		nowFn:   time.Now,
	}
	go rl.cleanupLoop()
	return rl
}

// Allow returns true if the key is within the rate limit and records the
// attempt. It returns false when the limit has been exceeded.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.nowFn()
	cutoff := now.Add(-rl.window)

	ws, ok := rl.windows[key]
	if !ok {
		ws = &windowState{}
		rl.windows[key] = ws
	}
	ws.lastSeen = now

	// Evict timestamps older than the window.
	valid := ws.attempts[:0]
	for _, t := range ws.attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	ws.attempts = valid

	if len(ws.attempts) >= rl.limit {
		return false
	}

	ws.attempts = append(ws.attempts, now)
	return true
}

// RetryAfter returns the duration the caller should wait before the oldest
// attempt expires and a new one would be allowed. Returns 0 if the key is not
// currently rate-limited.
func (rl *RateLimiter) RetryAfter(key string) time.Duration {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := rl.nowFn()
	cutoff := now.Add(-rl.window)

	ws, ok := rl.windows[key]
	if !ok {
		return 0
	}

	// Count valid attempts.
	var oldest time.Time
	count := 0
	for _, t := range ws.attempts {
		if t.After(cutoff) {
			count++
			if oldest.IsZero() || t.Before(oldest) {
				oldest = t
			}
		}
	}

	if count < rl.limit {
		return 0
	}
	// Oldest attempt expires at oldest + window.
	return oldest.Add(rl.window).Sub(now)
}

// cleanupLoop periodically evicts keys that have not been seen for longer than
// two window durations, bounding memory usage.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.window)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := rl.nowFn()
		cutoff := now.Add(-2 * rl.window)
		for key, ws := range rl.windows {
			if ws.lastSeen.Before(cutoff) {
				delete(rl.windows, key)
			}
		}
		rl.mu.Unlock()
	}
}
