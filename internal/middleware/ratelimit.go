package middleware

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*TokenBucket
	rate    int           // requests per window
	window  time.Duration // time window
}

// TokenBucket represents a token bucket for rate limiting
type TokenBucket struct {
	tokens     int
	lastRefill time.Time
	mu         sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*TokenBucket),
		rate:    rate,
		window:  window,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// Allow checks if a request is allowed for a given key (usually IP or user ID)
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	bucket, exists := rl.buckets[key]
	if !exists {
		bucket = &TokenBucket{
			tokens:     rl.rate,
			lastRefill: time.Now(),
		}
		rl.buckets[key] = bucket
	}
	rl.mu.Unlock()

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// Refill tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	if elapsed >= rl.window {
		bucket.tokens = rl.rate
		bucket.lastRefill = now
	}

	// Check if tokens are available
	if bucket.tokens > 0 {
		bucket.tokens--
		return true
	}

	return false
}

// cleanup removes old buckets
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, bucket := range rl.buckets {
			bucket.mu.Lock()
			if now.Sub(bucket.lastRefill) > rl.window*2 {
				delete(rl.buckets, key)
			}
			bucket.mu.Unlock()
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use IP address as the rate limit key
			ip := getClientIP(r)

			if !limiter.Allow(ip) {
				w.Header().Set("X-RateLimit-Limit", "100")
				w.Header().Set("X-RateLimit-Remaining", "0")
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return forwarded
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
