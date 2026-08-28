package ratelimit

import (
	"log"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// Limiter is a token bucket per caller. Buckets refill continuously, so a
// caller staying under the rate is never turned away while one that floods is
// blocked only until it has refilled.
//
// The state is per process, which on Cloud Run means per container instance:
// with several instances up, the real ceiling is this limit times the instance
// count. That is acceptable for what this is, a brake on cheap floods from a
// single source. It is deliberately not what protects the email budget - the
// per address caps in magiclink do that, and they live in datastore and so
// apply across every instance.
type Limiter struct {
	mutex   sync.Mutex
	buckets map[string]*bucket
	burst   float64
	refill  float64 // tokens per second
	idle    time.Duration
	swept   time.Time

	// now is swappable so the tests do not have to sleep.
	now func() time.Time
}

type bucket struct {
	tokens float64
	seen   time.Time
}

// New returns a limiter that allows burst requests from one caller and then
// refills at burst per window.
func New(burst int, window time.Duration) *Limiter {
	return &Limiter{
		buckets: map[string]*bucket{},
		burst:   float64(burst),
		refill:  float64(burst) / window.Seconds(),
		idle:    2 * window,
		now:     time.Now,
	}
}

// Allow takes a token for key and reports whether there was one to take. An
// empty key is always allowed - see ClientIP for why an unattributable request
// is better let through than guessed at.
func (l *Limiter) Allow(key string) bool {
	if key == "" {
		return true
	}

	l.mutex.Lock()
	defer l.mutex.Unlock()

	now := l.now()
	l.sweep(now)

	current, seen := l.buckets[key]
	if !seen {
		current = &bucket{tokens: l.burst}
		l.buckets[key] = current
	} else {
		current.tokens += now.Sub(current.seen).Seconds() * l.refill
		if current.tokens > l.burst {
			current.tokens = l.burst
		}
	}

	current.seen = now

	if current.tokens < 1 {
		return false
	}

	current.tokens--
	return true
}

// sweep drops buckets that have sat untouched long enough to have refilled
// completely, since those now behave exactly like a caller we have never seen.
// Without it the map gains an entry per distinct address and never loses one.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.swept) < l.idle {
		return
	}
	l.swept = now

	for key, current := range l.buckets {
		if now.Sub(current.seen) >= l.idle {
			delete(l.buckets, key)
		}
	}
}

// Middleware turns away requests from a caller that is over its limit, handing
// the response to onLimited. It keys on the network address only, never on
// anything the request claims about itself, so being refused here reveals
// nothing about which accounts exist.
func (l *Limiter) Middleware(onLimited gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		address := ClientIP(c)
		if l.Allow(address) {
			c.Next()
			return
		}

		log.Printf("rate limited %s %s from %s", c.Request.Method, c.Request.URL.Path, address)

		onLimited(c)
		c.Abort()
	}
}
