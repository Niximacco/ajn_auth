package ratelimit

import (
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// clock drives a limiter's sense of time from a test, so none of this has to
// sleep.
type clock struct{ at time.Time }

func (c *clock) now() time.Time          { return c.at }
func (c *clock) advance(d time.Duration) { c.at = c.at.Add(d) }

func limiterAt(burst int, window time.Duration) (*Limiter, *clock) {
	c := &clock{at: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)}
	l := New(burst, window)
	l.now = c.now

	return l, c
}

func TestAllowsTheBurstThenStops(t *testing.T) {
	l, _ := limiterAt(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !l.Allow("caller") {
			t.Fatalf("request %d of the burst was refused", i+1)
		}
	}

	if l.Allow("caller") {
		t.Fatal("the request past the burst was allowed")
	}
}

func TestRefillsOverTime(t *testing.T) {
	l, c := limiterAt(3, time.Minute)

	for i := 0; i < 3; i++ {
		l.Allow("caller")
	}

	// A third of the window is one of the three tokens back.
	c.advance(20 * time.Second)

	if !l.Allow("caller") {
		t.Fatal("a refilled token was not handed out")
	}

	if l.Allow("caller") {
		t.Fatal("more was refilled than the elapsed time earns")
	}
}

func TestRefillStopsAtTheBurst(t *testing.T) {
	l, c := limiterAt(3, time.Minute)

	l.Allow("caller")
	c.advance(time.Hour)

	// An hour idle must not bank an hour's worth of requests.
	for i := 0; i < 3; i++ {
		if !l.Allow("caller") {
			t.Fatalf("request %d after idling was refused", i+1)
		}
	}

	if l.Allow("caller") {
		t.Fatal("idling banked more than the burst")
	}
}

func TestCallersAreCountedSeparately(t *testing.T) {
	l, _ := limiterAt(1, time.Minute)

	if !l.Allow("first") || !l.Allow("second") {
		t.Fatal("two different callers shared one allowance")
	}

	if l.Allow("first") {
		t.Fatal("a caller got a second turn")
	}
}

func TestUnattributableRequestsAreAlwaysAllowed(t *testing.T) {
	l, _ := limiterAt(1, time.Minute)

	// Everything we cannot attribute would otherwise pile into one bucket and
	// lock out the world together.
	for i := 0; i < 50; i++ {
		if !l.Allow("") {
			t.Fatal("an unattributable request was refused")
		}
	}
}

func TestIdleCallersAreForgotten(t *testing.T) {
	l, c := limiterAt(3, time.Minute)

	l.Allow("caller")
	if len(l.buckets) != 1 {
		t.Fatalf("wanted the caller remembered, have %d buckets", len(l.buckets))
	}

	// Long enough that the bucket has refilled and is indistinguishable from a
	// caller never seen before. A sweep is only attempted on use, so it takes a
	// later request to trigger one.
	c.advance(10 * time.Minute)
	l.Allow("somebody else")

	if _, still := l.buckets["caller"]; still {
		t.Fatal("an idle caller was kept in the map")
	}
}

func TestForgettingACallerDoesNotForgiveALiveOne(t *testing.T) {
	l, c := limiterAt(2, time.Minute)

	l.Allow("caller")
	l.Allow("caller")

	// Past the sweep interval, but the caller keeps asking, so it stays live and
	// must not have its bucket dropped and handed back full.
	c.advance(3 * time.Minute)
	l.Allow("noise")

	if !l.Allow("caller") {
		t.Fatal("a caller idle past the sweep should have refilled by now")
	}
}

func TestMiddlewareLetsACallerThroughUntilTheyAreOver(t *testing.T) {
	withDepth(t, 0)

	l, _ := limiterAt(2, time.Minute)

	var reached, refused int
	handler := l.Middleware(func(c *gin.Context) { refused++ })

	for i := 0; i < 4; i++ {
		c := request("10.0.0.1:1234", "198.51.100.7")
		handler(c)
		if !c.IsAborted() {
			reached++
		}
	}

	if reached != 2 || refused != 2 {
		t.Fatalf("wanted 2 through and 2 refused, got %d and %d", reached, refused)
	}
}

func TestMiddlewareSeparatesCallersByForwardedAddress(t *testing.T) {
	withDepth(t, 0)

	l, _ := limiterAt(1, time.Minute)
	handler := l.Middleware(func(*gin.Context) {})

	// Same socket, which is what every request looks like behind the front end.
	// The forwarded address is the only thing telling these two apart.
	first := request("10.0.0.1:1234", "198.51.100.7")
	second := request("10.0.0.1:1234", "203.0.113.4")

	handler(first)
	handler(second)

	if first.IsAborted() || second.IsAborted() {
		t.Fatal("two separate callers were counted as one")
	}

	third := request("10.0.0.1:1234", "198.51.100.7")
	handler(third)

	if !third.IsAborted() {
		t.Fatal("a caller's second request was not counted against them")
	}
}
