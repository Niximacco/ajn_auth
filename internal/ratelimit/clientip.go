// Package ratelimit keeps a caller from turning cheap http requests into
// expensive work: datastore reads, cloud run instance time, and above all
// outbound email.
package ratelimit

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// TRUSTED_PROXY_DEPTH is how many entries at the right hand end of
// X-Forwarded-For were written by infrastructure we trust rather than by the
// caller. Everything to the left of those is caller-supplied and forgeable, so
// the header is read right to left and this many entries are stepped over.
//
// This service is reached through a Cloud Run domain mapping, which is exactly
// one hop: Google's front end appends the connecting address to whatever the
// caller sent. That makes the rightmost entry the real client and 0 the correct
// depth. Confirmed against Cloud Run request logs - a request carrying a forged
// X-Forwarded-For was still logged with the true remote address, so the front
// end is appending rather than trusting what it was handed.
//
// Putting a load balancer or a CDN in front of this adds a hop. Set
// TRUSTED_PROXY_DEPTH in the environment rather than editing this.
var TRUSTED_PROXY_DEPTH = 0

// debugClientIP logs how each request's address was resolved. It is a way to
// confirm the depth above against real traffic without shipping new code.
var debugClientIP = false

func init() {
	if depth := os.Getenv("TRUSTED_PROXY_DEPTH"); depth != "" {
		parsed, err := strconv.Atoi(depth)
		if err != nil || parsed < 0 {
			log.Printf("ignoring unusable TRUSTED_PROXY_DEPTH %q", depth)
		} else {
			TRUSTED_PROXY_DEPTH = parsed
		}
	}

	debugClientIP = os.Getenv("TRUSTED_PROXY_DEBUG") != ""
}

// ClientIP returns the address to hold responsible for a request, or "" when
// that cannot be established.
//
// Callers must read "" as "do not rate limit this". A limiter that cannot tell
// callers apart has two failure modes and both are worse than letting the
// request through: bucket the whole internet together and it locks everybody
// out at once, or treat a forged header as identity and it limits nobody. The
// email address caps in magiclink are the ones that actually protect the send
// budget, and they do not depend on this.
func ClientIP(c *gin.Context) string {
	address := resolveClientIP(c)

	if debugClientIP {
		log.Printf("client ip %q from X-Forwarded-For %q remote %q depth %d",
			address, c.GetHeader("X-Forwarded-For"), c.Request.RemoteAddr, TRUSTED_PROXY_DEPTH)
	}

	return address
}

func resolveClientIP(c *gin.Context) string {
	forwarded := c.GetHeader("X-Forwarded-For")
	if forwarded == "" {
		if TRUSTED_PROXY_DEPTH > 0 {
			// We are configured to expect proxies and got no header at all, so
			// the request did not arrive the way we think it did. Claim nothing.
			return ""
		}

		// Nothing in the way: the socket is the truth. This is how it looks
		// running locally.
		return normalizeIP(c.Request.RemoteAddr)
	}

	entries := strings.Split(forwarded, ",")

	index := len(entries) - 1 - TRUSTED_PROXY_DEPTH
	if index < 0 {
		// Fewer entries than there are hops we trust, so this header did not
		// come from the infrastructure we believe sits in front of us.
		return ""
	}

	return normalizeIP(entries[index])
}

// normalizeIP validates an address and reduces it to the unit worth limiting.
// An ipv6 caller routinely has a whole /64 to itself, so ipv6 is collapsed to
// its /64: limiting a single ipv6 address is trivial to walk around one address
// at a time.
func normalizeIP(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return ""
	}

	// Forwarded entries are normally bare addresses, but a RemoteAddr carries a
	// port, and an ipv6 literal is bracketed when it does.
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	address = strings.Trim(address, "[]")

	parsed := net.ParseIP(address)
	if parsed == nil {
		return ""
	}

	if parsed.To4() != nil {
		return parsed.String()
	}

	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
