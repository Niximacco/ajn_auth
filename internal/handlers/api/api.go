// Package api_handler is the two calls a site makes.
//
// It is deliberately small. A site asks for a link, and later trades a code for
// an address. Everything else about a login - who may have one, what a session
// is, what the person may then do - belongs to the site and is not represented
// here at all.
package api_handler

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Niximacco/ajn_auth/internal/email"
	"github.com/Niximacco/ajn_auth/internal/magiclink"
	"github.com/Niximacco/ajn_auth/internal/ratelimit"
	"github.com/Niximacco/ajn_auth/internal/sites"
	"github.com/gin-gonic/gin"
)

// contextSiteKey holds the authenticated site on the gin context.
const contextSiteKey = "api_site"

// The api is behind an api key, so these limits are a brake on a site that has
// gone wrong - a retry loop, a bad deploy - rather than a defence against a
// stranger. What actually bounds the email budget is the per address caps in
// magiclink, which are counted in datastore and hold across every instance.
//
// They are per caller address rather than per key, because a caller with no
// valid key never reaches the handler and should not get its own bucket.
var (
	linkLimiter     = ratelimit.New(60, time.Minute)
	exchangeLimiter = ratelimit.New(120, time.Minute)
)

// AddAPIV1 mounts the two calls. They have separate limiters, so a site stuck
// in a retry loop on one cannot take the other down for everybody.
func AddAPIV1(router *gin.Engine) {
	router.POST("/v1/links", limit(linkLimiter), authenticate(), RequestLink)
	router.POST("/v1/exchange", limit(exchangeLimiter), authenticate(), Exchange)
}

func limit(limiter *ratelimit.Limiter) gin.HandlerFunc {
	return limiter.Middleware(func(c *gin.Context) {
		c.Header("Retry-After", "60")
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "too many requests"})
	})
}

// authenticate resolves the api key on the request to a site.
//
// Every failure is the same 401 with the same body. A caller with a bad key
// learns that it is bad and nothing else - not whether the site exists, not
// whether it is disabled, and not whether the key was once valid.
func authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := bearer(c.GetHeader("Authorization"))

		roster, err := sites.Shared().Current()
		if err != nil {
			log.Printf("could not read the roster to authenticate a site: %s", err.Error())
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "the site roster is unavailable"})
			return
		}

		site, err := roster.Authenticate(key)
		if err != nil {
			if errors.Is(err, sites.ErrSiteDisabled) {
				log.Printf("refused a request from %s, which is disabled", site.ID)
			}

			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		c.Set(contextSiteKey, site)
		c.Next()
	}
}

// bearer pulls the key out of an "Authorization: Bearer <key>" header.
func bearer(header string) string {
	parts := strings.SplitN(strings.TrimSpace(header), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}

	return strings.TrimSpace(parts[1])
}

func callingSite(c *gin.Context) sites.Site {
	site, ok := c.Get(contextSiteKey)
	if !ok {
		return sites.Site{}
	}

	if asSite, ok := site.(sites.Site); ok {
		return asSite
	}

	return sites.Site{}
}

type linkRequest struct {
	Email string `json:"email"`
	// RedirectURI is where the exchange code should be delivered. It has to be
	// one this site registered. A site with a single callback can leave it out.
	RedirectURI string `json:"redirect_uri"`
	// Next is a path on the site to land on after signing in.
	Next string `json:"next"`
}

// RequestLink mails a login link.
//
// The reply says only whether a link went out or the address is being
// throttled, and the client is expected to render both the same way. This
// service has no idea whether the address belongs to a real user - the site
// decided that before calling - so there is nothing here that could leak it,
// and the throttle answer is kept indistinguishable so that the caps cannot be
// used to probe one either.
func RequestLink(c *gin.Context) {
	site := callingSite(c)

	var request linkRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the request body is not readable json"})
		return
	}

	redirect, err := site.CheckRedirect(request.RedirectURI)
	if err != nil {
		// This one is said plainly rather than hidden, because it is never a
		// fact about a person: it is the site's own configuration disagreeing
		// with the roster, and the developer reading it needs to know which.
		log.Printf("%s asked for an unregistered redirect uri", site.ID)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = magiclink.Request(site, request.Email, redirect, request.Next)

	switch {
	case err == nil:
		c.JSON(http.StatusOK, gin.H{"status": "sent"})

	case errors.Is(err, magiclink.ErrThrottled):
		c.JSON(http.StatusOK, gin.H{"status": "throttled"})

	case errors.Is(err, magiclink.ErrInvalidEmail):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})

	case errors.Is(err, magiclink.ErrBadNext):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})

	case errors.Is(err, email.ErrNotConfigured):
		log.Print("a link was requested but email sending is not configured")
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "email sending is not configured"})

	default:
		log.Printf("could not send a magic link for %s: %s", site.ID, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not send the login link"})
	}
}

type exchangeRequest struct {
	Code string `json:"code"`
}

// Exchange trades a single-use code for the address that owns it.
//
// This is the only place an address ever leaves this service, and it goes over
// a connection the site authenticated itself on, in a response body. It is
// never put in a redirect, a query string or a token the browser can read.
func Exchange(c *gin.Context) {
	site := callingSite(c)

	var request exchangeRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "the request body is not readable json"})
		return
	}

	identity, err := magiclink.Redeem(site, request.Code)
	if err != nil {
		if errors.Is(err, magiclink.ErrBadCode) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		log.Printf("could not redeem a code for %s: %s", site.ID, err.Error())
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not complete the login"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"email": identity.Email, "next": identity.Next})
}
