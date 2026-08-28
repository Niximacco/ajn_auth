// Package callback_handler is what a person sees when they click the link in
// their email.
//
// It is the one part of this service a visitor ever looks at, and it is on a
// domain they did not type. So it says whose login it is finishing, in that
// site's colour, and where confirming will send them - and then it sends them
// straight back. Nobody should have to think about this page for more than the
// second it takes to press the button.
package callback_handler

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/Niximacco/ajn_auth/internal/magiclink"
	"github.com/Niximacco/ajn_auth/internal/ratelimit"
	"github.com/Niximacco/ajn_auth/internal/sites"
	"github.com/Niximacco/ajn_auth/internal/web"
	"github.com/gin-gonic/gin"
)

// These are the only unauthenticated routes in the service that do datastore
// work, so they get a per caller ceiling. It is about the cost of being probed -
// datastore reads and instance time - rather than about email: nothing here
// sends anything. A person retrying a link will not meet it.
var callbackLimiter = ratelimit.New(20, time.Minute)

func AddCallbackV1(router *gin.Engine) {
	limited := callbackLimiter.Middleware(web.TooManyRequests(time.Minute))

	router.GET("/callback", limited, ConfirmLogin)
	router.POST("/callback", limited, CompleteLogin)
}

// ConfirmLogin renders the "yes, it was me" step.
//
// Following the emailed link deliberately does not sign anyone in: mail
// scanners and link previewers fetch urls out of email, and a plain GET would
// let them burn the token before the real person ever clicked it. The GET
// therefore reads nothing and writes nothing - it renders a form.
func ConfirmLogin(c *gin.Context) {
	token := c.Query("token")

	if token == "" {
		web.Fail(c, http.StatusBadRequest, "That link is incomplete",
			"This sign in link is missing its token. Ask the site for a new one.")
		return
	}

	roster, err := sites.Shared().Current()
	if err != nil {
		log.Printf("could not read the roster to show a confirm page: %s", err.Error())
		web.Fail(c, http.StatusServiceUnavailable, "Sign in is unavailable",
			"We couldn't finish signing you in. Try again in a moment.")
		return
	}

	// Reading the link to find out whose it is does not spend it, so a scanner
	// that fetches this url still leaves a working link behind.
	site, err := magiclink.Peek(token, roster)
	if err != nil {
		page := web.ForSite("That link didn't work", site)
		page.Error = "This sign in link has already been used or has expired. Ask the site for a new one."
		web.Render(c, http.StatusUnauthorized, web.MessagePage, page)
		return
	}

	page := web.ForSite("Finish signing in", site)
	page.Token = token

	web.Render(c, http.StatusOK, web.ConfirmPage, page)
}

// CompleteLogin spends the link and hands the browser back to the site with an
// exchange code.
func CompleteLogin(c *gin.Context) {
	roster, err := sites.Shared().Current()
	if err != nil {
		log.Printf("could not read the roster to complete a login: %s", err.Error())
		web.Fail(c, http.StatusServiceUnavailable, "Sign in is unavailable",
			"We couldn't finish signing you in. Try again in a moment.")
		return
	}

	consumed, err := magiclink.Consume(c.PostForm("token"), roster)
	if err != nil {
		page := web.New("That link didn't work")

		if errors.Is(err, magiclink.ErrBadToken) {
			page.Error = "This sign in link has already been used or has expired. Ask the site for a new one."
			web.Render(c, http.StatusUnauthorized, web.MessagePage, page)
			return
		}

		log.Printf("could not complete a login: %s", err.Error())
		page.Error = "Something went wrong signing you in. Please try again."
		web.Render(c, http.StatusInternalServerError, web.MessagePage, page)
		return
	}

	target, err := consumed.Deliver()
	if err != nil {
		log.Printf("could not build the redirect back to %s: %s", consumed.Site.ID, err.Error())
		page := web.ForSite("Something went wrong", consumed.Site)
		page.Error = "We couldn't send you back to " + consumed.Site.Name + ". Please try again."
		web.Render(c, http.StatusInternalServerError, web.MessagePage, page)
		return
	}

	// 303 rather than 302: this is the answer to a POST, and the browser must
	// follow it with a GET rather than repeating the form against the site.
	c.Redirect(http.StatusSeeOther, target)
}
