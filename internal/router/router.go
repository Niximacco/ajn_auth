package router

import "github.com/gin-gonic/gin"

func New() (router *gin.Engine) {
	r := gin.Default()
	// r.Use(logging.RequestResponseLogger())

	// gin.SetMode(gin.TestMode)
	r.Use(gin.Recovery())
	r.RedirectTrailingSlash = false

	// No proxy is trusted for gin's own c.ClientIP(), which leaves it returning
	// the address we are actually connected to. In front of this service that is
	// Google's front end, the same for every visitor, so c.ClientIP() is not an
	// identity and must not be treated as one.
	//
	// Anything that needs the real caller goes through ratelimit.ClientIP, which
	// reads X-Forwarded-For from the right and says so when it cannot tell.
	r.SetTrustedProxies(nil)

	return r
}
