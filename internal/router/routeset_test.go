package router

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// The routes are registered on one gin tree in the order main registers them.
// Gin builds that tree at registration time and panics on a conflict, which
// would be a crash at startup rather than a failing request, so it is worth
// pinning down here.
//
// The route set is written out rather than imported, because importing the
// handlers would pull in the auth package, whose init refuses to load without a
// signing key in the environment.
//
// The case this really exists for is the /admin subtree: three static children
// beside a /sites/:id parameter, with two more static segments underneath it.
// Gin allows all of that, but the arrangement is exactly the kind that stops
// being allowed, and a service that will not start is a bad way to find out.
func TestTheWholeRouteSetRegistersAndResolves(t *testing.T) {
	gin.SetMode(gin.TestMode)

	hit := ""
	mark := func(name string) gin.HandlerFunc {
		return func(c *gin.Context) { hit = name; c.Status(http.StatusOK) }
	}

	r := New()

	r.GET("/healthz", mark("health"))
	r.GET("/", mark("root"))

	// asset_handler.AddAssetV1
	r.GET("/static/:file", mark("asset"))

	// api_handler.AddAPIV1
	r.POST("/v1/links", mark("links"))
	r.POST("/v1/exchange", mark("exchange"))

	// callback_handler.AddCallbackV1
	r.GET("/callback", mark("confirm"))
	r.POST("/callback", mark("complete"))

	// admin_handler.AddAdminV1
	r.GET("/admin/login", mark("adminlogin"))
	r.POST("/admin/login", mark("adminrequest"))
	r.GET("/admin/callback", mark("admincallback"))
	r.POST("/admin/logout", mark("adminlogout"))

	pages := r.Group("/admin")
	pages.GET("", mark("sites"))
	pages.GET("/sites/new", mark("newsite"))
	pages.POST("/sites", mark("createsite"))
	pages.GET("/sites/:id", mark("editsite"))
	pages.POST("/sites/:id", mark("savesite"))
	pages.POST("/sites/:id/keys", mark("generatekey"))
	pages.POST("/sites/:id/keys/:key/revoke", mark("revokekey"))
	pages.POST("/sites/:id/delete", mark("deletesite"))
	pages.POST("/admins", mark("saveadmins"))

	cases := []struct {
		method string
		path   string
		want   string
	}{
		{http.MethodGet, "/healthz", "health"},
		{http.MethodGet, "/", "root"},

		// The stylesheet is asked for by a name carrying its own hash, so this
		// route sees a different path on every release that changes it.
		{http.MethodGet, "/static/app.a1b2c3d4e5.css", "asset"},

		{http.MethodPost, "/v1/links", "links"},
		{http.MethodPost, "/v1/exchange", "exchange"},

		{http.MethodGet, "/callback?token=x", "confirm"},
		{http.MethodPost, "/callback", "complete"},

		{http.MethodGet, "/admin", "sites"},
		{http.MethodGet, "/admin/login", "adminlogin"},
		{http.MethodGet, "/admin/login?next=%2Fadmin", "adminlogin"},
		{http.MethodPost, "/admin/login", "adminrequest"},
		{http.MethodGet, "/admin/callback?code=x", "admincallback"},
		{http.MethodPost, "/admin/logout", "adminlogout"},

		// "new" has to win over the parameter beside it, or a site could never
		// be added - and a site really called "new" would shadow the form.
		{http.MethodGet, "/admin/sites/new", "newsite"},
		{http.MethodGet, "/admin/sites/flight-log", "editsite"},
		{http.MethodPost, "/admin/sites", "createsite"},
		{http.MethodPost, "/admin/sites/flight-log", "savesite"},
		{http.MethodPost, "/admin/sites/flight-log/keys", "generatekey"},
		{http.MethodPost, "/admin/sites/flight-log/keys/ajnauth_abc123/revoke", "revokekey"},
		{http.MethodPost, "/admin/sites/flight-log/delete", "deletesite"},
		{http.MethodPost, "/admin/admins", "saveadmins"},
	}

	for _, test := range cases {
		hit = ""
		recorder := httptest.NewRecorder()
		r.ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, nil))

		if recorder.Code != http.StatusOK {
			t.Errorf("%s %s returned %d, want 200", test.method, test.path, recorder.Code)
			continue
		}

		if hit != test.want {
			t.Errorf("%s %s reached %q, want %q", test.method, test.path, hit, test.want)
		}
	}
}

// Nothing in front of this service is a proxy we have told gin about, so
// c.ClientIP must not be treated as an identity. See the comment in New.
func TestNoProxiesAreTrusted(t *testing.T) {
	gin.SetMode(gin.TestMode)

	seen := ""
	r := New()
	r.GET("/", func(c *gin.Context) {
		seen = c.ClientIP()
		c.Status(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.1.2.3:4567"
	request.Header.Set("X-Forwarded-For", "8.8.8.8")

	r.ServeHTTP(httptest.NewRecorder(), request)

	if seen == "8.8.8.8" {
		t.Error("gin trusted a forged X-Forwarded-For header")
	}
}
