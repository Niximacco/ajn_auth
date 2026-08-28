package web

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Niximacco/ajn_auth/internal/sites"
	"github.com/gin-gonic/gin"
)

// TestPreview writes the pages to disk so they can be looked at in a browser.
// It only runs when PREVIEW_DIR is set, so it is a tool rather than a test.
func TestPreview(t *testing.T) {
	dir := os.Getenv("PREVIEW_DIR")
	if dir == "" {
		t.Skip("set PREVIEW_DIR to write the pages out")
	}

	gin.SetMode(gin.TestMode)

	site := sites.Site{ID: "flight-log", Name: "Flight Log", BaseURL: "https://flights.ajn.me",
		RedirectURIs: []string{"https://flights.ajn.me/auth/callback"},
		MailFrom:     "Flight Log <login@ajn.me>", Accent: "#1f6feb",
		Keys: []sites.Key{{ID: "ajnauth_AbC123", Note: "cloud run", Created: 1740000000}}}
	games := sites.Site{ID: "wild-games", Name: "Wild Games", BaseURL: "https://wildgames.ajn.me",
		RedirectURIs: []string{"https://wildgames.ajn.me/auth/callback"},
		MailFrom:     "Wild Games <login@ajn.me>", Disabled: true}

	roster := sites.Config{Admins: []string{"you@example.com"}, Sites: []sites.Site{site, games},
		Updated: 1740000000, UpdatedBy: "you@example.com"}

	confirm := ForSite("Finish signing in", site)
	confirm.Token = "a-token"

	signedIn := New("Sites")
	signedIn.SignedIn = true
	signedIn.Email = "you@example.com"
	signedIn.Nav = "sites"
	signedIn.Roster = roster
	signedIn.Version = "projects/p/secrets/ajn-auth-sites/versions/4"

	sitePage := signedIn
	sitePage.Title = "Flight Log"
	sitePage.Site = site
	sitePage.Secret = "ajnauth_QmFzZTY0LWlzaC1sb29raW5nLWtleS12YWx1ZQ"

	out := map[string]struct {
		page string
		data Page
	}{
		"confirm.html": {ConfirmPage, confirm},
		"sites.html":   {SitesPage, signedIn},
		"site.html":    {SitePage, sitePage},
		"login.html":   {LoginPage, New("Sign in")},
	}

	for name, test := range out {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		Render(c, 200, test.page, test.data)

		// Inline the stylesheet so the file works on its own.
		body := strings.Replace(recorder.Body.String(),
			`<link rel="stylesheet" href="`+Stylesheet+`">`,
			"<style>"+string(assets[strings.TrimPrefix(Stylesheet, "/static/")].Body)+"</style>", 1)

		if err := os.WriteFile(dir+"/"+name, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
