package web

import (
	"html/template"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Niximacco/ajn_auth/internal/sites"
	"github.com/gin-gonic/gin"
)

// Every page is rendered, because a template that does not compile or names a
// field that does not exist fails at request time and nowhere earlier. These
// are the cheapest tests in the repository and they catch the most annoying
// class of breakage.
func TestEveryPageRenders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	site := sites.Site{
		ID:           "flight-log",
		Name:         "Flight Log",
		BaseURL:      "https://flights.example.com",
		RedirectURIs: []string{"https://flights.example.com/auth/callback"},
		MailFrom:     "Flight Log <login@example.com>",
		Accent:       "#1d1d1f",
		Keys:         []sites.Key{{ID: "ajnauth_abc123", Note: "cloud run", Created: 1740000000}},
	}

	roster := sites.Config{
		Admins:    []string{"admin@example.com"},
		Sites:     []sites.Site{site},
		Updated:   1740000000,
		UpdatedBy: "admin@example.com",
	}

	confirm := ForSite("Finish signing in", site)
	confirm.Token = "a-token"

	signedIn := New("Sites")
	signedIn.SignedIn = true
	signedIn.Email = "admin@example.com"
	signedIn.Nav = "sites"
	signedIn.Roster = roster
	signedIn.Version = "projects/p/secrets/s/versions/4"

	sitePage := signedIn
	sitePage.Site = site
	sitePage.Secret = "ajnauth_theplaintextkey"

	newSitePage := signedIn
	newSitePage.New = true

	empty := signedIn
	empty.Roster = sites.Config{Admins: []string{"admin@example.com"}}

	sent := New("Check your email")
	sent.Email = "someone@example.com"
	sent.ExpiresMinutes = 15

	cases := []struct {
		name string
		page string
		data Page
	}{
		{"confirm", ConfirmPage, confirm},
		{"message, mid-login", MessagePage, func() Page {
			p := ForSite("That link didn't work", site)
			p.Error = "This sign in link has already been used."
			return p
		}()},
		{"message, signed in", MessagePage, func() Page {
			p := signedIn
			p.Title = "No such site"
			p.Error = "There is no site with that id."
			return p
		}()},
		{"message, bare", MessagePage, New("Something went wrong")},
		{"login", LoginPage, New("Sign in")},
		{"sent", SentPage, sent},
		{"sites", SitesPage, signedIn},
		{"sites, empty", SitesPage, empty},
		{"site", SitePage, sitePage},
		{"site, new", SitePage, newSitePage},
	}

	for _, test := range cases {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)

		Render(c, 200, test.page, test.data)

		body := recorder.Body.String()

		if recorder.Code != 200 {
			t.Errorf("%s: rendered %d", test.name, recorder.Code)
		}

		if !strings.Contains(body, "</html>") {
			t.Errorf("%s: the page did not finish rendering:\n%s", test.name, body)
		}

		// A template that reaches for a field the data does not have writes
		// this into the page rather than failing, which is exactly the kind of
		// thing that gets shipped.
		for _, broken := range []string{"<no value>", "{{", "ZgotmplZ"} {
			if strings.Contains(body, broken) {
				t.Errorf("%s: the page contains %q:\n%s", test.name, broken, body)
			}
		}
	}
}

// The confirm page is the only page a visitor sees, on a domain they did not
// type. It has to name the site, and it must not name anybody's address.
func TestConfirmPageSaysWhereYouAre(t *testing.T) {
	gin.SetMode(gin.TestMode)

	site := sites.Site{
		ID:      "flight-log",
		Name:    "Flight Log",
		BaseURL: "https://flights.example.com",
		Accent:  "#123456",
	}

	page := ForSite("Finish signing in", site)
	page.Token = "a-token"

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	Render(c, 200, ConfirmPage, page)

	body := recorder.Body.String()

	for _, want := range []string{"Flight Log", "https://flights.example.com", "#123456", `value="a-token"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the confirm page is missing %q", want)
		}
	}

	// The address behind the token is never on this page. Somebody else opening
	// a forwarded link should not learn whose inbox it came from.
	if strings.Contains(body, "@") && strings.Contains(body, "example.com/auth") {
		t.Error("the confirm page appears to carry an address")
	}
}

// The accent comes out of the roster as template.CSS, which is a promise that
// it is safe in a style attribute. Only AccentColour can make that promise, so
// check the promise is actually kept.
func TestAccentIsBoundedByTheRoster(t *testing.T) {
	page := ForSite("x", sites.Site{Name: "x", Accent: "#1d1d1f;} body { display: none"})

	if page.Accent != template.CSS("#1d1d1f") {
		t.Errorf("a hostile accent reached the page as %q", page.Accent)
	}
}

func TestSafeNext(t *testing.T) {
	for _, next := range []string{"/admin", "/admin/sites/flight-log", "/"} {
		if got := SafeNext(next); got != next {
			t.Errorf("next %q came back as %q", next, got)
		}
	}

	for _, next := range []string{"", "//evil.example", "/\\evil.example", "https://evil.example", "admin", "/a\r\nb"} {
		if got := SafeNext(next); got != "/" {
			t.Errorf("next %q came back as %q, want /", next, got)
		}
	}
}
