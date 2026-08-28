package web

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Niximacco/ajn_auth/internal/config"
	"github.com/Niximacco/ajn_auth/internal/sites"
	"github.com/gin-gonic/gin"
)

// Templates ship inside the binary so there is nothing to mount or copy at
// deploy time, and a cold start does not touch the filesystem.
//
//go:embed templates/*.html
var templateFS embed.FS

const (
	ConfirmPage = "confirm.html"
	MessagePage = "message.html"
	LoginPage   = "login.html"
	SentPage    = "sent.html"
	SitesPage   = "sites.html"
	SitePage    = "site.html"
)

var pages = map[string]*template.Template{}

// funcs are the helpers the templates can call.
var funcs = template.FuncMap{
	// stamp renders a unix timestamp, for the "created" and "last edited"
	// columns.
	"stamp": func(seconds int64) string {
		if seconds <= 0 {
			return "-"
		}

		return time.Unix(seconds, 0).UTC().Format("Jan 2, 2006")
	},

	// accountName is the part of an address before the @, which is what the
	// navigation shows. Whose session this is fits in a corner; the whole
	// address does not.
	"accountName": func(address string) string {
		if at := strings.IndexByte(address, '@'); at > 0 {
			return address[:at]
		}

		return address
	},

	// lines joins a list into the textarea the admin form edits it in.
	"lines": func(values []string) string {
		return strings.Join(values, "\n")
	},

	// version shortens a Secret Manager resource name to the part a person
	// reads, which is the version number on the end.
	"version": func(resource string) string {
		if at := strings.LastIndex(resource, "/"); at >= 0 {
			return resource[at+1:]
		}

		return resource
	},
}

func init() {
	for _, page := range []string{ConfirmPage, MessagePage, LoginPage, SentPage, SitesPage, SitePage} {
		tmpl := template.New(page).Funcs(funcs)
		pages[page] = template.Must(tmpl.ParseFS(templateFS, "templates/base.html", "templates/"+page))
	}
}

// Page is everything the templates can render. Fields that do not apply to a
// given page are simply left empty.
type Page struct {
	Title       string
	ServiceName string
	BaseURL     string
	Email       string
	SignedIn    bool
	// Stylesheet is the versioned path of the service's css. It carries a hash
	// of the file in its name, so a deploy that changes the styling changes
	// this too and no browser is left holding the old one.
	Stylesheet string
	// FontAwesomeKit is the kit that draws the icons, or empty for a build
	// without them. The pages are written to read either way.
	FontAwesomeKit string
	// Nav is which navigation link to mark as current.
	Nav string

	Error   string
	Message string

	// The confirm page. SiteName and Accent are the site being signed in to,
	// not this service: a person who followed a link out of their mail should
	// be told whose login they are finishing.
	SiteName       string
	SiteURL        string
	Accent         template.CSS
	Token          string
	ExpiresMinutes int

	// The admin pages.
	Next string
	// Roster is the whole configuration, for the list.
	Roster sites.Config
	// Site is the one being edited, and New says it does not exist yet.
	Site sites.Site
	New  bool
	// Secret is a freshly generated api key, shown exactly once. It is never
	// read back out of storage, because only its hash is kept.
	Secret string
	// Version is the roster version this instance is serving.
	Version string
}

// New starts a Page with the service-wide values already filled in.
func New(title string) Page {
	return Page{
		Title:          title,
		ServiceName:    config.SERVICE_NAME,
		BaseURL:        config.BASE_URL,
		Stylesheet:     Stylesheet,
		FontAwesomeKit: config.FONTAWESOME_KIT,
	}
}

// ForSite starts a Page that a visitor mid-login sees, wearing the colours of
// the site they came from.
//
// The accent is typed as template.CSS so it can go into a style attribute. That
// is a promise that the value is safe there, and it is kept by the roster:
// AccentColour returns either a value that matched the six-digit-hex pattern or
// the default, and nothing else can reach this field.
func ForSite(title string, site sites.Site) Page {
	page := New(title)

	// An unknown token names no site, and the page it renders is the one saying
	// so. Leaving these empty is what keeps that page in this service's own
	// colours rather than dressing it in a default that belongs to nobody.
	if site.Name == "" {
		return page
	}

	page.SiteName = site.Name
	page.SiteURL = site.BaseURL
	page.Accent = template.CSS(site.AccentColour())

	return page
}

// Render writes an html page. Everything interpolated goes through
// html/template, so values that came in over the wire are escaped for the
// context they land in.
func Render(c *gin.Context, status int, name string, page Page) {
	tmpl, ok := pages[name]
	if !ok {
		log.Printf("no such template: %s", name)
		c.String(http.StatusInternalServerError, "template error")
		return
	}

	// None of these pages is worth keeping. Two of them carry a single-use
	// token in a form, and the rest are per-session.
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(status)

	if err := tmpl.ExecuteTemplate(c.Writer, "base", page); err != nil {
		log.Printf("could not render %s: %s", name, err.Error())
	}
}

// Fail renders an error page, for the handlers that have nothing better to say.
func Fail(c *gin.Context, status int, title string, message string) {
	page := New(title)
	page.Error = message
	Render(c, status, MessagePage, page)
}

// TooManyRequests renders the page a caller gets when they have been turned
// away by a rate limit, with a Retry-After for anything that reads one. It says
// nothing about email addresses, because the limits that use it are counted per
// connection and never look at one.
func TooManyRequests(retryAfter time.Duration) gin.HandlerFunc {
	seconds := strconv.Itoa(int(retryAfter.Seconds()))

	return func(c *gin.Context) {
		c.Header("Retry-After", seconds)

		page := New("Too many attempts")
		page.Error = "Too many attempts from your connection. Wait a minute and try again."
		Render(c, http.StatusTooManyRequests, MessagePage, page)
	}
}

// SafeNext sanitizes a "?next=" value so it can only ever send a browser to a
// path on this service. It is used by the admin pages; a site's own next is
// checked in magiclink and never interpreted here.
func SafeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") {
		return "/"
	}

	if strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}

	if strings.ContainsAny(next, "\r\n") {
		return "/"
	}

	return next
}
