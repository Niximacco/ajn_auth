// Package admin_handler is the roster editor.
//
// It signs its own people in with this service's own magic links, through the
// same code every site uses, and it keeps exactly one user list: the addresses
// in the roster that may edit the roster. Everything else about who may sign in
// anywhere belongs to the sites.
//
// There is no csrf token on these forms. The session cookie is SameSite=Strict,
// so a POST arriving from anywhere but these pages carries no session and is
// bounced to the login screen before a handler sees it. That is the whole of
// the defence, and it is written down here so that anyone who later relaxes the
// cookie knows what they are also turning off.
package admin_handler

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Niximacco/ajn_auth/internal/auth"
	"github.com/Niximacco/ajn_auth/internal/email"
	"github.com/Niximacco/ajn_auth/internal/magiclink"
	"github.com/Niximacco/ajn_auth/internal/ratelimit"
	"github.com/Niximacco/ajn_auth/internal/sites"
	"github.com/Niximacco/ajn_auth/internal/web"
	"github.com/gin-gonic/gin"
)

// The two routes an anonymous caller can reach get a per caller ceiling, for
// the same reason the sites put one on theirs: this is about the cost of being
// probed, not about email, which has its own caps in magiclink.
var (
	loginLimiter    = ratelimit.New(10, time.Minute)
	callbackLimiter = ratelimit.New(20, time.Minute)
)

func AddAdminV1(router *gin.Engine) {
	router.GET("/admin/login", auth.Optional(), LoginPage)
	router.POST("/admin/login", loginLimiter.Middleware(web.TooManyRequests(time.Minute)), RequestLink)
	router.GET("/admin/callback", callbackLimiter.Middleware(web.TooManyRequests(time.Minute)), CompleteLogin)
	router.POST("/admin/logout", Logout)

	pages := router.Group("/admin", auth.Required())
	pages.GET("", Sites)
	pages.GET("/sites/new", NewSite)
	pages.POST("/sites", CreateSite)
	pages.GET("/sites/:id", EditSite)
	pages.POST("/sites/:id", SaveSite)
	pages.POST("/sites/:id/keys", GenerateKey)
	pages.POST("/sites/:id/keys/:key/revoke", RevokeKey)
	pages.POST("/sites/:id/delete", DeleteSite)
	pages.POST("/admins", SaveAdmins)
}

// ------------------------------------------------------------- signing in ---

func LoginPage(c *gin.Context) {
	next := web.SafeNext(c.Query("next"))

	if auth.IsSignedIn(c) {
		c.Redirect(http.StatusFound, next)
		return
	}

	page := web.New("Sign in")
	page.Next = next

	web.Render(c, http.StatusOK, web.LoginPage, page)
}

// RequestLink mails an admin a link, if that address is an admin.
//
// An address that is not on the list is told a link is on its way, exactly as a
// site does for an address that is not one of its users. This form is on the
// open internet and the list behind it is short; it must not be usable to find
// out who runs this.
func RequestLink(c *gin.Context) {
	address := strings.TrimSpace(c.PostForm("email"))
	next := web.SafeNext(c.PostForm("next"))

	page := web.New("Sign in")
	page.Next = next
	page.Email = address

	if !sites.ValidAddress(address) {
		page.Error = "That doesn't look like an email address."
		web.Render(c, http.StatusBadRequest, web.LoginPage, page)
		return
	}

	roster, err := sites.Shared().Current()
	if err != nil {
		log.Printf("could not read the roster to sign an admin in: %s", err.Error())
		page.Title = "Sign in unavailable"
		page.Error = "Sign in is temporarily unavailable. Please try again in a moment."
		web.Render(c, http.StatusServiceUnavailable, web.MessagePage, page)
		return
	}

	if roster.IsAdmin(address) {
		err = magiclink.Request(sites.Self(), address, "", next)

		switch {
		case err == nil, errors.Is(err, magiclink.ErrThrottled):
			// Both look exactly like success. Saying "slow down" would confirm
			// the address is one of ours.

		case errors.Is(err, email.ErrNotConfigured):
			log.Print("an admin link was requested but email sending is not configured")
			page.Title = "Sign in unavailable"
			page.Error = "Sign in is temporarily unavailable. Please try again later."
			web.Render(c, http.StatusServiceUnavailable, web.MessagePage, page)
			return

		default:
			log.Printf("could not send an admin magic link: %s", err.Error())
			page.Title = "Something went wrong"
			page.Error = "We couldn't send your sign in link. Please try again."
			web.Render(c, http.StatusInternalServerError, web.MessagePage, page)
			return
		}
	} else {
		log.Print("admin login requested for an address that is not an admin")
	}

	page.Title = "Check your email"
	page.ExpiresMinutes = int(magiclink.TOKEN_VALID_TIME.Minutes())
	web.Render(c, http.StatusOK, web.SentPage, page)
}

// CompleteLogin is this service's own side of the exchange: the confirm page
// redirected here with a code, and this trades it for the address.
//
// A site does this over http with its api key. This one is in-process, which is
// the only shortcut the self site takes - and it still goes through Redeem, so
// the code is spent, single-use and site-scoped exactly like anybody else's.
func CompleteLogin(c *gin.Context) {
	identity, err := magiclink.Redeem(sites.Self(), c.Query("code"))
	if err != nil {
		page := web.New("That link didn't work")
		page.Error = "This sign in link has already been used or has expired. Request a new one."
		web.Render(c, http.StatusUnauthorized, web.MessagePage, page)
		return
	}

	// The link was valid, but the address may have been taken off the admin
	// list while it sat in the inbox.
	roster, err := sites.Shared().Current()
	if err != nil || !roster.IsAdmin(identity.Email) {
		page := web.New("Not for this account")
		page.Error = "That account can't edit the roster."
		web.Render(c, http.StatusForbidden, web.MessagePage, page)
		return
	}

	if err = auth.StartSession(c, identity.Email); err != nil {
		log.Printf("could not issue an admin session token: %s", err.Error())
		page := web.New("Something went wrong")
		page.Error = "We couldn't start your session. Please try again."
		web.Render(c, http.StatusInternalServerError, web.MessagePage, page)
		return
	}

	log.Printf("signed in an admin")
	c.Redirect(http.StatusSeeOther, web.SafeNext(identity.Next))
}

func Logout(c *gin.Context) {
	auth.ClearSessionCookie(c)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

// ----------------------------------------------------------- the roster ---

// adminPage starts an admin page with the session and the roster already on it.
// The bool is false when the roster could not be read, in which case it has
// already rendered the failure and the caller must simply return.
func adminPage(c *gin.Context, title string) (web.Page, sites.Config, bool) {
	rendered := web.New(title)
	rendered.SignedIn = true
	rendered.Email = auth.Email(c)
	rendered.Nav = "sites"
	rendered.Version = sites.Shared().Version()

	roster, err := sites.Shared().Current()
	if err != nil {
		log.Printf("could not read the roster: %s", err.Error())
		web.Fail(c, http.StatusServiceUnavailable, "The roster is unavailable",
			"We couldn't read the site roster. Try again in a moment.")
		return rendered, sites.Config{}, false
	}

	rendered.Roster = roster
	return rendered, roster, true
}

func Sites(c *gin.Context) {
	rendered, _, ok := adminPage(c, "Sites")
	if !ok {
		return
	}

	web.Render(c, http.StatusOK, web.SitesPage, rendered)
}

func NewSite(c *gin.Context) {
	rendered, _, ok := adminPage(c, "Add a site")
	if !ok {
		return
	}

	rendered.New = true
	web.Render(c, http.StatusOK, web.SitePage, rendered)
}

// read pulls a site out of the submitted form. It does not validate: that is
// Config.Validate's job, and doing it in one place means the admin form and a
// roster pasted straight into Secret Manager are held to the same rules.
func read(c *gin.Context, id string) sites.Site {
	return sites.Site{
		ID:           id,
		Name:         strings.TrimSpace(c.PostForm("name")),
		BaseURL:      strings.TrimSpace(c.PostForm("base_url")),
		RedirectURIs: splitLines(c.PostForm("redirect_uris")),
		MailFrom:     strings.TrimSpace(c.PostForm("mail_from")),
		Accent:       strings.TrimSpace(c.PostForm("accent")),
		Intro:        strings.TrimSpace(c.PostForm("intro")),
		Subject:      strings.TrimSpace(c.PostForm("subject")),
		Disabled:     c.PostForm("disabled") != "",
	}
}

// splitLines reads one of the textareas that hold a list, dropping the blank
// lines a person leaves behind while editing.
func splitLines(value string) []string {
	lines := []string{}

	for _, line := range strings.Split(value, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}

	return lines
}

// CreateSite adds a site, with its first api key.
//
// The key is generated here rather than left for a second step because a site
// without one cannot do anything at all, and the key can only ever be read on
// the page that made it. One trip, one thing to copy.
func CreateSite(c *gin.Context) {
	rendered, roster, ok := adminPage(c, "Add a site")
	if !ok {
		return
	}

	site := read(c, strings.TrimSpace(c.PostForm("id")))
	rendered.Site = site
	rendered.New = true

	if _, err := roster.Find(site.ID); err == nil {
		rendered.Error = "There is already a site called " + site.ID + "."
		web.Render(c, http.StatusConflict, web.SitePage, rendered)
		return
	}

	secret, key, err := sites.NewKey("first key")
	if err != nil {
		log.Printf("could not generate an api key: %s", err.Error())
		rendered.Error = "We couldn't generate an api key. Please try again."
		web.Render(c, http.StatusInternalServerError, web.SitePage, rendered)
		return
	}

	site.Keys = []sites.Key{key}
	roster.Sites = append(roster.Sites, site)

	if err := sites.Shared().Save(roster, auth.Email(c)); err != nil {
		rendered.Error = err.Error()
		web.Render(c, http.StatusBadRequest, web.SitePage, rendered)
		return
	}

	log.Printf("added the site %s", site.ID)

	// Rendered rather than redirected, because the key is on this response and
	// nothing can produce it again.
	rendered, _, ok = adminPage(c, site.Name)
	if !ok {
		return
	}

	rendered.Site = site
	rendered.Secret = secret
	rendered.Message = "Added " + site.ID + "."
	web.Render(c, http.StatusOK, web.SitePage, rendered)
}

func EditSite(c *gin.Context) {
	rendered, roster, ok := adminPage(c, "Site")
	if !ok {
		return
	}

	site, err := roster.Find(c.Param("id"))
	if err != nil {
		web.Fail(c, http.StatusNotFound, "No such site", "There is no site with that id.")
		return
	}

	rendered.Title = site.Name
	rendered.Site = site
	web.Render(c, http.StatusOK, web.SitePage, rendered)
}

func SaveSite(c *gin.Context) {
	rendered, roster, ok := adminPage(c, "Site")
	if !ok {
		return
	}

	id := c.Param("id")

	existing, err := roster.Find(id)
	if err != nil {
		web.Fail(c, http.StatusNotFound, "No such site", "There is no site with that id.")
		return
	}

	updated := read(c, id)
	// The keys are not on the form. Carrying them across explicitly is what
	// keeps a save from silently revoking every one of them.
	updated.Keys = existing.Keys

	roster.Sites = replace(roster.Sites, updated)

	rendered.Title = updated.Name
	rendered.Site = updated

	if err := sites.Shared().Save(roster, auth.Email(c)); err != nil {
		rendered.Error = err.Error()
		web.Render(c, http.StatusBadRequest, web.SitePage, rendered)
		return
	}

	log.Printf("updated the site %s", id)
	c.Redirect(http.StatusSeeOther, "/admin/sites/"+id)
}

func DeleteSite(c *gin.Context) {
	rendered, roster, ok := adminPage(c, "Site")
	if !ok {
		return
	}

	id := c.Param("id")

	site, err := roster.Find(id)
	if err != nil {
		web.Fail(c, http.StatusNotFound, "No such site", "There is no site with that id.")
		return
	}

	rendered.Title = site.Name
	rendered.Site = site

	// Typing the id is the whole confirmation. It is a short list of very
	// similar rows and the button is next to the one that saves.
	if strings.TrimSpace(c.PostForm("confirm")) != id {
		rendered.Error = "Type the site id exactly to confirm removing it."
		web.Render(c, http.StatusBadRequest, web.SitePage, rendered)
		return
	}

	kept := make([]sites.Site, 0, len(roster.Sites))
	for _, candidate := range roster.Sites {
		if candidate.ID != id {
			kept = append(kept, candidate)
		}
	}
	roster.Sites = kept

	if err := sites.Shared().Save(roster, auth.Email(c)); err != nil {
		rendered.Error = err.Error()
		web.Render(c, http.StatusBadRequest, web.SitePage, rendered)
		return
	}

	log.Printf("removed the site %s", id)
	c.Redirect(http.StatusSeeOther, "/admin")
}

// -------------------------------------------------------------- the keys ---

func GenerateKey(c *gin.Context) {
	rendered, roster, ok := adminPage(c, "Site")
	if !ok {
		return
	}

	site, err := roster.Find(c.Param("id"))
	if err != nil {
		web.Fail(c, http.StatusNotFound, "No such site", "There is no site with that id.")
		return
	}

	secret, key, err := sites.NewKey(c.PostForm("note"))
	if err != nil {
		log.Printf("could not generate an api key: %s", err.Error())
		web.Fail(c, http.StatusInternalServerError, "Something went wrong",
			"We couldn't generate an api key. Please try again.")
		return
	}

	site.Keys = append(site.Keys, key)
	roster.Sites = replace(roster.Sites, site)

	rendered.Title = site.Name
	rendered.Site = site
	rendered.Roster = roster

	if err := sites.Shared().Save(roster, auth.Email(c)); err != nil {
		rendered.Error = err.Error()
		web.Render(c, http.StatusBadRequest, web.SitePage, rendered)
		return
	}

	log.Printf("generated api key %s for %s", key.ID, site.ID)

	// Rendered rather than redirected: this response is the only place the key
	// exists in plaintext, and a redirect would throw it away.
	rendered.Secret = secret
	web.Render(c, http.StatusOK, web.SitePage, rendered)
}

func RevokeKey(c *gin.Context) {
	rendered, roster, ok := adminPage(c, "Site")
	if !ok {
		return
	}

	site, err := roster.Find(c.Param("id"))
	if err != nil {
		web.Fail(c, http.StatusNotFound, "No such site", "There is no site with that id.")
		return
	}

	keyID := c.Param("key")

	kept := make([]sites.Key, 0, len(site.Keys))
	for _, key := range site.Keys {
		if key.ID != keyID {
			kept = append(kept, key)
		}
	}

	if len(kept) == len(site.Keys) {
		web.Fail(c, http.StatusNotFound, "No such key", "That key is not on this site.")
		return
	}

	site.Keys = kept
	roster.Sites = replace(roster.Sites, site)

	rendered.Title = site.Name
	rendered.Site = site
	rendered.Roster = roster

	if err := sites.Shared().Save(roster, auth.Email(c)); err != nil {
		rendered.Error = err.Error()
		web.Render(c, http.StatusBadRequest, web.SitePage, rendered)
		return
	}

	// The revoked key keeps working on other instances until their cached copy
	// of the roster ages out, which is a minute. Say so rather than leave
	// somebody believing it stopped the moment they pressed the button.
	log.Printf("revoked api key %s on %s", keyID, site.ID)
	c.Redirect(http.StatusSeeOther, "/admin/sites/"+site.ID)
}

// ------------------------------------------------------------ the admins ---

// SaveAdmins rewrites the list of people who may edit the roster.
//
// Taking yourself off it is allowed, and it is the reason Validate refuses an
// empty list: a roster with no admins cannot be edited through this service by
// anybody, and would have to be fixed with gcloud.
func SaveAdmins(c *gin.Context) {
	_, roster, ok := adminPage(c, "Sites")
	if !ok {
		return
	}

	roster.Admins = splitLines(c.PostForm("admins"))

	if err := sites.Shared().Save(roster, auth.Email(c)); err != nil {
		rendered, _, stillOk := adminPage(c, "Sites")
		if !stillOk {
			return
		}

		rendered.Error = err.Error()
		web.Render(c, http.StatusBadRequest, web.SitesPage, rendered)
		return
	}

	log.Print("updated the admin list")
	c.Redirect(http.StatusSeeOther, "/admin")
}

// replace swaps a site into the roster by id, keeping the order so the list
// does not reshuffle itself every time somebody saves.
func replace(all []sites.Site, updated sites.Site) []sites.Site {
	for i, candidate := range all {
		if candidate.ID == updated.ID {
			all[i] = updated
			return all
		}
	}

	return append(all, updated)
}
