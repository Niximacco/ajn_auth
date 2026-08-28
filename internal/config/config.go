// Package config is everything this service reads out of its environment.
//
// The roster of sites is deliberately not here. It changes without a deploy and
// it is edited through the admin pages, so it lives in Secret Manager and is
// loaded by the sites package.
package config

import (
	"log"
	"os"
	"regexp"
	"strings"
)

var (
	// BASE_URL is the public origin this service is reached at. Magic links and
	// the confirm form are built from it, so it has to match what the browser
	// actually sees.
	BASE_URL = "https://auth.ajn.me"
	// SERVICE_NAME is what this service's own pages and its admin sign-in email
	// call it. Site emails are named by the site, never by this.
	SERVICE_NAME = "ajn auth"
	// FONTAWESOME_KIT is the id of the Font Awesome kit that draws the icons,
	// or empty for a build with no icons on it. It is an identifier rather than
	// a credential - it ends up in the page source of every request - but it is
	// configuration rather than code, because the kit belongs to an account
	// this repository knows nothing about.
	FONTAWESOME_KIT = ""

	// MAIL_FROM is the From header used when a site has not registered one of
	// its own, and the one this service's own admin login is sent as. The
	// domain has to be verified with Resend on the account RESEND_API_KEY
	// belongs to.
	MAIL_FROM = ""

	// SITES_SECRET is the Secret Manager resource the site roster is kept in,
	// "projects/<project>/secrets/<name>". Versions are added by the admin
	// pages and read back by every instance, so the roster survives a deploy
	// and a rollback is a matter of pinning an older version by hand.
	SITES_SECRET = ""
)

// kitID is what a Font Awesome kit id looks like. The value is interpolated
// into a script src, so it is checked against this rather than trusted: a
// mis-set variable should turn the icons off, not put arbitrary text into a
// <script> tag. html/template would escape it anyway; this is the belt to that
// pair of braces.
var kitID = regexp.MustCompile(`^[a-zA-Z0-9]{6,32}$`)

func init() {
	if baseURL := os.Getenv("APP_BASE_URL"); baseURL != "" {
		BASE_URL = strings.TrimRight(baseURL, "/")
	} else {
		log.Printf("APP_BASE_URL is not set, magic links will point at %s", BASE_URL)
	}

	if name := os.Getenv("SERVICE_NAME"); name != "" {
		SERVICE_NAME = name
	}

	MAIL_FROM = strings.TrimSpace(os.Getenv("MAIL_FROM"))
	if MAIL_FROM == "" {
		log.Print("MAIL_FROM is not set, so a site without a from address of its own cannot send and neither can the admin login")
	}

	SITES_SECRET = strings.TrimSpace(os.Getenv("SITES_SECRET"))

	switch kit := strings.TrimSpace(os.Getenv("FONTAWESOME_KIT")); {
	case kit == "":
		log.Printf("FONTAWESOME_KIT is not set, the pages will render without icons")

	case kitID.MatchString(kit):
		FONTAWESOME_KIT = kit

	default:
		log.Printf("FONTAWESOME_KIT does not look like a kit id, the pages will render without icons")
	}
}
