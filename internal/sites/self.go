package sites

import (
	"github.com/Niximacco/ajn_auth/internal/config"
)

// SelfID is the site this service is to itself.
//
// The admin pages need a login, and there was a choice between writing a second
// one for them and treating this service as one more site on its own roster.
// This is the second: the admin sign in goes through the same Request, the same
// confirm page and the same Consume as flight-log's does, so the path every
// site depends on is the path that is exercised every time somebody opens these
// pages. A login that only breaks for other people is a login nobody notices is
// broken.
//
// It is built rather than stored, so it cannot be edited away by an admin, and
// its user list is the roster's own Admins rather than anything held for it.
const SelfID = "ajn-auth"

// Self is the built-in registration for this service.
func Self() Site {
	return Site{
		ID:           SelfID,
		Name:         config.SERVICE_NAME,
		BaseURL:      config.BASE_URL + "/admin",
		RedirectURIs: []string{config.BASE_URL + "/admin/callback"},
		MailFrom:     config.MAIL_FROM,
		Accent:       "#1a7f52",
		Subject:      "Your sign in link for " + config.SERVICE_NAME,
	}
}

// Lookup finds a site by id, including this service itself. It is what the
// callback resolves against, so a magic link minted for the admin pages is
// consumed by exactly the same code as one minted for a site.
func (c Config) Lookup(id string) (Site, error) {
	if id == SelfID {
		return Self(), nil
	}

	return c.Find(id)
}
