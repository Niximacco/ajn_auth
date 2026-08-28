// Package magiclink is the login itself: what gets mailed, what spends it, and
// what a site is handed at the end.
//
// It is the logic that used to sit in three repositories, with one change of
// shape. It no longer asks whether an address may sign in, because it no longer
// can: the user lists stayed with the sites. A site asks for a link only for an
// address it has already decided about, and decides again when it redeems the
// code - which is also where a revoked account is caught, and is the right
// place for it, since that is where the answer lives.
package magiclink

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	data "github.com/Niximacco/ajn_auth/internal/cloud"
	"github.com/Niximacco/ajn_auth/internal/config"
	"github.com/Niximacco/ajn_auth/internal/email"
	"github.com/Niximacco/ajn_auth/internal/sites"
)

const (
	// TOKEN_VALID_TIME is how long a magic link works for.
	TOKEN_VALID_TIME = 15 * time.Minute

	// CODE_VALID_TIME is how long the site has to trade an exchange code for
	// the address behind it. It is short because it does not need to be long:
	// the redeem happens in the same redirect that delivered the code, server
	// to server, while the person is watching a page load.
	CODE_VALID_TIME = 2 * time.Minute

	// SEND_THROTTLE is the minimum gap between two links for the same address
	// on the same site.
	SEND_THROTTLE = 60 * time.Second

	// SEND_LIMIT_HOUR and SEND_LIMIT_DAY cap how many links one address can
	// have mailed to it, per site, inside SEND_WINDOW_HOUR and SEND_WINDOW_DAY.
	//
	// SEND_THROTTLE on its own only spaces sends out, it does not bound them: a
	// link a minute forever is 1440 emails a day to a single address, which is
	// enough to burn through a Resend plan and bury whoever owns that address,
	// off nothing more than a guessed email. These are what actually bound the
	// send budget, and because they are counted from state in datastore they
	// hold across every running instance.
	SEND_LIMIT_HOUR = 5
	SEND_LIMIT_DAY  = 15

	SEND_WINDOW_HOUR = time.Hour
	SEND_WINDOW_DAY  = 24 * time.Hour

	// tokenBytes is the amount of entropy behind a link, and behind the code it
	// turns into.
	tokenBytes = 32
)

var (
	// ErrThrottled means a link was already sent to this address for this site
	// moments ago, or the address is at its cap.
	ErrThrottled = errors.New("a login link was sent recently")
	// ErrInvalidEmail means the submitted address isn't a usable address.
	ErrInvalidEmail = errors.New("that doesn't look like an email address")
	// ErrBadToken covers every reason a magic link won't sign somebody in:
	// unknown, already used, or expired.
	ErrBadToken = errors.New("this login link is no longer valid")
	// ErrBadCode covers the same for an exchange code.
	ErrBadCode = errors.New("this login could not be completed")
	// ErrBadNext means the site asked us to land somewhere that is not a path
	// on the site.
	ErrBadNext = errors.New("next must be a path beginning with /")
)

// newSecret returns a value to hand out and the hash to store for it. The
// plaintext is never persisted, so neither a magic link nor an exchange code
// can be read back out of datastore and used.
func newSecret() (secret string, hash string, err error) {
	buffer := make([]byte, tokenBytes)
	if _, err = rand.Read(buffer); err != nil {
		return "", "", err
	}

	secret = base64.RawURLEncoding.EncodeToString(buffer)
	return secret, hashSecret(secret), nil
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Request mails a login link on behalf of a site.
//
// redirect must already have been checked against the site's registered uris by
// the caller, or be empty to mean the first uri the site registered. next is a
// path on the site to land on afterwards.
//
// Whether the address is allowed to sign in is the site's question and it has
// already answered it. This decides only whether we are willing to send another
// email to that address today.
func Request(site sites.Site, address string, redirect string, next string) error {
	address = sites.NormalizeEmail(address)
	if !sites.ValidAddress(address) {
		return ErrInvalidEmail
	}

	next, err := SafeNext(next)
	if err != nil {
		return err
	}

	record, err := data.GetSendRecord(site.ID, address)
	if err != nil {
		return err
	}

	if record.LastSent > 0 && time.Since(time.Unix(record.LastSent, 0)) < SEND_THROTTLE {
		return ErrThrottled
	}

	// Same error as the throttle on purpose. A site renders both as success, so
	// being capped stays indistinguishable from a link going out and the login
	// form cannot be used to work out which addresses are real.
	if OverSendLimit(record.RecentSends, time.Now()) {
		log.Printf("magic link send limit reached for an address on %s", site.ID)
		return ErrThrottled
	}

	token, tokenHash, err := newSecret()
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(TOKEN_VALID_TIME)
	if err = data.NewMagicLink(tokenHash, data.MagicLink{
		SiteID:      site.ID,
		Email:       address,
		RedirectURI: redirect,
		Next:        next,
		ExpiresAt:   expiresAt.Unix(),
	}); err != nil {
		return err
	}

	if err = email.SendLogin(site, address, buildURL(token), int(TOKEN_VALID_TIME.Minutes())); err != nil {
		return err
	}

	// Only throttle once something was actually delivered, so a Resend outage
	// doesn't lock the user out for a minute at a time.
	if err = data.MarkSent(site.ID, address, time.Now(), SEND_WINDOW_DAY); err != nil {
		log.Printf("could not record a magic link send: %s", err.Error())
	}

	log.Printf("mailed a login link for %s", site.ID)
	return nil
}

// OverSendLimit reports whether an address has had its allowance of links for
// now. Both windows are counted off the same list of send times, which
// data.MarkSent keeps pruned to the longer of the two.
func OverSendLimit(sends []int64, now time.Time) bool {
	withinHour, withinDay := 0, 0

	for _, send := range sends {
		age := now.Sub(time.Unix(send, 0))
		if age < 0 {
			// A send stamped in the future: clock skew, or an entity edited by
			// hand. Count it against the tighter window rather than ignore it,
			// so a bad value cannot be used to unlock more sends.
			age = 0
		}

		if age < SEND_WINDOW_HOUR {
			withinHour++
		}

		if age < SEND_WINDOW_DAY {
			withinDay++
		}
	}

	return withinHour >= SEND_LIMIT_HOUR || withinDay >= SEND_LIMIT_DAY
}

// Peek reports which site a token belongs to, without spending it.
//
// It is what lets the confirm page say "sign in to Flight Log" in Flight Log's
// colour. The alternative was carrying the site id in the link's query string,
// which would have made the name on that page something an attacker could
// choose - and a page whose entire job is to tell somebody where they are must
// not take that from anywhere but the token.
func Peek(token string, roster sites.Config) (sites.Site, error) {
	if token == "" {
		return sites.Site{}, ErrBadToken
	}

	link, err := data.PeekMagicLink(hashSecret(token))
	if err != nil {
		if errors.Is(err, data.TokenNotFoundErr) || errors.Is(err, data.TokenUsedErr) || errors.Is(err, data.TokenExpiredErr) {
			// A link that is spent or stale still names its site, and saying
			// which one makes "ask for a new link" an instruction somebody can
			// follow. An unknown token names nothing, so that one stays blank.
			if link.SiteID != "" {
				if site, found := roster.Lookup(link.SiteID); found == nil {
					return site, ErrBadToken
				}
			}

			return sites.Site{}, ErrBadToken
		}

		return sites.Site{}, err
	}

	site, err := roster.Lookup(link.SiteID)
	if err != nil || site.Disabled {
		return sites.Site{}, ErrBadToken
	}

	return site, nil
}

// Consumed is a spent magic link: who it was for, and where to send them.
type Consumed struct {
	Site  sites.Site
	Email string
	// Code is the exchange code, to be handed to the site in the redirect.
	Code string
	// RedirectURI is the url to deliver it to, as the site registered it.
	RedirectURI string
	Next        string
}

// Consume spends a magic link and mints the exchange code that replaces it.
//
// The two are separate values with separate lifetimes because they travel by
// different routes. The token went through a mail server and sat in an inbox;
// the code goes over one redirect and is traded in immediately. Spending the
// first to mint the second is what stops a link that has been sitting in a
// mailbox for a week from still being a working credential.
func Consume(token string, roster sites.Config) (Consumed, error) {
	if token == "" {
		return Consumed{}, ErrBadToken
	}

	link, err := data.ConsumeMagicLink(hashSecret(token))
	if err != nil {
		if errors.Is(err, data.TokenNotFoundErr) || errors.Is(err, data.TokenUsedErr) || errors.Is(err, data.TokenExpiredErr) {
			log.Printf("rejected magic link: %s", err.Error())
			return Consumed{}, ErrBadToken
		}
		return Consumed{}, err
	}

	// The site could have been removed or disabled while the link sat in
	// somebody's inbox.
	site, err := roster.Lookup(link.SiteID)
	if err != nil || site.Disabled {
		log.Printf("magic link for a site that is gone or disabled: %s", link.SiteID)
		return Consumed{}, ErrBadToken
	}

	// The uri was pinned when the link was mailed. It is checked again against
	// what the site currently has registered, so a redirect target removed from
	// the roster stops working immediately rather than for links mailed after
	// the edit.
	redirect, err := site.CheckRedirect(link.RedirectURI)
	if err != nil {
		log.Printf("magic link for %s named a redirect uri that is no longer registered", site.ID)
		return Consumed{}, ErrBadToken
	}

	code, codeHash, err := newSecret()
	if err != nil {
		return Consumed{}, err
	}

	if err = data.NewExchangeCode(codeHash, data.ExchangeCode{
		SiteID:    site.ID,
		Email:     link.Email,
		Next:      link.Next,
		ExpiresAt: time.Now().Add(CODE_VALID_TIME).Unix(),
	}); err != nil {
		return Consumed{}, err
	}

	return Consumed{
		Site:        site,
		Email:       link.Email,
		Code:        code,
		RedirectURI: redirect,
		Next:        link.Next,
	}, nil
}

// Identity is what a site gets back for an exchange code.
type Identity struct {
	Email string
	Next  string
}

// Redeem trades an exchange code for the address it stands for. site is the
// site the presented api key authenticated as, so a code can only ever be
// spent by the site it was minted for.
func Redeem(site sites.Site, code string) (Identity, error) {
	if code == "" {
		return Identity{}, ErrBadCode
	}

	redeemed, err := data.RedeemExchangeCode(hashSecret(code), site.ID)
	if err != nil {
		switch {
		case errors.Is(err, data.CodeNotFoundErr), errors.Is(err, data.CodeUsedErr),
			errors.Is(err, data.CodeExpiredErr), errors.Is(err, data.CodeWrongSite):
			log.Printf("rejected an exchange code for %s: %s", site.ID, err.Error())
			return Identity{}, ErrBadCode
		}

		return Identity{}, err
	}

	log.Printf("completed a login for %s", site.ID)
	return Identity{Email: redeemed.Email, Next: redeemed.Next}, nil
}

// Deliver is the url a consumed link redirects the browser to: the site's
// registered callback, with the exchange code on it.
func (c Consumed) Deliver() (string, error) {
	target, err := url.Parse(c.RedirectURI)
	if err != nil {
		return "", err
	}

	// Whatever query the registered uri already carries is kept, and the code
	// is added to it. A site is free to register a callback with something of
	// its own in the query string.
	query := target.Query()
	query.Set("code", c.Code)
	target.RawQuery = query.Encode()

	return target.String(), nil
}

// SafeNext checks the path a site wants its user returned to.
//
// This service will not put anything in front of a browser that could send it
// to another origin. The site sanitizes this too - it is the site's url space,
// and it is the one that knows which of its paths exist - but the value passes
// through here and comes back out attached to a redirect, so it is checked at
// both ends. An absolute url, a protocol-relative "//host", a backslash trick
// or an embedded newline is refused outright rather than quietly rewritten,
// because a site sending one has a bug and should hear about it.
func SafeNext(next string) (string, error) {
	next = strings.TrimSpace(next)
	if next == "" {
		return "", nil
	}

	if !strings.HasPrefix(next, "/") ||
		strings.HasPrefix(next, "//") ||
		strings.HasPrefix(next, "/\\") ||
		strings.ContainsAny(next, "\r\n") {
		return "", ErrBadNext
	}

	return next, nil
}

// buildURL is the link that goes in the email. It points at this service: the
// token is ours, the confirm step is ours, and the site is not involved until
// there is a code to hand it.
func buildURL(token string) string {
	query := url.Values{}
	query.Set("token", token)

	return fmt.Sprintf("%s/callback?%s", config.BASE_URL, query.Encode())
}
