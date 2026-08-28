// Package sites is the roster: which sites may use this service, what their
// login emails look like, and which keys speak for them.
//
// A site is configuration rather than code, because the whole point of this
// service is that a fourth site is a config change and not a deploy. The roster
// is one json document, kept in Secret Manager by the store in this package.
//
// The user lists are not here and never will be. This service knows that
// flight-log exists and how to mail on its behalf; it does not know who is
// allowed into flight-log, because flight-log knows that and the answer changes
// there. A site asks for a link only for an address it has already decided may
// sign in, and checks again when it redeems the code.
package sites

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	// ErrNoSuchSite means nothing in the roster has that id.
	ErrNoSuchSite = errors.New("no such site")
	// ErrBadKey means the presented api key matches no key on any site. It is
	// the only thing an unauthenticated caller is ever told.
	ErrBadKey = errors.New("that api key is not valid")
	// ErrSiteDisabled means the site exists but has been turned off.
	ErrSiteDisabled = errors.New("that site is disabled")
	// ErrBadRedirect means the redirect uri a site asked for is not one it
	// registered.
	ErrBadRedirect = errors.New("that redirect uri is not registered for this site")
)

// siteID is what a site id may look like. It ends up in datastore keys, in log
// lines, and in rate limit buckets, so it is kept to something that cannot be
// confused with any of them.
var siteID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$`)

// accentColour is what a site's brand colour may look like, because it is
// written into the style attribute of the button in every login email. A value
// that is not one of these is dropped rather than interpolated.
var accentColour = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Config is the whole roster, as it is stored.
type Config struct {
	// Admins are the addresses that may sign in to this service's own pages and
	// edit what is in here. It is the one user list this service does keep, and
	// it is only ever about this service.
	Admins []string `json:"admins"`
	Sites  []Site   `json:"sites"`

	// Updated and UpdatedBy record the last edit, so the admin pages can say
	// where a version came from without reading Secret Manager's metadata.
	Updated   int64  `json:"updated,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
}

// Site is one thing that can send people login emails through this service.
type Site struct {
	// ID identifies the site everywhere: in its datastore keys, in its log
	// lines, and in its rate limit buckets. It never changes, because the send
	// counters that protect the email budget are keyed on it.
	ID string `json:"id"`
	// Name is what the emails and the confirm page call this site. It is the
	// visitor-facing name - "Flight Log", not "flight-log".
	Name string `json:"name"`
	// BaseURL is the site's public origin. It is what the confirm page offers
	// as a way back when a link has expired.
	BaseURL string `json:"base_url"`
	// RedirectURIs are the exact urls this site may be handed an exchange code
	// at. A link request naming anything else is refused: this is the check
	// that keeps a leaked api key from mailing your users a link that lands on
	// somebody else's server.
	RedirectURIs []string `json:"redirect_uris"`

	// MailFrom is the From header on this site's login emails, in the form
	// Resend wants - "Flight Log <login@ajn.me>". The domain has to be verified
	// with Resend on the one account this service holds the key for.
	MailFrom string `json:"mail_from"`
	// Accent is the button colour in the email, "#1d1d1f". Empty is the
	// default near-black.
	Accent string `json:"accent,omitempty"`
	// Intro replaces the line of copy above the button, for a site that wants
	// to say something of its own. Empty is the default sentence.
	Intro string `json:"intro,omitempty"`
	// Subject replaces the whole subject line. Empty is "Your sign in link for
	// <Name>".
	Subject string `json:"subject,omitempty"`

	// Keys are the api keys that may act as this site. There is a list rather
	// than one value so a key can be rotated with both live for as long as it
	// takes to deploy the new one.
	Keys []Key `json:"keys"`

	// Disabled stops this site sending anything, without losing its
	// configuration or its send history.
	Disabled bool `json:"disabled,omitempty"`
}

// Key is one api key, as it is stored: the hash and nothing else.
//
// The plaintext is shown once, on the page that generated it, and is not
// recoverable afterwards. That is what keeps a leaked copy of the roster from
// being a set of working credentials, and it is why the admin pages offer
// "generate a new key" rather than "show me the key".
type Key struct {
	// ID names the key in the admin pages and in the log line that says which
	// one was used. It is the first characters of the key itself, which is what
	// lets a key found in a site's own config be matched to a row here.
	ID   string `json:"id"`
	Hash string `json:"hash"`
	// Note is whatever the person who made it wanted to remember - "cloud run",
	// "laptop".
	Note    string `json:"note,omitempty"`
	Created int64  `json:"created"`
}

// KeyPrefix is on the front of every generated key. It is there so that a key
// that ends up somewhere it should not be - a commit, a log line, a paste - is
// recognisable as this service's, by a person or by a secret scanner.
const KeyPrefix = "ajnauth_"

// keyBytes is the entropy behind a key. These are bearer credentials that are
// not rotated on a schedule, so they are generously sized.
const keyBytes = 32

// NewKey returns a key to give to a site and the record to store for it. The
// plaintext is returned exactly once and is never persisted.
func NewKey(note string) (plaintext string, record Key, err error) {
	buffer := make([]byte, keyBytes)
	if _, err = rand.Read(buffer); err != nil {
		return "", Key{}, err
	}

	plaintext = KeyPrefix + base64.RawURLEncoding.EncodeToString(buffer)

	return plaintext, Key{
		ID:      keyID(plaintext),
		Hash:    HashKey(plaintext),
		Note:    strings.TrimSpace(note),
		Created: time.Now().Unix(),
	}, nil
}

// HashKey is how a key is stored and compared. A plain sha256 is right here and
// a password hash would not be: this is 256 bits of uniform randomness, so
// there is no dictionary to run and nothing for a work factor to slow down -
// and it is checked on the hot path of every login.
func HashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// keyID is the recognisable head of a key, used to name it in the admin pages.
// It is short enough to be useless on its own and long enough to tell two keys
// on one site apart.
func keyID(plaintext string) string {
	trimmed := strings.TrimPrefix(plaintext, KeyPrefix)
	if len(trimmed) > 6 {
		trimmed = trimmed[:6]
	}

	return KeyPrefix + trimmed
}

// Find returns the site with an id, whether or not it is disabled.
func (c Config) Find(id string) (Site, error) {
	for _, site := range c.Sites {
		if site.ID == id {
			return site, nil
		}
	}

	return Site{}, ErrNoSuchSite
}

// Authenticate returns the site an api key speaks for.
//
// Every key on every site is compared, in constant time, with no early return
// on whichever site happens to be listed first. A caller learns whether their
// key works and nothing else - not how many sites there are, and not whether a
// key that failed was close to one that would have worked.
func (c Config) Authenticate(plaintext string) (Site, error) {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return Site{}, ErrBadKey
	}

	presented := []byte(HashKey(plaintext))

	found := Site{}
	matched := false

	for _, site := range c.Sites {
		for _, key := range site.Keys {
			if subtle.ConstantTimeCompare(presented, []byte(key.Hash)) == 1 {
				found = site
				matched = true
			}
		}
	}

	if !matched {
		return Site{}, ErrBadKey
	}

	if found.Disabled {
		return found, ErrSiteDisabled
	}

	return found, nil
}

// CheckRedirect confirms a redirect uri is one this site registered, and
// returns it in the exact form that was registered.
//
// The comparison is on the whole url and it is exact. Prefix matching is the
// classic way this check is got wrong: "starts with https://site/" is satisfied
// by "https://site/@evil.example", and matching only the origin turns any open
// redirect on the site into one here.
func (s Site) CheckRedirect(redirect string) (string, error) {
	redirect = strings.TrimSpace(redirect)

	// A site that asks for nothing gets the first uri it registered. Every site
	// so far has exactly one, and this is what lets a site's config say nothing
	// about a value it could only ever repeat.
	if redirect == "" {
		if len(s.RedirectURIs) == 0 {
			return "", ErrBadRedirect
		}

		return s.RedirectURIs[0], nil
	}

	for _, registered := range s.RedirectURIs {
		if subtle.ConstantTimeCompare([]byte(redirect), []byte(registered)) == 1 {
			return registered, nil
		}
	}

	return "", ErrBadRedirect
}

// AccentColour is the button colour for this site's emails, defaulting to the
// near-black the pages use. A value that is not a six digit hex colour is
// dropped: it is interpolated into a style attribute, and a mis-typed one
// should give a plain button rather than a broken email.
func (s Site) AccentColour() string {
	if accentColour.MatchString(s.Accent) {
		return s.Accent
	}

	return "#1d1d1f"
}

// EmailSubject is the subject line of this site's login emails.
func (s Site) EmailSubject() string {
	if subject := strings.TrimSpace(s.Subject); subject != "" {
		return subject
	}

	return fmt.Sprintf("Your sign in link for %s", s.Name)
}

// EmailIntro is the line of copy above the button.
func (s Site) EmailIntro() string {
	if intro := strings.TrimSpace(s.Intro); intro != "" {
		return intro
	}

	return "Click the button below to finish signing in."
}

// IsAdmin reports whether an address may edit this roster.
func (c Config) IsAdmin(address string) bool {
	address = NormalizeEmail(address)
	if address == "" {
		return false
	}

	for _, admin := range c.Admins {
		if NormalizeEmail(admin) == address {
			return true
		}
	}

	return false
}

// NormalizeEmail is how an address is compared everywhere in this service:
// trimmed and lower-cased. It matches what the sites do, so an address means
// the same thing on both sides of the api.
func NormalizeEmail(address string) string {
	return strings.ToLower(strings.TrimSpace(address))
}

// Validate checks a whole roster before it is saved. It is the only thing
// standing between a typo in the admin form and a service that cannot mail
// anybody, so it is stricter than the reader has to be.
func (c Config) Validate() error {
	if len(c.Admins) == 0 {
		return errors.New("the roster needs at least one admin, or nobody can edit it again")
	}

	for _, admin := range c.Admins {
		if !ValidAddress(admin) {
			return fmt.Errorf("%q is not a usable email address", admin)
		}
	}

	seen := map[string]bool{}
	for _, site := range c.Sites {
		if err := site.Validate(); err != nil {
			return err
		}

		if site.ID == SelfID {
			return fmt.Errorf("%q is this service's own id and cannot be used for a site", SelfID)
		}

		if seen[site.ID] {
			return fmt.Errorf("two sites are both called %q", site.ID)
		}
		seen[site.ID] = true
	}

	return nil
}

// Validate checks one site.
func (s Site) Validate() error {
	if !siteID.MatchString(s.ID) {
		return fmt.Errorf("%q is not a usable site id: lower case letters, digits and hyphens, 3 to 40 characters", s.ID)
	}

	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("site %q needs a name, it is what its emails call it", s.ID)
	}

	if err := checkOrigin(s.BaseURL); err != nil {
		return fmt.Errorf("site %q: base url %w", s.ID, err)
	}

	if len(s.RedirectURIs) == 0 {
		return fmt.Errorf("site %q needs at least one redirect uri, or it has nowhere to sign anybody in", s.ID)
	}

	for _, redirect := range s.RedirectURIs {
		if err := checkOrigin(redirect); err != nil {
			return fmt.Errorf("site %q: redirect uri %q %w", s.ID, redirect, err)
		}
	}

	if strings.TrimSpace(s.MailFrom) == "" {
		return fmt.Errorf("site %q needs a from address for its emails", s.ID)
	}

	// A line break in the From header is header injection, and Resend takes
	// this value as it is given. Nothing else in the config reaches a header.
	if strings.ContainsAny(s.MailFrom, "\r\n") {
		return fmt.Errorf("site %q has a from address with a line break in it", s.ID)
	}

	if s.Accent != "" && !accentColour.MatchString(s.Accent) {
		return fmt.Errorf("site %q: %q is not a colour like #1d1d1f", s.ID, s.Accent)
	}

	return nil
}

// checkOrigin is what a url has to be to be worth sending a person who is
// mid-login to: absolute, https, and with a host.
//
// http is allowed only for localhost, which is what makes a site runnable on a
// laptop against the deployed service. Anywhere else it would mean mailing
// somebody a link that hands their exchange code to the network.
func checkOrigin(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("is missing")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("is not a url")
	}

	if parsed.Host == "" {
		return errors.New("has no host, it must be absolute")
	}

	host := parsed.Hostname()
	local := host == "localhost" || host == "127.0.0.1" || host == "::1"

	switch parsed.Scheme {
	case "https":
	case "http":
		if !local {
			return errors.New("must be https")
		}
	default:
		return errors.New("must be an http url")
	}

	// A fragment is never sent to the server, so a redirect uri carrying one is
	// a misunderstanding about where the code will arrive.
	if strings.Contains(raw, "#") {
		return errors.New("must not have a fragment")
	}

	return nil
}

// ValidAddress is a deliberately loose check on an email address. The real
// check is the site's own user list, which this service does not hold; this
// only catches obvious junk before anything is stored or mailed.
func ValidAddress(address string) bool {
	address = NormalizeEmail(address)

	if len(address) < 3 || len(address) > 254 {
		return false
	}

	at := strings.LastIndex(address, "@")
	if at < 1 || at == len(address)-1 {
		return false
	}

	domain := address[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	return !strings.ContainsAny(address, " \t\r\n<>\"")
}
