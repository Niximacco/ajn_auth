// Package authclient is the site's half of the magic link login.
//
// A site keeps its own user list, its own sessions and its own idea of what an
// account may do. What it hands over is the part that was identical in all
// three of them: generating a token, mailing it, hosting the confirm page, and
// the rate limits that keep one guessed address from costing a fortune at
// Resend.
//
// The whole integration is two calls:
//
//	// on POST /login, for an address the site has already decided may sign in
//	client.RequestLink(ctx, address, next)
//
//	// on GET /auth/callback?code=...
//	identity, err := client.Redeem(ctx, c.Query("code"))
//
// with the site checking its own user list again on the way out of Redeem,
// because access can be revoked while a link sits in an inbox.
//
// It has no dependencies beyond the standard library, on purpose: it is
// imported by every site, and a login should not be able to break because
// something three levels down changed.
package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	// ErrNotConfigured means this client has no url or no api key, so it cannot
	// call anything.
	ErrNotConfigured = errors.New("ajn auth is not configured")
	// ErrUnauthorized means the api key was refused. It is a fault in this
	// site's configuration and never anything about the person signing in.
	ErrUnauthorized = errors.New("ajn auth refused this site's api key")
	// ErrInvalidEmail means the address is not a usable address.
	ErrInvalidEmail = errors.New("that doesn't look like an email address")
	// ErrBadCode means the code was unknown, already redeemed, expired, or
	// belongs to another site. Show the visitor "that link didn't work" and
	// offer them a new one.
	ErrBadCode = errors.New("this login could not be completed")
	// ErrUnavailable means the service could not be reached or answered that it
	// cannot send right now. It is temporary and worth retrying.
	ErrUnavailable = errors.New("ajn auth is unavailable")
)

// Status is what came of asking for a link.
type Status string

const (
	// Sent means a link went out.
	Sent Status = "sent"
	// Throttled means the address has had its allowance of links for now.
	//
	// A site must render this exactly as it renders Sent. Showing anything
	// different turns the login form into a way of finding out which addresses
	// are real, which is the one thing the caps must not cost.
	Throttled Status = "throttled"
)

// Identity is who a redeemed code belonged to.
type Identity struct {
	// Email is the address, normalized the same way the site normalizes its
	// own: trimmed and lower-cased.
	Email string `json:"email"`
	// Next is the path the site asked to return to, or "" if it asked for none.
	// It came back the way it went out, and the site should still put it
	// through its own next-sanitizing before redirecting.
	Next string `json:"next"`
}

// Client talks to an ajn auth service on behalf of one site.
type Client struct {
	// BaseURL is the service's origin, "https://auth.ajn.me".
	BaseURL string
	// APIKey is this site's key. It authenticates the site and nothing else -
	// it says nothing about which person is signing in.
	APIKey string
	// RedirectURI is where this site wants exchange codes delivered. Leave it
	// empty to use the first uri registered for the site, which is what a site
	// with one callback should do: it keeps the value in one place, the roster.
	RedirectURI string

	// HTTP is the client used for the two calls. Leave it nil for a sensible
	// default with a timeout on it.
	HTTP *http.Client
}

// timeout bounds both calls. Requesting a link waits on Resend, which is the
// slow one; redeeming a code is a datastore transaction and is quick.
const timeout = 15 * time.Second

// New returns a client configured from the environment:
//
//	AJN_AUTH_URL           the service origin, "https://auth.ajn.me"
//	AJN_AUTH_API_KEY       this site's key, from the admin pages
//	AJN_AUTH_REDIRECT_URI  optional, when a site has more than one callback
//
// It returns a client either way. A site with none of these set gets one that
// fails every call with ErrNotConfigured, which is the same shape of failure
// the sites already have for an unset Resend key: login is unavailable and
// nothing else is.
func New() *Client {
	return &Client{
		BaseURL:     strings.TrimRight(strings.TrimSpace(os.Getenv("AJN_AUTH_URL")), "/"),
		APIKey:      strings.TrimSpace(os.Getenv("AJN_AUTH_API_KEY")),
		RedirectURI: strings.TrimSpace(os.Getenv("AJN_AUTH_REDIRECT_URI")),
	}
}

// Configured reports whether this client can actually call anything. A site
// should check it at start and say so in its logs, rather than discovering it
// at somebody's first login.
func (c *Client) Configured() bool {
	return c != nil && c.BaseURL != "" && c.APIKey != ""
}

// RequestLink mails a login link to an address.
//
// Call it only for an address the site has already decided may sign in. This
// service does not hold the user list and cannot make that decision; an address
// that is not a user of the site should be answered with the same "check your
// email" page and no call made at all.
//
// next is a path on the site to land on afterwards, or "". It must begin with a
// single "/" - anything that could resolve to another origin is refused rather
// than quietly rewritten, because a site sending one has a bug.
func (c *Client) RequestLink(ctx context.Context, address string, next string) (Status, error) {
	var reply struct {
		Status Status `json:"status"`
		Error  string `json:"error"`
	}

	status, err := c.call(ctx, "/v1/links", map[string]string{
		"email":        address,
		"redirect_uri": c.RedirectURI,
		"next":         next,
	}, &reply)
	if err != nil {
		return "", err
	}

	switch status {
	case http.StatusOK:
		if reply.Status == Throttled {
			return Throttled, nil
		}

		return Sent, nil

	case http.StatusBadRequest:
		// The service distinguishes a bad address from a bad next or an
		// unregistered redirect uri. Only the first is about the person typing;
		// the rest are this site's configuration and are worth surfacing as
		// they came.
		if strings.Contains(reply.Error, "email address") {
			return "", ErrInvalidEmail
		}

		return "", fmt.Errorf("%w: %s", ErrNotConfigured, reply.Error)

	case http.StatusUnauthorized:
		return "", ErrUnauthorized

	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return "", ErrUnavailable

	default:
		return "", fmt.Errorf("ajn auth returned %d: %s", status, reply.Error)
	}
}

// Redeem trades the code from the callback query string for the address behind
// it. The code is single-use and short-lived, so this must be called once, on
// the request that received it.
//
// The address it returns is a person the service is satisfied clicked a link
// that was mailed to that address. It is not a person the site has agreed may
// sign in: check your own user list again here, because access can be revoked
// while a link sits in an inbox.
func (c *Client) Redeem(ctx context.Context, code string) (Identity, error) {
	var reply struct {
		Identity
		Error string `json:"error"`
	}

	status, err := c.call(ctx, "/v1/exchange", map[string]string{"code": code}, &reply)
	if err != nil {
		return Identity{}, err
	}

	switch status {
	case http.StatusOK:
		if reply.Email == "" {
			return Identity{}, ErrBadCode
		}

		return reply.Identity, nil

	case http.StatusUnauthorized:
		// Both a refused key and a spent code answer 401, and they are told
		// apart by the body: a key problem is this site's, a code problem is
		// the visitor's and is the ordinary case of a link used twice.
		if strings.Contains(reply.Error, "unauthorized") {
			return Identity{}, ErrUnauthorized
		}

		return Identity{}, ErrBadCode

	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return Identity{}, ErrUnavailable

	default:
		return Identity{}, fmt.Errorf("ajn auth returned %d: %s", status, reply.Error)
	}
}

// call posts a json body and decodes a json reply, returning the status code so
// the caller can map it to something a page can act on.
func (c *Client) call(ctx context.Context, path string, body any, into any) (int, error) {
	if !c.Configured() {
		return 0, ErrNotConfigured
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return 0, err
	}

	request.Header.Set("Authorization", "Bearer "+c.APIKey)
	request.Header.Set("Content-Type", "application/json")

	response, err := c.http().Do(request)
	if err != nil {
		// A service that cannot be reached is temporary and the caller should
		// say so, rather than showing somebody an error about their address.
		return 0, fmt.Errorf("%w: %s", ErrUnavailable, err.Error())
	}
	defer response.Body.Close()

	// Cap the read. Nothing here is large, and an unbounded read of a reply
	// from anywhere is a way to be made to allocate.
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8192))
	if err != nil {
		return response.StatusCode, fmt.Errorf("%w: %s", ErrUnavailable, err.Error())
	}

	// A body that will not parse is not fatal on its own; the status decides.
	_ = json.Unmarshal(raw, into)

	return response.StatusCode, nil
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}

	return &http.Client{Timeout: timeout}
}
