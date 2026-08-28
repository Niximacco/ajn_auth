# ajn_auth

The site's half of magic link sign in — one package, no dependencies beyond the standard library.

```go
import "github.com/Niximacco/ajn_auth/pkg/authclient"
```

The service it talks to is a separate repository,
[Niximacco/ajn_auth_service](https://github.com/Niximacco/ajn_auth_service), and is deployed to
`auth.ajn.me`. That split is the reason this one is public and this small: a site adding a login
should pull in a few hundred lines of `net/http`, not datastore, Secret Manager and gin.

Three sites — [flight-log](https://github.com/Niximacco/flight-log),
[niximacco-recipes](https://github.com/Niximacco/niximacco-recipes) and
[wild-games](https://github.com/Niximacco/wild-games) — had grown byte-identical copies of the same
login: the same token generation, the same Resend client, the same send caps, the same confirm page.
Three Resend keys, three verified-sender setups, three places to fix a bug in the same email. That
code moved to the service. This is what is left on the site's side of the line.

**What the service does:** generating and mailing the link, hosting the confirm page, spending the
token, and the rate limits that stop one guessed address from costing a fortune at Resend.

**What a site keeps:** its user list, its sessions, and every decision about what an account may do.
Those stay with the site, because that is where the answers live and where they change. The service
can tell a site "the person holding this code proved they can read someone@example.com". It has no
opinion about whether that person may sign in, and it does not hold a list that could form one.

## How a login works

```
   person              flights.ajn.me                auth.ajn.me
     │                       │                            │
  1  │ POST /login           │                            │
     ├──────────────────────>│ is this one of my users?   │
     │                       │ (its own datastore)        │
  2  │                       ├───────────────────────────>│  POST /v1/links
     │                       │                            │  + api key
     │                       │                            │
     │                       │      sent | throttled      │  mints a token,
  3  │ "check your email"    │<───────────────────────────┤  mails the link
     │<──────────────────────┤                            │
     │                       │                            │
  4  │ clicks the link ─────────────────────────────────> │  GET /callback?token=…
     │                       │                            │
  5  │ "sign in to Flight Log?" ──── POST ──────────────> │  spends the token,
     │                       │                            │  mints a code
  6  │ 303 to /auth/callback?code=…                       │
     │<─────────────────────────────────────────────────  ┤
     │                       │                            │
  7  │ GET /auth/callback    │                            │
     ├──────────────────────>│                            │
  8  │                       ├───────────────────────────>│  POST /v1/exchange
     │                       │                            │  + api key
     │                       │  {"email": …, "next": …}   │
     │                       │<───────────────────────────┤
     │                       │                            │
     │                       │ still one of my users?     │
     │                       │ issue my own session cookie│
  9  │ 303 to where they were going                       │
     │<──────────────────────┤                            │
```

Steps 2 and 8 are the two calls this package makes. Everything else is the site's own code, or the
service's.

Five things about that shape are deliberate.

**The site checks its user list twice** — once before asking for a link, once after redeeming the
code. The second is not paranoia: a link can sit in an inbox for fifteen minutes, and an account can
be removed in fourteen of them.

**An address that is not a user gets no call at all.** The site renders "check your email" and stops.
Nothing is sent, and the form cannot be used to find out who has an account.

**The emailed link is a GET that changes nothing.** Mail scanners and link previewers fetch urls out
of email; a GET that signed you in would let them burn the token before the real person clicked it.
Step 5 is a form, and the POST is what spends the token.

**The token and the code are different secrets with different lifetimes.** The token travelled
through a mail server and sat in an inbox, so it is good for fifteen minutes and dies the moment it
is used. The code travels over one redirect and is traded in immediately, so it is good for two.

**The address comes back in a response body, never in the redirect.** A query string is not a private
channel — it lands in access logs, in browser history, and in the `Referer` of anything the landing
page loads. What travels the front channel is a code that is worthless in all three places a moment
later, and worthless to anybody without the site's api key at any time.

## Adding it to a site

Register the site in the service's admin pages, generate it a key, and put two values in its
environment:

```bash
AJN_AUTH_URL=https://auth.ajn.me
AJN_AUTH_API_KEY=ajnauth_…
```

`AJN_AUTH_REDIRECT_URI` is only needed by a site with more than one registered callback.

Then construct a client from them:

```go
import "github.com/Niximacco/ajn_auth/pkg/authclient"

var login = authclient.New()
```

It has no dependencies beyond the standard library, on purpose: it is imported by every site, and a
login should not be able to break because something three levels down changed.

### Asking for a link

```go
func RequestMagicLink(c *gin.Context) {
	next := web.SafeNext(c.PostForm("next"))
	address := strings.TrimSpace(c.PostForm("email"))

	page := web.New("Sign in")
	page.Next = next
	page.Email = address

	// The user list is ours. An address that is not on it gets the same page as
	// one that is, and no call is made.
	if _, err := data.GetUser(address); err == nil {
		switch _, err := login.RequestLink(c, address, next); {
		case err == nil:
			// Sent or throttled - both look like success, deliberately.

		case errors.Is(err, authclient.ErrInvalidEmail):
			page.Error = "That doesn't look like an email address."
			web.Render(c, http.StatusBadRequest, web.LoginPage, page)
			return

		default:
			log.Printf("could not send a magic link: %s", err.Error())
			page.Title = "Sign in unavailable"
			page.Error = "We couldn't send your sign in link. Please try again."
			web.Render(c, http.StatusServiceUnavailable, web.MessagePage, page)
			return
		}
	}

	page.Title = "Check your email"
	web.Render(c, http.StatusOK, web.SentPage, page)
}
```

`RequestLink` returns `Sent` or `Throttled` and no error for either. **Render them identically.**
Showing anything different turns the login form into a way of checking which addresses are real,
which is the one thing the send caps must not cost.

### Completing one

```go
func CompleteLogin(c *gin.Context) {
	identity, err := login.Redeem(c, c.Query("code"))
	if err != nil {
		page := web.New("That link didn't work")
		page.Error = "This sign in link has already been used or has expired. Request a new one."
		web.Render(c, http.StatusUnauthorized, web.MessagePage, page)
		return
	}

	// Check again. The link may have been sitting in an inbox while the account
	// was removed.
	if _, err := data.GetUser(identity.Email); err != nil {
		page := web.New("That account can no longer sign in")
		web.Render(c, http.StatusUnauthorized, web.MessagePage, page)
		return
	}

	// Our session, our cookie, our signing key. The service never sees one.
	if err := auth.StartSession(c, identity.Email); err != nil {
		// …
	}

	c.Redirect(http.StatusSeeOther, web.SafeNext(identity.Next))
}
```

Route it at whatever the site registered as its redirect uri, on `GET`.

### What a site keeps

Its `JWT_SIGNING_KEY`, its session cookie, its user kind, its roles. Those are per-site values that
never need coordinating with anything, and keeping them local is what makes the service safe to
deploy: it is not in the path of a request that already has a session, so a bad deploy there cannot
sign anybody out. It only stops new logins until it is fixed.

What a site can delete: its `magiclink` package, its `email` package, its `RESEND_API_KEY` and
`MAIL_FROM`, and the confirm page and its template.

`LastLinkSent` and `RecentLinkSents` on the user entity become dead properties — the send counters
live in the service now, keyed per site and per address. They can be left where they are; nothing
reads them and datastore does not charge for a property nobody indexes.

## The errors

| Error | What it means |
|---|---|
| `ErrNotConfigured` | No url or no api key. This site's configuration, not the visitor's fault. |
| `ErrUnauthorized` | The api key was refused. Also this site's configuration. |
| `ErrInvalidEmail` | The address is not a usable address. Worth showing on the form. |
| `ErrBadCode` | Unknown, already redeemed, expired, or another site's. Offer a new link. |
| `ErrUnavailable` | The service could not be reached, or cannot send right now. Temporary. |

## The tests

```bash
go test ./...
```

They run the client against a stubbed service — what it sends, what it makes of each reply, and which
error comes back from each failure. No credentials and no network.
