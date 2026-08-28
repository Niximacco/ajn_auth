# ajn_auth

Magic link sign in, once, for every site that needs it.

Three sites — [flight-log](https://github.com/Niximacco/flight-log),
[niximacco-recipes](https://github.com/Niximacco/niximacco-recipes) and
[wild-games](https://github.com/Niximacco/wild-games) — had grown byte-identical copies of the same
login: the same token generation, the same Resend client, the same send caps, the same confirm page.
Three Resend keys, three verified-sender setups, three places to fix a bug in the same email. This is
that code, extracted, with an api in front of it.

**What moved here:** generating and mailing the link, hosting the confirm page, spending the token,
and the rate limits that stop one guessed address from costing a fortune at Resend.

**What did not:** the user lists, the sessions, and every decision about what an account may do.
Those stayed with the sites, because that is where the answers live and where they change. This
service can tell a site "the person holding this code proved they can read someone@example.com". It
has no opinion about whether that person may sign in, and it does not hold a list that could form
one.

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

Register the site in the admin pages, generate it a key, and put three values in its environment:

```bash
AJN_AUTH_URL=https://auth.ajn.me
AJN_AUTH_API_KEY=ajnauth_…
```

`AJN_AUTH_REDIRECT_URI` is only needed by a site with more than one registered callback.

Then import the client:

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

	// Our session, our cookie, our signing key. This service never sees one.
	if err := auth.StartSession(c, identity.Email); err != nil {
		// …
	}

	c.Redirect(http.StatusSeeOther, web.SafeNext(identity.Next))
}
```

Route it at whatever the site registered as its redirect uri, on `GET`.

### What a site keeps

Its `JWT_SIGNING_KEY`, its session cookie, its user kind, its roles. Those are per-site values that
never need coordinating with anything, and keeping them local is what makes this service safe to
deploy: it is not in the path of a request that already has a session, so a bad deploy here cannot
sign anybody out. It only stops new logins until it is fixed.

What a site can delete: its `magiclink` package, its `email` package, its `RESEND_API_KEY` and
`MAIL_FROM`, and the confirm page and its template.

`LastLinkSent` and `RecentLinkSents` on the user entity become dead properties — the send counters
live here now, keyed per site and per address. They can be left where they are; nothing reads them
and datastore does not charge for a property nobody indexes.

## The roster

Which sites exist, what their emails look like and which keys speak for them is one json document,
kept in Secret Manager and edited through the admin pages at `/admin`. See
[sites.example.json](sites.example.json) for the shape.

Keeping it in Secret Manager rather than an environment variable is what lets it change without a
deploy, and every save adds a version — so an edit that breaks a site is rolled back by pinning the
previous one rather than by remembering what it used to say.

**Api keys are stored hashed.** The plaintext is shown once, on the page that generated it, and is
not recoverable. That is what keeps a leaked copy of the roster from being a set of working
credentials, and it is why the admin pages offer "generate a new key" rather than "show me the key".
Rotating one means generating a second, deploying it, and revoking the first.

Each instance caches the roster for a minute. A revoked key therefore keeps working on other
instances for up to that long — if a key is known to be in the wrong hands, disable the site too,
which is checked against the same cached copy but leaves nothing usable behind when it takes.

### Who can edit it

The addresses in `admins`, signing in at `/admin/login`. That login goes through this service's own
`Request`, its own confirm page and its own `Consume` — the exact path flight-log uses. A login that
only breaks for other people is a login nobody notices is broken.

`Validate` refuses a roster with no admins, because one is not recoverable through this service:
it would have to be fixed with `gcloud`.

## Configuration

| Variable | What it is |
|---|---|
| `DATASTORE_PROJECT_ID` | The GCP project. Required. |
| `DATASTORE_NAMESPACE` | The datastore namespace, and the audience on admin session tokens. Required. |
| `SITES_SECRET` | The roster secret, `projects/<project>/secrets/<name>`, with no version on the end. Required. |
| `JWT_SIGNING_KEY` | Signs admin sessions for this service's own pages. Required. Unrelated to any site's. |
| `RESEND_API_KEY` | The one Resend key, for every site. Without it no site can send. |
| `MAIL_FROM` | The from address for the admin login, and the fallback for a site that registered none. |
| `APP_BASE_URL` | This service's public origin. Magic links are built from it, so it has to match what the browser sees. |
| `SERVICE_NAME` | What this service's own pages call it. Defaults to "ajn auth". |
| `FONTAWESOME_KIT` | Optional. The pages are labelled in words and read fine without it. |
| `COOKIE_SECURE` | Set to `false` only for plain http local development. |
| `TRUSTED_PROXY_DEPTH` | How many `X-Forwarded-For` entries came from infrastructure. `0` behind a Cloud Run domain mapping. |

`RESEND_API_KEY` and `JWT_SIGNING_KEY` belong in Secret Manager and should be mounted as secret
environment variables, not typed into the service's config.

## Deploying

The workflow in `.github/workflows` builds a container, pushes it to Artifact Registry and deploys to
Cloud Run on a push to `main`. Setting it up is the same handful of steps as the other services —
they are written out in the header of that file — with these differences:

1. Enable **Secret Manager** (`secretmanager.googleapis.com`) alongside Cloud Run, Artifact Registry
   and Datastore.

2. Create the roster secret and seed it, before the first deploy — the service reads it at start and
   will not come up without it:

```bash
gcloud secrets create ajn-auth-sites --project=ajnhosting-163818 --replication-policy=automatic
```

```bash
gcloud secrets versions add ajn-auth-sites --project=ajnhosting-163818 --data-file=sites.example.json
```

3. The runtime service account needs `roles/datastore.user`, plus **both**
   `roles/secretmanager.secretAccessor` and `roles/secretmanager.secretVersionAdder` on that secret.
   Read access alone leaves the admin pages unable to save anything, and the failure looks like a
   permissions error at save time rather than at start.

```bash
gcloud secrets add-iam-policy-binding ajn-auth-sites --project=ajnhosting-163818 --member="serviceAccount:<runtime-sa>" --role=roles/secretmanager.secretVersionAdder
```

4. Point `auth.ajn.me` at the service with a Cloud Run domain mapping and set `APP_BASE_URL` to
   match, or the links in every site's email will point somewhere else.

### Sweeping the expired entities

Spent magic links, spent codes and send records for addresses that stopped signing in are never
deleted by the service. Each carries a timestamp field for a datastore
[TTL policy](https://cloud.google.com/datastore/docs/ttl) to read — `Expires` on `magic_link` and
`exchange_code`, `Updated` on `send_record`. Set one on each; nothing depends on it, and every check
in the code is against the numeric field beside it, so a policy that is slow or missing makes the
kinds larger and changes no behaviour.

## Running it locally

Point it at a real project's datastore and a roster on disk is not supported — it reads the roster
from Secret Manager and nothing else, so local running means real credentials and a real secret:

```bash
gcloud auth application-default login
```

```bash
DATASTORE_PROJECT_ID=ajnhosting-163818 DATASTORE_NAMESPACE=ajn-auth-dev SITES_SECRET=projects/ajnhosting-163818/secrets/ajn-auth-sites JWT_SIGNING_KEY=dev COOKIE_SECURE=false APP_BASE_URL=http://localhost:8080 go run ./cmd/ajn-auth
```

Register the site being developed with an `http://localhost:…` redirect uri — that is the one place
plain http is allowed, and only for `localhost`, `127.0.0.1` and `::1`.

## The tests

```bash
go test ./...
```

They cover what is painful to debug in production: what a redirect uri is and is not allowed to be
(the near misses, not the hits), the send caps at their edges, that tokens and api keys are only ever
stored hashed, the whole route set registering on one gin tree, every template rendering, and the
client the sites import against a stubbed service.
