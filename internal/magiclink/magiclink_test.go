package magiclink

import (
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Niximacco/ajn_auth/internal/sites"
)

// The send caps are the thing standing between a guessed address and a Resend
// bill, so they are checked at their edges rather than in the middle.
func TestOverSendLimit(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

	ago := func(d time.Duration) int64 { return now.Add(-d).Unix() }

	repeat := func(count int, d time.Duration) []int64 {
		sends := make([]int64, 0, count)
		for i := 0; i < count; i++ {
			// Spread them out a little so they are distinct moments rather than
			// one timestamp repeated.
			sends = append(sends, ago(d+time.Duration(i)*time.Second))
		}
		return sends
	}

	cases := []struct {
		name  string
		sends []int64
		over  bool
	}{
		{"nothing sent", nil, false},
		{"one just now", []int64{ago(time.Second)}, false},
		{"one under the hourly cap", repeat(SEND_LIMIT_HOUR-1, time.Minute), false},
		{"exactly the hourly cap", repeat(SEND_LIMIT_HOUR, time.Minute), true},
		{"the hourly cap, but all of it over an hour ago", repeat(SEND_LIMIT_HOUR, 2*time.Hour), false},
		{"one under the daily cap, spread over the day", spread(now, SEND_LIMIT_DAY-1), false},
		{"exactly the daily cap, spread over the day", spread(now, SEND_LIMIT_DAY), true},
		{"the daily cap, but all of it over a day ago", repeat(SEND_LIMIT_DAY, 25*time.Hour), false},

		// A timestamp in the future is clock skew or a hand-edited entity. It
		// must count against the tighter window rather than be ignored, or it
		// would be a way to unlock more sends.
		{"the hourly cap, with the sends stamped in the future",
			[]int64{now.Add(time.Hour).Unix(), now.Add(2 * time.Hour).Unix(),
				now.Add(3 * time.Hour).Unix(), now.Add(4 * time.Hour).Unix(),
				now.Add(5 * time.Hour).Unix()}, true},
	}

	for _, test := range cases {
		if got := OverSendLimit(test.sends, now); got != test.over {
			t.Errorf("%s: OverSendLimit gave %v, want %v", test.name, got, test.over)
		}
	}
}

// spread returns count sends laid out across the day, far enough apart that no
// more than a few land inside any one hour.
func spread(now time.Time, count int) []int64 {
	sends := make([]int64, 0, count)
	for i := 0; i < count; i++ {
		sends = append(sends, now.Add(-time.Duration(i+1)*90*time.Minute).Unix())
	}

	return sends
}

// A site's "next" comes in over the api and goes back out attached to a
// redirect, so anything that could resolve to another origin is refused
// outright rather than quietly rewritten.
func TestSafeNext(t *testing.T) {
	allowed := []string{"", "/", "/flights", "/flights?year=2026", "/a/b/c", "/flights#top"}
	for _, next := range allowed {
		got, err := SafeNext(next)
		if err != nil {
			t.Errorf("next %q was refused: %s", next, err.Error())
			continue
		}
		if got != next {
			t.Errorf("next %q came back as %q", next, got)
		}
	}

	refused := []string{
		"//evil.example",
		"/\\evil.example",
		"https://evil.example",
		"http://evil.example",
		"evil.example",
		"flights",
		"javascript:alert(1)",
		"/flights\r\nSet-Cookie: a=b",
		"/flights\nX: y",
	}

	for _, next := range refused {
		if _, err := SafeNext(next); !errors.Is(err, ErrBadNext) {
			t.Errorf("next %q gave %v, want ErrBadNext", next, err)
		}
	}
}

// Deliver builds the redirect that carries the exchange code back to the site.
func TestDeliver(t *testing.T) {
	consumed := Consumed{
		RedirectURI: "https://flights.example.com/auth/callback",
		Code:        "a-code+with/characters",
	}

	target, err := consumed.Deliver()
	if err != nil {
		t.Fatalf("could not build the redirect: %s", err.Error())
	}

	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatalf("the redirect is not a url: %s", err.Error())
	}

	if parsed.Host != "flights.example.com" || parsed.Path != "/auth/callback" {
		t.Errorf("the redirect went to %q", target)
	}

	// The code has to survive being put in a query string exactly as it was
	// minted, or the site trades in something that will never match.
	if got := parsed.Query().Get("code"); got != consumed.Code {
		t.Errorf("the code came back as %q, want %q", got, consumed.Code)
	}

	// A callback registered with a query of its own keeps it.
	consumed.RedirectURI = "https://flights.example.com/auth/callback?source=email"
	target, err = consumed.Deliver()
	if err != nil {
		t.Fatalf("could not build the redirect: %s", err.Error())
	}

	parsed, _ = url.Parse(target)
	if parsed.Query().Get("source") != "email" {
		t.Errorf("the registered query was dropped: %q", target)
	}
	if parsed.Query().Get("code") != consumed.Code {
		t.Errorf("the code was dropped: %q", target)
	}
}

// The link in the email must point at this service, carry the token, and carry
// nothing else. In particular it must not carry the address or the site id:
// everything needed to finish is behind the token.
func TestBuildURL(t *testing.T) {
	link := buildURL("a-token")

	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("the login url is not a url: %s", err.Error())
	}

	if parsed.Path != "/callback" {
		t.Errorf("the login url points at %q", parsed.Path)
	}

	if got := parsed.Query().Get("token"); got != "a-token" {
		t.Errorf("the token came out as %q", got)
	}

	if len(parsed.Query()) != 1 {
		t.Errorf("the login url carries more than the token: %q", parsed.RawQuery)
	}
}

// A token and the hash stored for it must never be the same value, or a read of
// the magic_link kind would be a set of working links.
func TestSecretsAreStoredHashedOnly(t *testing.T) {
	secret, hash, err := newSecret()
	if err != nil {
		t.Fatalf("could not generate a secret: %s", err.Error())
	}

	if secret == hash || strings.Contains(hash, secret) {
		t.Fatal("the stored hash is the secret")
	}

	if hash != hashSecret(secret) {
		t.Error("the hash is not the hash of the secret")
	}

	// It goes in a url, so it has to survive being one.
	if url.QueryEscape(secret) != secret {
		t.Errorf("the token needs escaping in a url: %q", secret)
	}

	other, _, err := newSecret()
	if err != nil {
		t.Fatalf("could not generate a secret: %s", err.Error())
	}
	if other == secret {
		t.Error("two generated secrets came out the same")
	}
}

// Request must refuse an address that is obviously not one before it touches
// datastore or mails anything.
func TestRequestRefusesJunkBeforeDoingAnyWork(t *testing.T) {
	site := sites.Site{ID: "flight-log", Name: "Flight Log"}

	// data.Initialize has not been called, so anything that reached datastore
	// would panic. That is the assertion: these return before they get there.
	for _, address := range []string{"", "not-an-address", "someone@example"} {
		if err := Request(site, address, "https://flights.example.com/auth/callback", ""); !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("address %q gave %v, want ErrInvalidEmail", address, err)
		}
	}

	if err := Request(site, "someone@example.com", "https://flights.example.com/auth/callback", "//evil.example"); !errors.Is(err, ErrBadNext) {
		t.Errorf("a bad next gave %v, want ErrBadNext", err)
	}
}
