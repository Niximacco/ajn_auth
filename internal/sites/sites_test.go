package sites

import (
	"errors"
	"strings"
	"testing"
)

// roster is a small but realistic configuration to check things against.
func roster(t *testing.T) (Config, string, string) {
	t.Helper()

	flightKey, flightRecord, err := NewKey("cloud run")
	if err != nil {
		t.Fatalf("could not generate a key: %s", err.Error())
	}

	gamesKey, gamesRecord, err := NewKey("cloud run")
	if err != nil {
		t.Fatalf("could not generate a key: %s", err.Error())
	}

	return Config{
		Admins: []string{"admin@example.com"},
		Sites: []Site{
			{
				ID:           "flight-log",
				Name:         "Flight Log",
				BaseURL:      "https://flights.example.com",
				RedirectURIs: []string{"https://flights.example.com/auth/callback"},
				MailFrom:     "Flight Log <login@example.com>",
				Keys:         []Key{flightRecord},
			},
			{
				ID:           "wild-games",
				Name:         "Wild Games",
				BaseURL:      "https://games.example.com",
				RedirectURIs: []string{"https://games.example.com/auth/callback"},
				MailFrom:     "Wild Games <login@example.com>",
				Keys:         []Key{gamesRecord},
				Disabled:     true,
			},
		},
	}, flightKey, gamesKey
}

func TestAuthenticate(t *testing.T) {
	config, flightKey, gamesKey := roster(t)

	site, err := config.Authenticate(flightKey)
	if err != nil {
		t.Fatalf("a valid key was refused: %s", err.Error())
	}
	if site.ID != "flight-log" {
		t.Errorf("a key resolved to %q, want flight-log", site.ID)
	}

	// A disabled site's key is recognised and then refused. The two have to be
	// distinguishable here, because the caller logs one and not the other.
	if _, err = config.Authenticate(gamesKey); !errors.Is(err, ErrSiteDisabled) {
		t.Errorf("a disabled site's key gave %v, want ErrSiteDisabled", err)
	}

	// A key with a character added, one taken off, and one changed. All three
	// are what a truncated copy-paste or a stale value looks like.
	wrongKeys := []string{
		"", "  ", "ajnauth_nonsense",
		flightKey + "x",
		flightKey[:len(flightKey)-1],
		flightKey[:len(flightKey)-1] + "~",
	}

	for _, wrong := range wrongKeys {
		if _, err := config.Authenticate(wrong); !errors.Is(err, ErrBadKey) {
			t.Errorf("key %q gave %v, want ErrBadKey", wrong, err)
		}
	}
}

// A key must never be stored in the clear, because the whole roster is one
// document that gets read, copied and pasted.
func TestKeysAreStoredHashedOnly(t *testing.T) {
	plaintext, record, err := NewKey("note")
	if err != nil {
		t.Fatalf("could not generate a key: %s", err.Error())
	}

	if record.Hash == plaintext {
		t.Fatal("the stored hash is the key itself")
	}

	if strings.Contains(record.Hash, strings.TrimPrefix(plaintext, KeyPrefix)) {
		t.Fatal("the stored hash contains the key")
	}

	if record.Hash != HashKey(plaintext) {
		t.Error("the stored hash is not the hash of the key")
	}

	// The id is the head of the key, which is how a key in a site's config is
	// matched to a row in the admin pages.
	if !strings.HasPrefix(plaintext, record.ID) {
		t.Errorf("the key id %q is not the head of the key", record.ID)
	}

	other, _, err := NewKey("note")
	if err != nil {
		t.Fatalf("could not generate a key: %s", err.Error())
	}
	if other == plaintext {
		t.Error("two generated keys came out the same")
	}
}

// The redirect check is what keeps a leaked api key from mailing somebody a
// link that lands on another server, so the near misses matter more than the
// hits.
func TestCheckRedirect(t *testing.T) {
	site := Site{
		RedirectURIs: []string{
			"https://flights.example.com/auth/callback",
			"http://localhost:8080/auth/callback",
		},
	}

	for _, allowed := range site.RedirectURIs {
		if got, err := site.CheckRedirect(allowed); err != nil || got != allowed {
			t.Errorf("registered uri %q gave (%q, %v)", allowed, got, err)
		}
	}

	// Nothing asked for means the first registered one, so a site with a single
	// callback need not repeat it in its own configuration.
	if got, err := site.CheckRedirect(""); err != nil || got != site.RedirectURIs[0] {
		t.Errorf("an empty redirect gave (%q, %v), want the first registered uri", got, err)
	}

	refused := []string{
		// The classic prefix-match escapes.
		"https://flights.example.com/auth/callback/../../evil",
		"https://flights.example.com@evil.example/auth/callback",
		"https://flights.example.com.evil.example/auth/callback",
		"https://evil.example/auth/callback",
		// Same host, different path: a site's callback is one url, not a space.
		"https://flights.example.com/auth/callback2",
		"https://flights.example.com/",
		// Same url with something appended, which an exact compare must reject.
		"https://flights.example.com/auth/callback?next=/evil",
		// Scheme downgrade on a host that is not local.
		"http://flights.example.com/auth/callback",
	}

	for _, uri := range refused {
		if _, err := site.CheckRedirect(uri); !errors.Is(err, ErrBadRedirect) {
			t.Errorf("redirect %q was allowed, want ErrBadRedirect", uri)
		}
	}

	// A site with nothing registered can be sent nowhere at all.
	empty := Site{}
	if _, err := empty.CheckRedirect(""); !errors.Is(err, ErrBadRedirect) {
		t.Errorf("a site with no redirect uris gave %v, want ErrBadRedirect", err)
	}
}

func TestValidate(t *testing.T) {
	good, _, _ := roster(t)
	if err := good.Validate(); err != nil {
		t.Fatalf("a good roster was refused: %s", err.Error())
	}

	valid := good.Sites[0]

	broken := map[string]Config{
		"no admins": {Sites: []Site{valid}},
		"an admin that is not an address": {
			Admins: []string{"not-an-address"}, Sites: []Site{valid},
		},
		"a site with no name": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{withName(valid, "")},
		},
		"a site with an http base url": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{withBase(valid, "http://flights.example.com")},
		},
		"a site with a relative base url": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{withBase(valid, "/flights")},
		},
		"a site with no redirect uris": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{withRedirects(valid, nil)},
		},
		"a site with a javascript redirect": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{withRedirects(valid, []string{"javascript:alert(1)"})},
		},
		"a from address with a header injection in it": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{withFrom(valid, "Flight Log <login@example.com>\r\nBcc: everyone@example.com")},
		},
		"two sites with one id": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{valid, valid},
		},
		"a site squatting this service's own id": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{withID(valid, SelfID)},
		},
		"a site id with an upper case letter": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{withID(valid, "Flight-Log")},
		},
		"a site id with a pipe in it, which is the send record key separator": {
			Admins: []string{"admin@example.com"},
			Sites:  []Site{withID(valid, "flight|log")},
		},
	}

	for name, config := range broken {
		if err := config.Validate(); err == nil {
			t.Errorf("a roster with %s was accepted", name)
		}
	}
}

func withID(site Site, id string) Site         { site.ID = id; return site }
func withName(site Site, name string) Site     { site.Name = name; return site }
func withBase(site Site, base string) Site     { site.BaseURL = base; return site }
func withFrom(site Site, from string) Site     { site.MailFrom = from; return site }
func withRedirects(site Site, u []string) Site { site.RedirectURIs = u; return site }

// A localhost callback over plain http is what makes a site runnable on a
// laptop against the deployed service, and it is the one exception.
func TestLocalhostMayBeHTTP(t *testing.T) {
	site := Site{
		ID:           "flight-log",
		Name:         "Flight Log",
		BaseURL:      "http://localhost:8080",
		RedirectURIs: []string{"http://localhost:8080/auth/callback", "http://127.0.0.1:8080/auth/callback"},
		MailFrom:     "Flight Log <login@example.com>",
	}

	if err := site.Validate(); err != nil {
		t.Errorf("a localhost site was refused: %s", err.Error())
	}
}

func TestAccentColour(t *testing.T) {
	// A colour that would break out of the style attribute it lands in is
	// dropped rather than interpolated.
	for _, bad := range []string{"", "red", "#12345", "#1d1d1f;background:url(x)", "</style><script>"} {
		if got := (Site{Accent: bad}).AccentColour(); got != "#1d1d1f" {
			t.Errorf("accent %q gave %q, want the default", bad, got)
		}
	}

	if got := (Site{Accent: "#AABBCC"}).AccentColour(); got != "#AABBCC" {
		t.Errorf("a good accent gave %q", got)
	}
}

func TestIsAdmin(t *testing.T) {
	config := Config{Admins: []string{"Admin@Example.com ", "other@example.com"}}

	for _, address := range []string{"admin@example.com", "ADMIN@EXAMPLE.COM", " admin@example.com "} {
		if !config.IsAdmin(address) {
			t.Errorf("%q was not recognised as an admin", address)
		}
	}

	for _, address := range []string{"", "  ", "nobody@example.com", "admin@example.com.evil.example"} {
		if config.IsAdmin(address) {
			t.Errorf("%q was treated as an admin", address)
		}
	}
}

func TestLookupFindsThisServiceItself(t *testing.T) {
	config, _, _ := roster(t)

	self, err := config.Lookup(SelfID)
	if err != nil {
		t.Fatalf("this service could not look itself up: %s", err.Error())
	}

	if len(self.RedirectURIs) != 1 {
		t.Fatalf("the built-in site has %d redirect uris, want 1", len(self.RedirectURIs))
	}

	// Find is the stored roster only, and must not see the built-in site: it is
	// what the admin pages edit through.
	if _, err := config.Find(SelfID); !errors.Is(err, ErrNoSuchSite) {
		t.Errorf("Find(%q) gave %v, want ErrNoSuchSite", SelfID, err)
	}
}

func TestParseRejectsTypos(t *testing.T) {
	// "redirect_uri" for "redirect_uris" would otherwise parse into a site with
	// no callback at all, and fail much later with a confusing message.
	body := []byte(`{
	  "admins": ["admin@example.com"],
	  "sites": [{
	    "id": "flight-log",
	    "name": "Flight Log",
	    "base_url": "https://flights.example.com",
	    "redirect_uri": "https://flights.example.com/auth/callback",
	    "mail_from": "Flight Log <login@example.com>"
	  }]
	}`)

	if _, err := Parse(body); err == nil {
		t.Error("a roster with a mis-spelled field was accepted")
	}

	if _, err := Parse([]byte("not json")); err == nil {
		t.Error("a roster that is not json was accepted")
	}
}

func TestValidAddress(t *testing.T) {
	good := []string{"a@b.co", "someone@example.com", "SOMEONE@EXAMPLE.COM", "first.last+tag@example.co.uk"}
	for _, address := range good {
		if !ValidAddress(address) {
			t.Errorf("%q was refused", address)
		}
	}

	bad := []string{
		"", "  ", "no-at-sign", "@example.com", "someone@", "someone@example",
		"someone@.com", "someone@example.", "someone@exa mple.com",
		"someone@example.com\r\nBcc: everyone@example.com",
		"<someone@example.com>",
		strings.Repeat("a", 250) + "@example.com",
	}
	for _, address := range bad {
		if ValidAddress(address) {
			t.Errorf("%q was accepted", address)
		}
	}
}
