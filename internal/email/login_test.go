package email

import (
	"strings"
	"testing"

	"github.com/Niximacco/ajn_auth/internal/sites"
)

func TestLoginUsesTheSitesOwnWords(t *testing.T) {
	site := sites.Site{
		ID:       "flight-log",
		Name:     "Flight Log",
		MailFrom: "Flight Log <login@example.com>",
		Accent:   "#1d1d1f",
		Intro:    "One tap and you're in.",
		Subject:  "Your Flight Log link",
	}

	message, err := Login(site, "https://auth.example.com/callback?token=abc", 15)
	if err != nil {
		t.Fatalf("could not build the message: %s", err.Error())
	}

	if message.From != site.MailFrom {
		t.Errorf("the message is from %q, want %q", message.From, site.MailFrom)
	}

	if message.Subject != "Your Flight Log link" {
		t.Errorf("the subject is %q", message.Subject)
	}

	for _, want := range []string{"Flight Log", "One tap and you&#39;re in.", "#1d1d1f", "15 minutes"} {
		if !strings.Contains(message.HTML, want) {
			t.Errorf("the html body is missing %q", want)
		}
	}

	// Both bodies have to carry the link, because a client that will not render
	// html is the whole reason the text one exists.
	for _, body := range []string{message.HTML, message.Text} {
		if !strings.Contains(body, "token=abc") {
			t.Error("a body is missing the login link")
		}
	}

	if strings.Contains(message.Text, "<") {
		t.Errorf("the text body has markup in it: %q", message.Text)
	}
}

func TestLoginFallsBackToTheDefaults(t *testing.T) {
	site := sites.Site{ID: "wild-games", Name: "Wild Games", MailFrom: "Wild Games <login@example.com>"}

	message, err := Login(site, "https://auth.example.com/callback?token=abc", 15)
	if err != nil {
		t.Fatalf("could not build the message: %s", err.Error())
	}

	if message.Subject != "Your sign in link for Wild Games" {
		t.Errorf("the default subject is %q", message.Subject)
	}

	if !strings.Contains(message.HTML, "Click the button below") {
		t.Error("the default intro is missing")
	}

	if !strings.Contains(message.HTML, "#1d1d1f") {
		t.Error("the default accent is missing")
	}
}

// A site name is configuration, but it is configuration a person types into a
// form. It must not be able to put markup into the email.
func TestSiteNameIsEscaped(t *testing.T) {
	site := sites.Site{
		ID:       "evil",
		Name:     `Flight Log</h1><script>alert(1)</script>`,
		MailFrom: "x <login@example.com>",
	}

	message, err := Login(site, "https://auth.example.com/callback?token=abc", 15)
	if err != nil {
		t.Fatalf("could not build the message: %s", err.Error())
	}

	if strings.Contains(message.HTML, "<script>") {
		t.Errorf("a site name put a script tag in the email:\n%s", message.HTML)
	}
}

// The url is written into an href and into the visible fallback line, and both
// have to survive it.
func TestLoginURLIsEscapedAndIntact(t *testing.T) {
	site := sites.Site{ID: "flight-log", Name: "Flight Log", MailFrom: "x <login@example.com>"}
	link := "https://auth.example.com/callback?token=a-b_c&x=1"

	message, err := Login(site, link, 15)
	if err != nil {
		t.Fatalf("could not build the message: %s", err.Error())
	}

	// html/template escapes the ampersand for the document, which is correct
	// and is what a mail client will read back as the original url.
	if !strings.Contains(message.HTML, "token=a-b_c&amp;x=1") {
		t.Errorf("the link was not written into the html body intact:\n%s", message.HTML)
	}

	// The text body is not a document, so it carries the url exactly.
	if !strings.Contains(message.Text, link) {
		t.Errorf("the link was not written into the text body intact:\n%s", message.Text)
	}
}

// Nothing can be sent without a Resend key, and a site with no from address of
// its own falls back to the service's.
func TestSendNeedsConfiguring(t *testing.T) {
	saved := RESEND_API_KEY
	defer func() { RESEND_API_KEY = saved }()

	RESEND_API_KEY = ""
	if err := Send(Message{From: "x <a@b.co>", To: "someone@example.com"}); err != ErrNotConfigured {
		t.Errorf("sending without a key gave %v, want ErrNotConfigured", err)
	}

	// With a key but no from address anywhere, there is still nothing to send
	// as. It must refuse rather than post a request Resend will reject.
	RESEND_API_KEY = "test"
	if err := Send(Message{To: "someone@example.com"}); err != ErrNotConfigured {
		t.Errorf("sending with no from address gave %v, want ErrNotConfigured", err)
	}
}
