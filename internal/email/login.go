package email

import (
	"bytes"
	"html/template"
	"log"
	"strings"
	texttemplate "text/template"

	"github.com/Niximacco/ajn_auth/internal/sites"
)

// One template, filled in per site.
//
// The alternative was letting each site register its own html, and it is worth
// saying why that was not done: a login email is the one message a site sends
// that has to work in every mail client, render the same on a phone as on a
// laptop, and never look like a phishing attempt. That is a thing you get right
// once. A site that wants to sound like itself gets its name, its colour, its
// subject line and its opening sentence, which is every part a reader actually
// reads - and the table layout, the inline styles and the plain text
// alternative stay in one place where fixing them fixes them everywhere.
//
// Both bodies are built with the template packages rather than by concatenating
// strings, so a site name with an ampersand in it, or a next path with a quote,
// is escaped for the context it lands in instead of breaking the markup.
var (
	htmlTemplate = template.Must(template.New("login.html").Parse(loginHTML))
	textTemplate = texttemplate.Must(texttemplate.New("login.txt").Parse(loginText))
)

// LoginEmail is everything the two bodies are written from.
type LoginEmail struct {
	SiteName string
	Intro    string
	// URL is the link that signs the person in. It points at this service, not
	// at the site: the confirm step and the token live here.
	URL string
	// Accent is the button colour.
	Accent string
	// ExpiresMinutes is how long the link is good for, in words the reader can
	// act on.
	ExpiresMinutes int
}

// Login builds the login message for a site.
func Login(site sites.Site, loginURL string, expiresMinutes int) (Message, error) {
	content := LoginEmail{
		SiteName:       site.Name,
		Intro:          site.EmailIntro(),
		URL:            loginURL,
		Accent:         site.AccentColour(),
		ExpiresMinutes: expiresMinutes,
	}

	var html bytes.Buffer
	if err := htmlTemplate.Execute(&html, content); err != nil {
		return Message{}, err
	}

	var text bytes.Buffer
	if err := textTemplate.Execute(&text, content); err != nil {
		return Message{}, err
	}

	return Message{
		From:    site.MailFrom,
		Subject: site.EmailSubject(),
		HTML:    html.String(),
		Text:    text.String(),
	}, nil
}

// SendLogin builds and sends the login message for a site.
func SendLogin(site sites.Site, address string, loginURL string, expiresMinutes int) error {
	message, err := Login(site, loginURL, expiresMinutes)
	if err != nil {
		log.Printf("could not build the login email for %s: %s", site.ID, err.Error())
		return err
	}

	message.To = strings.TrimSpace(address)

	return Send(message)
}

// The html body. Tables and inline styles, because that is what mail clients
// render predictably; the accent colour is the one thing a site changes.
const loginHTML = `<!doctype html>
<html>
  <body style="margin:0;padding:32px;background:#f5f5f7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#1d1d1f;">
    <table role="presentation" cellpadding="0" cellspacing="0" style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;">
      <tr><td>
        <h1 style="margin:0 0 8px;font-size:20px;">Sign in to {{.SiteName}}</h1>
        <p style="margin:0 0 24px;font-size:15px;line-height:1.5;color:#4a4a4f;">{{.Intro}}</p>
        <p style="margin:0 0 24px;">
          <a href="{{.URL}}" style="display:inline-block;background:{{.Accent}};color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:8px;font-size:15px;font-weight:600;">Sign in</a>
        </p>
        <p style="margin:0 0 24px;font-size:13px;line-height:1.5;color:#6e6e73;">Or paste this into your browser:<br><span style="word-break:break-all;">{{.URL}}</span></p>
        <p style="margin:0;font-size:13px;line-height:1.5;color:#6e6e73;">The link works once and expires in {{.ExpiresMinutes}} minutes. If you didn't ask to sign in, you can ignore this email.</p>
      </td></tr>
    </table>
  </body>
</html>`

const loginText = `Sign in to {{.SiteName}}

Open this link to sign in:

{{.URL}}

The link works once and expires in {{.ExpiresMinutes}} minutes. If you didn't ask to sign in, you can ignore this email.
`
