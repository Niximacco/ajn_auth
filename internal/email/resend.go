package email

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Niximacco/ajn_auth/internal/config"
)

const resendEndpoint = "https://api.resend.com/emails"

var (
	RESEND_API_KEY string

	client = &http.Client{Timeout: 10 * time.Second}
)

// ErrNotConfigured means the service has no Resend credentials, so nothing can
// be sent. Login is unavailable for every site until RESEND_API_KEY is set.
//
// One key, one account, one set of verified domains. Collapsing three of these
// into one is most of the reason this service exists.
var ErrNotConfigured = errors.New("email sending is not configured")

func init() {
	RESEND_API_KEY = os.Getenv("RESEND_API_KEY")

	if RESEND_API_KEY == "" {
		log.Print("WARNING: RESEND_API_KEY is unset, magic link login is disabled for every site")
	}
}

// Configured reports whether email can actually be sent.
func Configured() bool {
	return RESEND_API_KEY != ""
}

type Message struct {
	// From is the site's own From header. Empty falls back to MAIL_FROM.
	From    string
	To      string
	Subject string
	HTML    string
	Text    string
}

// from is the header this message actually goes out with.
func (m Message) from() string {
	if strings.TrimSpace(m.From) != "" {
		return m.From
	}

	return config.MAIL_FROM
}

type resendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
	Text    string   `json:"text"`
}

type resendResponse struct {
	Id      string `json:"id"`
	Message string `json:"message"`
	Name    string `json:"name"`
}

// Send delivers a single message through Resend. It blocks until Resend has
// accepted it: on Cloud Run the container's cpu is only guaranteed while a
// request is being handled, so this must not be moved to a goroutine.
func Send(message Message) error {
	if !Configured() {
		return ErrNotConfigured
	}

	from := message.from()
	if from == "" {
		return ErrNotConfigured
	}

	body, err := json.Marshal(resendRequest{
		From:    from,
		To:      []string{message.To},
		Subject: message.Subject,
		HTML:    message.HTML,
		Text:    message.Text,
	})
	if err != nil {
		return err
	}

	request, err := http.NewRequest(http.MethodPost, resendEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}

	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", RESEND_API_KEY))
	request.Header.Set("Content-Type", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	// Cap the read: we only ever want the error message out of this.
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return err
	}

	var parsed resendResponse
	// A body we can't parse is not fatal on its own, the status code decides.
	_ = json.Unmarshal(responseBody, &parsed)

	if response.StatusCode < 200 || response.StatusCode > 299 {
		if parsed.Message != "" {
			return fmt.Errorf("resend returned %d: %s", response.StatusCode, parsed.Message)
		}
		return fmt.Errorf("resend returned %d", response.StatusCode)
	}

	log.Printf("sent email %s", parsed.Id)
	return nil
}
