package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serve stands in for the auth service, and records what the client sent it.
func serve(t *testing.T, status int, reply any) (*Client, *http.Request, *map[string]string) {
	t.Helper()

	var got *http.Request
	body := map[string]string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())

		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(server.Close)

	client := &Client{BaseURL: server.URL, APIKey: "ajnauth_testkey", HTTP: server.Client()}

	// got and body are filled in by the handler when a call is made, so the
	// caller reads them after calling rather than now.
	return client, got, &body
}

func TestRequestLink(t *testing.T) {
	client, _, body := serve(t, http.StatusOK, map[string]string{"status": "sent"})

	status, err := client.RequestLink(context.Background(), "someone@example.com", "/flights")
	if err != nil {
		t.Fatalf("requesting a link failed: %s", err.Error())
	}

	if status != Sent {
		t.Errorf("status was %q, want sent", status)
	}

	if (*body)["email"] != "someone@example.com" || (*body)["next"] != "/flights" {
		t.Errorf("the request body was %v", *body)
	}
}

// Throttled has to come back as its own value rather than an error, because the
// site renders it exactly like Sent. If it arrived as an error a site would
// naturally show something different, and the login form would become a way of
// checking which addresses are real.
func TestThrottledIsNotAnError(t *testing.T) {
	client, _, _ := serve(t, http.StatusOK, map[string]string{"status": "throttled"})

	status, err := client.RequestLink(context.Background(), "someone@example.com", "")
	if err != nil {
		t.Fatalf("a throttled reply came back as an error: %s", err.Error())
	}

	if status != Throttled {
		t.Errorf("status was %q, want throttled", status)
	}
}

func TestRequestLinkErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		reply  map[string]string
		want   error
	}{
		{"a bad address", http.StatusBadRequest,
			map[string]string{"error": "that doesn't look like an email address"}, ErrInvalidEmail},
		{"a refused key", http.StatusUnauthorized,
			map[string]string{"error": "unauthorized"}, ErrUnauthorized},
		{"email not configured", http.StatusServiceUnavailable,
			map[string]string{"error": "email sending is not configured"}, ErrUnavailable},
		{"rate limited", http.StatusTooManyRequests,
			map[string]string{"error": "too many requests"}, ErrUnavailable},
		{"an unregistered redirect uri", http.StatusBadRequest,
			map[string]string{"error": "that redirect uri is not registered for this site"}, ErrNotConfigured},
	}

	for _, test := range cases {
		client, _, _ := serve(t, test.status, test.reply)

		if _, err := client.RequestLink(context.Background(), "someone@example.com", ""); !errors.Is(err, test.want) {
			t.Errorf("%s: gave %v, want %v", test.name, err, test.want)
		}
	}
}

func TestRedeem(t *testing.T) {
	client, _, body := serve(t, http.StatusOK,
		map[string]string{"email": "someone@example.com", "next": "/flights"})

	identity, err := client.Redeem(context.Background(), "a-code")
	if err != nil {
		t.Fatalf("redeeming failed: %s", err.Error())
	}

	if identity.Email != "someone@example.com" || identity.Next != "/flights" {
		t.Errorf("the identity was %+v", identity)
	}

	if (*body)["code"] != "a-code" {
		t.Errorf("the request body was %v", *body)
	}
}

// A spent code and a refused api key both answer 401, and they mean completely
// different things: one is an ordinary visitor clicking a link twice, the other
// is this site being misconfigured.
func TestRedeemTellsASpentCodeFromABadKey(t *testing.T) {
	client, _, _ := serve(t, http.StatusUnauthorized,
		map[string]string{"error": "this login could not be completed"})

	if _, err := client.Redeem(context.Background(), "a-code"); !errors.Is(err, ErrBadCode) {
		t.Errorf("a spent code gave %v, want ErrBadCode", err)
	}

	client, _, _ = serve(t, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})

	if _, err := client.Redeem(context.Background(), "a-code"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("a refused key gave %v, want ErrUnauthorized", err)
	}
}

// A 200 with no address in it must not be read as a successful login.
func TestRedeemRefusesAnEmptyIdentity(t *testing.T) {
	client, _, _ := serve(t, http.StatusOK, map[string]string{})

	if _, err := client.Redeem(context.Background(), "a-code"); !errors.Is(err, ErrBadCode) {
		t.Errorf("an empty identity gave %v, want ErrBadCode", err)
	}
}

func TestTheKeyIsSentAsABearerToken(t *testing.T) {
	var header string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"sent"}`))
	}))
	defer server.Close()

	client := &Client{BaseURL: server.URL, APIKey: "ajnauth_testkey", HTTP: server.Client()}

	if _, err := client.RequestLink(context.Background(), "someone@example.com", ""); err != nil {
		t.Fatalf("requesting a link failed: %s", err.Error())
	}

	if header != "Bearer ajnauth_testkey" {
		t.Errorf("the authorization header was %q", header)
	}
}

// A site with nothing configured should fail the same way it fails with no
// Resend key today: login is unavailable, and nothing else about the site is.
func TestUnconfiguredFailsCleanly(t *testing.T) {
	for _, client := range []*Client{
		{},
		{BaseURL: "https://auth.example.com"},
		{APIKey: "ajnauth_testkey"},
	} {
		if client.Configured() {
			t.Errorf("%+v reported itself configured", client)
		}

		if _, err := client.RequestLink(context.Background(), "someone@example.com", ""); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%+v: requesting gave %v, want ErrNotConfigured", client, err)
		}

		if _, err := client.Redeem(context.Background(), "a-code"); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%+v: redeeming gave %v, want ErrNotConfigured", client, err)
		}
	}
}

// A service that cannot be reached is temporary, and the site should say so
// rather than show somebody an error about their email address.
func TestUnreachableIsUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()

	client := &Client{BaseURL: url, APIKey: "ajnauth_testkey"}

	if _, err := client.RequestLink(context.Background(), "someone@example.com", ""); !errors.Is(err, ErrUnavailable) {
		t.Errorf("an unreachable service gave %v, want ErrUnavailable", err)
	}
}
