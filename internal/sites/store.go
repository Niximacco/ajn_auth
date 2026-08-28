package sites

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
)

// The roster is read from Secret Manager rather than from an environment
// variable, because it is edited by the admin pages while the service is
// running and a Cloud Run environment variable can only change with a new
// revision. Secret Manager also gives the thing that actually matters when the
// roster is wrong: every save is a new version, and rolling back is pinning an
// older one.
//
// It is cached, because it is read on the hot path of every login and every
// exchange, and it changes a few times a year. cacheFor is how long an instance
// may serve a roster it has not re-checked - long enough that Secret Manager is
// not in the request path, short enough that a key revoked in the admin pages
// takes effect across every instance without a deploy.
//
// A save refreshes the saving instance immediately. The others notice within
// cacheFor, which is the window to keep in mind when revoking a key: if the key
// is known to be in someone else's hands, disable the site as well, because
// that is checked against the same cached copy but leaves nothing usable behind
// when it does take.
const cacheFor = 60 * time.Second

// loadTimeout bounds a read of the secret. It is on the login path, and a
// service that hangs is worse than one that says it is unavailable.
const loadTimeout = 10 * time.Second

var (
	// ErrNoStore means SITES_SECRET was never set, so there is no roster to
	// read and nothing can sign in.
	ErrNoStore = errors.New("no site roster is configured")
)

// Store reads and writes the roster.
type Store struct {
	// secret is the resource the roster lives in,
	// "projects/<project>/secrets/<name>", without a version.
	secret string

	client *secretmanager.Client

	mutex  sync.RWMutex
	cached Config
	// version is the resource name of the version the cached copy came from,
	// which is what the admin pages show and what a save is checked against.
	version string
	loaded  time.Time
	// ok records whether cached is a roster that was actually read, as opposed
	// to the empty one a failed first load leaves behind.
	ok bool
}

var shared *Store

// Initialize opens the roster and reads it once, so that a service that cannot
// see its own configuration fails at start rather than at the first login.
func Initialize(secret string) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		log.Fatal(`You need to set the environment variable "SITES_SECRET" to the Secret Manager resource holding the site roster, "projects/<project>/secrets/<name>"`)
	}

	// The resource is named without a version here; reads ask for "latest" and
	// writes add a new one.
	if strings.Contains(secret, "/versions/") {
		log.Fatalf("SITES_SECRET must name the secret and not a version, got %q", secret)
	}

	ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
	defer cancel()

	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("Could not create the Secret Manager client: %v", err)
	}

	shared = &Store{secret: secret, client: client}

	if _, err := shared.Reload(); err != nil {
		log.Fatalf("Could not read the site roster from %s: %v", secret, err)
	}

	log.Printf("loaded the site roster from %s", shared.version)
}

// Shared is the process-wide store. Every handler reads through it.
func Shared() *Store {
	return shared
}

// Current returns the roster, re-reading it when the cached copy has aged out.
//
// A read that fails while there is a usable cached copy is logged and the
// cached copy is returned. Secret Manager having a bad moment must not take
// logins down across every site: the roster it is holding is the one that was
// correct a minute ago, and serving that is better than refusing everybody.
func (s *Store) Current() (Config, error) {
	if s == nil {
		return Config{}, ErrNoStore
	}

	s.mutex.RLock()
	cached, ok, loaded := s.cached, s.ok, s.loaded
	s.mutex.RUnlock()

	if ok && time.Since(loaded) < cacheFor {
		return cached, nil
	}

	config, err := s.Reload()
	if err != nil {
		if ok {
			log.Printf("could not refresh the site roster, continuing on the copy read %s ago: %s",
				time.Since(loaded).Round(time.Second), err.Error())
			return cached, nil
		}

		return Config{}, err
	}

	return config, nil
}

// Reload reads the latest version of the roster, whatever the cache says.
func (s *Store) Reload() (Config, error) {
	if s == nil {
		return Config{}, ErrNoStore
	}

	ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
	defer cancel()

	response, err := s.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: s.secret + "/versions/latest",
	})
	if err != nil {
		return Config{}, err
	}

	config, err := Parse(response.GetPayload().GetData())
	if err != nil {
		return Config{}, err
	}

	s.mutex.Lock()
	s.cached = config
	s.version = response.GetName()
	s.loaded = time.Now()
	s.ok = true
	s.mutex.Unlock()

	return config, nil
}

// Save validates a roster and adds it as a new version, then refreshes this
// instance's cache from what was written.
//
// It refuses to write a roster that does not validate. The admin pages check
// too, and this checks again, because a roster that cannot be parsed or that
// has no admins left in it is not recoverable through this service - it would
// have to be fixed with gcloud.
func (s *Store) Save(config Config, by string) error {
	if s == nil {
		return ErrNoStore
	}

	if err := config.Validate(); err != nil {
		return err
	}

	config.Updated = time.Now().Unix()
	config.UpdatedBy = NormalizeEmail(by)

	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), loadTimeout)
	defer cancel()

	version, err := s.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent:  s.secret,
		Payload: &secretmanagerpb.SecretPayload{Data: body},
	})
	if err != nil {
		return err
	}

	s.mutex.Lock()
	s.cached = config
	s.version = version.GetName()
	s.loaded = time.Now()
	s.ok = true
	s.mutex.Unlock()

	log.Printf("site roster saved as %s by %s", version.GetName(), config.UpdatedBy)
	return nil
}

// Version is the resource name of the roster version this instance is serving,
// for the admin pages to show.
func (s *Store) Version() string {
	if s == nil {
		return ""
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.version
}

// Parse reads a roster document. It is separate from the reading so the tests,
// and anyone checking a roster before pasting it in, can use it on its own.
func Parse(body []byte) (Config, error) {
	var config Config

	decoder := json.NewDecoder(strings.NewReader(string(body)))
	// An unknown field is almost always a typo in a key name - "redirect_uri"
	// for "redirect_uris" - and silently ignoring it means a site with no
	// redirect uris and a confusing error much later.
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("the site roster is not readable json: %w", err)
	}

	if err := config.Validate(); err != nil {
		return Config{}, fmt.Errorf("the site roster is not usable: %w", err)
	}

	return config, nil
}

// FromFile reads a roster off disk. It exists for checking a document before it
// is pasted into Secret Manager, and for running the service locally.
func FromFile(path string) (Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	return Parse(body)
}
