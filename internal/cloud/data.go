// Package data is everything in this service that touches Cloud Datastore.
//
// There are three kinds and no users. A magic link is the thing that was
// mailed, an exchange code is what a consumed link turns into on its way back
// to the site, and a send record is the counter that keeps one address from
// being mailed a thousand links.
//
// The magic link half is carried over from the three sites this service
// replaces, because the login it implements is the same login. What is new is
// that every key is scoped to a site: two sites can be mid-login for the same
// person at the same time, and neither can spend the other's link.
package data

import (
	"context"
	"errors"
	"log"
	"os"
	"sort"
	"time"

	datastore "cloud.google.com/go/datastore"
	"github.com/Niximacco/ajn_auth/internal/sites"
)

var datastoreClient *datastore.Client
var ctx context.Context
var namespace string

var (
	TokenNotFoundErr = errors.New("login token not found")
	TokenUsedErr     = errors.New("login token has already been used")
	TokenExpiredErr  = errors.New("login token has expired")

	CodeNotFoundErr = errors.New("exchange code not found")
	CodeUsedErr     = errors.New("exchange code has already been redeemed")
	CodeExpiredErr  = errors.New("exchange code has expired")
	CodeWrongSite   = errors.New("exchange code belongs to another site")
)

const (
	magicLinkKind    = "magic_link"
	exchangeCodeKind = "exchange_code"
	sendRecordKind   = "send_record"
)

func Initialize() {
	projID := os.Getenv("DATASTORE_PROJECT_ID")
	if projID == "" {
		log.Fatal(`You need to set the environment variable "DATASTORE_PROJECT_ID"`)
	}

	namespace = os.Getenv("DATASTORE_NAMESPACE")
	if namespace == "" {
		log.Fatal(`You need to set the environment variable "DATASTORE_NAMESPACE"`)
	}

	ctx = context.Background()
	client, err := datastore.NewClient(ctx, projID)
	if err != nil {
		log.Fatalf("Could not create datastore client: %v", err)
	}

	datastoreClient = client
}

// ----------------------------------------------------------- magic links ----

// MagicLink is one link that was mailed. The key is the hash of the token, so
// the token itself is only ever in the email and in the url the person clicks:
// a reader of this kind cannot sign in as anybody.
type MagicLink struct {
	SiteID string
	Email  string
	// RedirectURI is the url the exchange code will be delivered to. It is
	// pinned when the link is created rather than read again when it is
	// consumed, so a link mailed under one registered uri cannot be redeemed
	// against another that was added to the site later.
	RedirectURI string
	// Next is the path on the site to land on afterwards. It is the site's
	// value and this service does not interpret it beyond refusing one that is
	// not a path.
	Next      string
	Created   int64
	ExpiresAt int64
	Used      bool
	UsedAt    int64

	// Expires is the same moment as a time, for a datastore ttl policy to read.
	// Nothing in this service reads it; ExpiresAt is what the checks use.
	Expires time.Time
}

func magicLinkKey(tokenHash string) *datastore.Key {
	key := datastore.NameKey(magicLinkKind, tokenHash, nil)
	key.Namespace = namespace
	return key
}

func NewMagicLink(tokenHash string, link MagicLink) error {
	link.Email = sites.NormalizeEmail(link.Email)
	link.Created = time.Now().Unix()
	link.Expires = time.Unix(link.ExpiresAt, 0)

	_, err := datastoreClient.Put(ctx, magicLinkKey(tokenHash), &link)
	return err
}

// PeekMagicLink reads a link without spending it.
//
// It exists for one thing: the confirm page has to name the site somebody is
// signing in to, and the only thing that knows which site that is is the token.
// Reading it is a plain Get with no write, so a mail scanner that fetches the
// url out of an email still cannot burn the link - which is the whole reason
// there is a confirm page rather than a GET that signs you in.
//
// It reports expiry and use, so a person with a stale link is told so on the
// page rather than after pressing the button.
func PeekMagicLink(tokenHash string) (link MagicLink, err error) {
	if err = datastoreClient.Get(ctx, magicLinkKey(tokenHash), &link); err != nil {
		if errors.Is(err, datastore.ErrNoSuchEntity) {
			return MagicLink{}, TokenNotFoundErr
		}

		return MagicLink{}, err
	}

	if link.Used {
		return link, TokenUsedErr
	}

	if time.Now().Unix() > link.ExpiresAt {
		return link, TokenExpiredErr
	}

	return link, nil
}

// ConsumeMagicLink spends a link and returns what it was for. The link is spent
// whether or not the caller goes on to do anything with it, and the whole check
// and mark happens in one transaction, so two clicks arriving together cannot
// both succeed.
func ConsumeMagicLink(tokenHash string) (link MagicLink, err error) {
	key := magicLinkKey(tokenHash)

	_, err = datastoreClient.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var stored MagicLink
		if err := tx.Get(key, &stored); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				return TokenNotFoundErr
			}
			return err
		}

		if stored.Used {
			return TokenUsedErr
		}

		if time.Now().Unix() > stored.ExpiresAt {
			return TokenExpiredErr
		}

		stored.Used = true
		stored.UsedAt = time.Now().Unix()
		link = stored

		_, err := tx.Put(key, &stored)
		return err
	})

	if err != nil {
		return MagicLink{}, err
	}

	return link, nil
}

// -------------------------------------------------------- exchange codes ----

// ExchangeCode is what a consumed link becomes: a short-lived, single-use
// value handed to the site's browser, which the site trades for the address
// over its own authenticated connection.
//
// The reason the address does not simply travel in the redirect is that a query
// string is not a private channel. It lands in the site's access logs, in the
// browser's history, and in the Referer of anything the landing page loads. A
// code is worthless in all three places a moment later, and worthless to anyone
// without the site's api key at any time.
type ExchangeCode struct {
	SiteID    string
	Email     string
	Next      string
	Created   int64
	ExpiresAt int64
	Used      bool
	UsedAt    int64

	Expires time.Time
}

func exchangeCodeKey(codeHash string) *datastore.Key {
	key := datastore.NameKey(exchangeCodeKind, codeHash, nil)
	key.Namespace = namespace
	return key
}

func NewExchangeCode(codeHash string, code ExchangeCode) error {
	code.Email = sites.NormalizeEmail(code.Email)
	code.Created = time.Now().Unix()
	code.Expires = time.Unix(code.ExpiresAt, 0)

	_, err := datastoreClient.Put(ctx, exchangeCodeKey(codeHash), &code)
	return err
}

// RedeemExchangeCode spends a code on behalf of a site and returns what it
// stands for.
//
// siteID is checked inside the transaction rather than by the caller
// afterwards, so a site presenting another site's code does not spend it. It is
// the difference between a mis-addressed redeem being an error and being a way
// to knock somebody else's user out of their login.
func RedeemExchangeCode(codeHash string, siteID string) (code ExchangeCode, err error) {
	key := exchangeCodeKey(codeHash)

	_, err = datastoreClient.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var stored ExchangeCode
		if err := tx.Get(key, &stored); err != nil {
			if errors.Is(err, datastore.ErrNoSuchEntity) {
				return CodeNotFoundErr
			}
			return err
		}

		if stored.SiteID != siteID {
			return CodeWrongSite
		}

		if stored.Used {
			return CodeUsedErr
		}

		if time.Now().Unix() > stored.ExpiresAt {
			return CodeExpiredErr
		}

		stored.Used = true
		stored.UsedAt = time.Now().Unix()
		code = stored

		_, err := tx.Put(key, &stored)
		return err
	})

	if err != nil {
		return ExchangeCode{}, err
	}

	return code, nil
}

// ---------------------------------------------------------- send records ----

// SendRecord is how many links have gone to one address for one site, and when.
//
// It is per site and per address on purpose. The caps exist to bound what one
// address can be made to receive and what one guessed address can cost at
// Resend, and both of those are per site: being at the daily cap on wild-games
// is not a reason to refuse a login on flight-log.
//
// It is in datastore rather than in memory because the cap has to hold across
// every running instance to actually bound anything. An in-process counter on
// Cloud Run is a cap times the instance count, which is not a cap.
type SendRecord struct {
	// LastSent is the most recent send, for the short throttle between two
	// links to the same address.
	LastSent int64
	// RecentSends holds the unix times of the links mailed to this address
	// inside the retention window, oldest first. The hourly and daily caps are
	// counted from it. It is left out of the indexes: nothing queries on it,
	// and a repeated indexed property costs an index row per entry.
	RecentSends []int64 `datastore:",noindex"`
	// Updated is when this record was last written, so a ttl policy can sweep
	// records for addresses that stopped signing in.
	Updated time.Time
}

// MAX_RECENT_SENDS is a ceiling on how many timestamps are kept on one record,
// so a pathological entity cannot grow without bound.
const MAX_RECENT_SENDS = 64

func sendRecordKey(siteID string, address string) *datastore.Key {
	// The two parts are joined with a character that cannot appear in either: a
	// site id is letters, digits and hyphens, and an address that got this far
	// has passed ValidAddress. Without that, "a|b" and "a" + "|b" would be the
	// same key and one site could spend another's allowance.
	key := datastore.NameKey(sendRecordKind, siteID+"|"+sites.NormalizeEmail(address), nil)
	key.Namespace = namespace
	return key
}

// GetSendRecord returns what has been sent to an address for a site. An address
// that has never been mailed comes back as a zero record and no error - there
// is nothing exceptional about a first login.
func GetSendRecord(siteID string, address string) (record SendRecord, err error) {
	err = datastoreClient.Get(ctx, sendRecordKey(siteID, address), &record)
	if errors.Is(err, datastore.ErrNoSuchEntity) {
		return SendRecord{}, nil
	}

	if err != nil {
		return SendRecord{}, err
	}

	return record, nil
}

// MarkSent records that a link went out, dropping the timestamps that have
// aged past retain.
func MarkSent(siteID string, address string, at time.Time, retain time.Duration) error {
	key := sendRecordKey(siteID, address)

	_, err := datastoreClient.RunInTransaction(ctx, func(tx *datastore.Transaction) error {
		var record SendRecord
		if err := tx.Get(key, &record); err != nil && !errors.Is(err, datastore.ErrNoSuchEntity) {
			return err
		}

		sends := append(within(record.RecentSends, at.Add(-retain)), at.Unix())
		if len(sends) > MAX_RECENT_SENDS {
			sends = sends[len(sends)-MAX_RECENT_SENDS:]
		}

		record.LastSent = at.Unix()
		record.RecentSends = sends
		record.Updated = at

		_, err := tx.Put(key, &record)
		return err
	})

	return err
}

// within keeps the timestamps at or after a cutoff, in order. Anything older
// has fallen out of every window that is counted from this list.
func within(sends []int64, cutoff time.Time) []int64 {
	kept := make([]int64, 0, len(sends))
	for _, send := range sends {
		if send >= cutoff.Unix() {
			kept = append(kept, send)
		}
	}

	sort.Slice(kept, func(i, j int) bool { return kept[i] < kept[j] })

	return kept
}
