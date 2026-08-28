// Package auth is the session for this service's own admin pages.
//
// It is worth being clear about what this is not. It is not the session any of
// the sites use - those stay with the sites, signed with the sites' own keys,
// and this service never sees one. This is the login for the handful of people
// who edit the roster, and the roster is the only user list it consults.
//
// The service signs its own admins in with its own magic links, through the
// same code path a site uses. That is deliberate: the login every site depends
// on is exercised every time somebody opens the admin pages, so a change that
// breaks it is noticed here first.
package auth

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Niximacco/ajn_auth/internal/sites"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	JWT_SIGNING_KEY []byte
	AUDIENCE        = os.Getenv("DATASTORE_NAMESPACE")

	COOKIE_NAME   = "ajnauth_admin"
	COOKIE_DOMAIN = ""
	COOKIE_SECURE = true
)

var (
	errorNoCredentials = errors.New("not signed in")
	errorInvalidToken  = errors.New("invalid token")
	errorNotAnAdmin    = errors.New("that account may not edit the roster")
)

const (
	// SESSION_VALID_TIME is how long an admin session survives without being
	// used. It is far shorter than the thirty days the sites give an ordinary
	// visitor, because what this session can do is change who may send email as
	// any of them.
	SESSION_VALID_TIME = 12 * time.Hour
	// REFRESH_AFTER is how old a token has to be before a visit re-issues it,
	// so an admin at work for a day is not thrown out mid-edit.
	REFRESH_AFTER = 1 * time.Hour
	ISSUER        = "ajn-auth-admin"

	// contextEmailKey holds the authenticated email address on the gin context.
	contextEmailKey = "auth_email"
)

func init() {
	signingKey := os.Getenv("JWT_SIGNING_KEY")
	if signingKey == "" {
		log.Fatal("No Signing Key Present.")
	}

	JWT_SIGNING_KEY = []byte(signingKey)

	if name := os.Getenv("SESSION_COOKIE_NAME"); name != "" {
		COOKIE_NAME = name
	}

	COOKIE_DOMAIN = os.Getenv("COOKIE_DOMAIN")

	// Secure cookies are the default; plain http local development needs this
	// off.
	if strings.EqualFold(os.Getenv("COOKIE_SECURE"), "false") {
		log.Print("WARNING: COOKIE_SECURE=false, admin session cookies will be sent over plain http")
		COOKIE_SECURE = false
	}
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func New(username string) (tokenString string, err error) {
	claims := Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ISSUER,
			Subject:   username,
			Audience:  []string{AUDIENCE},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(SESSION_VALID_TIME)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(JWT_SIGNING_KEY)
}

// parse validates a raw token string and returns its claims. Anything that
// fails validation - bad signature, wrong algorithm, expired, or issued for
// somebody else's deployment - comes back as an error.
func parse(tokenString string) (claims *Claims, err error) {
	claims = &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return JWT_SIGNING_KEY, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS512.Alg()}))

	if err != nil {
		return nil, err
	}

	if !token.Valid || claims.Issuer != ISSUER || claims.Username == "" {
		return nil, errorInvalidToken
	}

	if !hasAudience(claims.Audience, AUDIENCE) {
		return nil, errorInvalidToken
	}

	return claims, nil
}

func hasAudience(audiences jwt.ClaimStrings, want string) bool {
	for _, audience := range audiences {
		if audience == want {
			return true
		}
	}

	return false
}

// SetSessionCookie writes the session token as an http-only cookie.
func SetSessionCookie(c *gin.Context, token string) {
	// Strict rather than Lax. Nothing links into the admin pages from anywhere
	// else - a person types the address or follows their own magic link, and a
	// magic link lands on /callback and is redirected from there, which carries
	// the cookie either way.
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(COOKIE_NAME, token, int(SESSION_VALID_TIME.Seconds()), "/", COOKIE_DOMAIN, COOKIE_SECURE, true)
}

// ClearSessionCookie expires the session cookie in the browser.
func ClearSessionCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(COOKIE_NAME, "", -1, "/", COOKIE_DOMAIN, COOKIE_SECURE, true)
}

// StartSession issues a fresh token for an email address and sets it as a
// cookie.
func StartSession(c *gin.Context, email string) error {
	token, err := New(email)
	if err != nil {
		return err
	}

	SetSessionCookie(c, token)
	return nil
}

// resolve pulls the session out of the request cookie. There is no bearer
// header alternative: the admin pages are pages, and the api this service
// offers is authenticated by site api keys rather than by anybody's session.
func resolve(c *gin.Context) (email string, err error) {
	cookie, err := c.Cookie(COOKIE_NAME)
	if err != nil || cookie == "" {
		return "", errorNoCredentials
	}

	claims, err := parse(cookie)
	if err != nil {
		// A cookie we can't validate is worse than no cookie: drop it so the
		// browser stops sending it and the admin gets a clean login.
		ClearSessionCookie(c)
		return "", err
	}

	if claims.IssuedAt != nil && time.Since(claims.IssuedAt.Time) > REFRESH_AFTER {
		if refreshed, refreshErr := New(claims.Username); refreshErr == nil {
			SetSessionCookie(c, refreshed)
		}
	}

	return claims.Username, nil
}

// authenticate resolves the session and confirms the address is still on the
// admin list. Being taken off it therefore takes effect on the next click,
// rather than whenever the cookie happens to expire.
//
// It fails closed, which is the opposite of what the sites do with their user
// lookups and is right for the same reason theirs is: a site that cannot read
// its user list should keep people signed in and refuse writes, while a service
// that cannot read the list of who may rewrite its own roster should refuse
// everything until it can.
func authenticate(c *gin.Context) (email string, err error) {
	email, err = resolve(c)
	if err != nil {
		return "", err
	}

	roster, err := sites.Shared().Current()
	if err != nil {
		log.Printf("could not read the roster to check an admin session: %s", err.Error())
		return "", err
	}

	if !roster.IsAdmin(email) {
		ClearSessionCookie(c)
		return "", errorNotAnAdmin
	}

	c.Set(contextEmailKey, email)
	return email, nil
}

// Optional attaches the signed-in admin to the context when there is one, and
// lets the request through either way.
func Optional() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, _ = authenticate(c)
		c.Next()
	}
}

// Required sends anyone without a valid admin session to the login page,
// remembering where they were headed.
func Required() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, err := authenticate(c); err != nil {
			c.Redirect(http.StatusFound, "/admin/login?next="+url.QueryEscape(c.Request.URL.RequestURI()))
			c.Abort()
			return
		}

		c.Next()
	}
}

// Email returns the authenticated address for the request, or "" when the
// request is anonymous.
func Email(c *gin.Context) string {
	email, ok := c.Get(contextEmailKey)
	if !ok {
		return ""
	}

	if asString, ok := email.(string); ok {
		return asString
	}

	return ""
}

// IsSignedIn reports whether the request carried a valid admin session.
func IsSignedIn(c *gin.Context) bool {
	return Email(c) != ""
}
