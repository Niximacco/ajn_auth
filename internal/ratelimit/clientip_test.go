package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

// request builds a context the way gin would for an inbound request.
func request(remoteAddr string, forwarded string) *gin.Context {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/login", nil)
	c.Request.RemoteAddr = remoteAddr
	if forwarded != "" {
		c.Request.Header.Set("X-Forwarded-For", forwarded)
	}

	return c
}

func withDepth(t *testing.T, depth int) {
	t.Helper()
	original := TRUSTED_PROXY_DEPTH
	TRUSTED_PROXY_DEPTH = depth
	t.Cleanup(func() { TRUSTED_PROXY_DEPTH = original })
}

func TestClientIPTakesTheRightmostEntry(t *testing.T) {
	withDepth(t, 0)

	// What Cloud Run hands the container when the caller forged a header of
	// their own: the front end appends the address it actually saw.
	c := request("10.0.0.1:1234", "203.0.113.99, 198.51.100.7")

	if got := ClientIP(c); got != "198.51.100.7" {
		t.Fatalf("wanted the appended address 198.51.100.7, got %q", got)
	}
}

func TestClientIPIgnoresAForgedHeader(t *testing.T) {
	withDepth(t, 0)

	// A caller claiming to be somebody else must not be able to spend that
	// somebody's allowance, nor to escape their own by rotating the claim.
	first := ClientIP(request("10.0.0.1:1234", "1.1.1.1, 198.51.100.7"))
	second := ClientIP(request("10.0.0.1:1234", "2.2.2.2, 198.51.100.7"))

	if first != second {
		t.Fatalf("forged header changed the identity: %q then %q", first, second)
	}
}

func TestClientIPFallsBackToTheSocketWithoutAHeader(t *testing.T) {
	withDepth(t, 0)

	if got := ClientIP(request("198.51.100.7:44321", "")); got != "198.51.100.7" {
		t.Fatalf("wanted 198.51.100.7 from the socket, got %q", got)
	}
}

func TestClientIPStepsOverExtraTrustedHops(t *testing.T) {
	withDepth(t, 1)

	// A load balancer in front of the front end adds a hop, so the real caller
	// moves one further left.
	c := request("10.0.0.1:1234", "203.0.113.99, 198.51.100.7, 10.0.0.9")

	if got := ClientIP(c); got != "198.51.100.7" {
		t.Fatalf("wanted 198.51.100.7 at depth 1, got %q", got)
	}
}

func TestClientIPClaimsNothingWhenTheShapeIsWrong(t *testing.T) {
	withDepth(t, 2)

	cases := map[string]*gin.Context{
		"fewer entries than trusted hops": request("10.0.0.1:1234", "198.51.100.7"),
		"no header when proxies expected": request("10.0.0.1:1234", ""),
	}

	for name, c := range cases {
		if got := ClientIP(c); got != "" {
			t.Errorf("%s: wanted no address, got %q", name, got)
		}
	}
}

func TestClientIPRejectsJunk(t *testing.T) {
	withDepth(t, 0)

	if got := ClientIP(request("10.0.0.1:1234", "not-an-address")); got != "" {
		t.Fatalf("wanted no address for junk, got %q", got)
	}
}

func TestNormalizeIPCollapsesIPv6ToItsPrefix(t *testing.T) {
	// A single caller normally holds a whole /64, so limiting one address at a
	// time would be walked around trivially.
	first := normalizeIP("2001:db8:1234:5678:0000:0000:0000:0001")
	second := normalizeIP("2001:db8:1234:5678:ffff:ffff:ffff:ffff")

	if first != second {
		t.Fatalf("addresses in one /64 were treated as different callers: %q and %q", first, second)
	}

	// A different /64 is a different caller.
	if other := normalizeIP("2001:db8:1234:9999::1"); other == first {
		t.Fatalf("a different /64 collapsed onto the same key %q", other)
	}
}

func TestNormalizeIPStripsPorts(t *testing.T) {
	if got := normalizeIP("198.51.100.7:44321"); got != "198.51.100.7" {
		t.Errorf("ipv4 with port: got %q", got)
	}

	if got := normalizeIP("[2001:db8::1]:44321"); got != "2001:db8::/64" {
		t.Errorf("bracketed ipv6 with port: got %q", got)
	}
}
