package middlewares

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/fernandoescolar/minioidc/pkg/domain"
)

var (
	// De-facto standard header keys.
	xForwardedFor    = http.CanonicalHeaderKey("X-Forwarded-For")
	xForwardedHost   = http.CanonicalHeaderKey("X-Forwarded-Host")
	xForwardedProto  = http.CanonicalHeaderKey("X-Forwarded-Proto")
	xForwardedScheme = http.CanonicalHeaderKey("X-Forwarded-Scheme")
	xRealIP          = http.CanonicalHeaderKey("X-Real-IP")
)

var (
	// RFC7239 defines a new "Forwarded: " header designed to replace the
	// existing use of X-Forwarded-* headers.
	// e.g. Forwarded: for=192.0.2.60;proto=https;by=203.0.113.43.
	forwarded = http.CanonicalHeaderKey("Forwarded")
	// Allows for a sub-match of the first value after 'for=' to the next
	// comma, semi-colon or space. The match is case-insensitive.
	forRegex = regexp.MustCompile(`(?i)(?:for=)([^(;|,| )]+)`)
	// Allows for a sub-match for the first instance of scheme (http|https)
	// prefixed by 'proto='. The match is case-insensitive.
	protoRegex = regexp.MustCompile(`(?i)(?:proto=)(https|http)`)
)

type ForwardedHeaders struct {
	active bool
}

func NewForwardedHeaders(config *domain.Config) *ForwardedHeaders {
	return &ForwardedHeaders{active: config.UseForwardedHeaders}
}

func (m *ForwardedHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if m.active {
		if fwd := getIP(r); fwd != "" {
			r.RemoteAddr = fwd
		}

		if scheme := getScheme(r); scheme != "" {
			r.URL.Scheme = scheme
		}

		if r.Header.Get(xForwardedHost) != "" {
			r.Host = r.Header.Get(xForwardedHost)
		}
	}

	next(w, r)
}

func getIP(r *http.Request) string {
	var addr string

	switch {
	case r.Header.Get(xForwardedFor) != "":
		fwd := r.Header.Get(xForwardedFor)
		// Only grab the first (client) address. Note that '192.168.0.1,
		// 10.1.1.1' is a valid key for X-Forwarded-For where addresses after
		// the first may represent forwarding proxies earlier in the chain.
		s := strings.Index(fwd, ", ")
		if s == -1 {
			s = len(fwd)
		}
		addr = fwd[:s]
	case r.Header.Get(xRealIP) != "":
		addr = r.Header.Get(xRealIP)
	case r.Header.Get(forwarded) != "":
		// match should contain at least two elements if the protocol was
		// specified in the Forwarded header. The first element will always be
		// the 'for=' capture, which we ignore. In the case of multiple IP
		// addresses (for=8.8.8.8, 8.8.4.4,172.16.1.20 is valid) we only
		// extract the first, which should be the client IP.
		if match := forRegex.FindStringSubmatch(r.Header.Get(forwarded)); len(match) > 1 {
			// IPv6 addresses in Forwarded headers are quoted-strings. We strip
			// these quotes.
			addr = strings.Trim(match[1], `"`)
		}
	}

	return addr
}

func getScheme(r *http.Request) string {
	var scheme string

	// Retrieve the scheme from X-Forwarded-Proto.
	if proto := r.Header.Get(xForwardedProto); proto != "" {
		scheme = strings.ToLower(proto)
	} else if proto = r.Header.Get(xForwardedScheme); proto != "" {
		scheme = strings.ToLower(proto)
	} else if proto = r.Header.Get(forwarded); proto != "" {
		// match should contain at least two elements if the protocol was
		// specified in the Forwarded header. The first element will always be
		// the 'proto=' capture, which we ignore. In the case of multiple proto
		// parameters (invalid) we only extract the first.
		if match := protoRegex.FindStringSubmatch(proto); len(match) > 1 {
			scheme = strings.ToLower(match[1])
		}
	}

	return scheme
}
