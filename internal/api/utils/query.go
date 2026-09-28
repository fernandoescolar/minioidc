package utils

import (
	"net/http"
	"net/url"
	"strings"
)

// GetReturnURL returns the return_url parameter only if it is a local path,
// to prevent open redirects to other sites. Otherwise, it returns the fallback.
func GetReturnURL(req *http.Request, fallback string) string {
	returnURL := req.URL.Query().Get("return_url")
	if !isLocalURL(returnURL) {
		return fallback
	}

	return returnURL
}

func isLocalURL(value string) bool {
	// "//host" and "/\host" are treated by browsers as absolute URLs
	if !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.HasPrefix(value, "/\\") {
		return false
	}

	u, err := url.Parse(value)
	return err == nil && u.Scheme == "" && u.Host == ""
}
