package utils

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func AddRedirectToCSPHeader(w http.ResponseWriter, redirectURI string) {
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		Error(w, InvalidRequest, "Invalid redirect uri", http.StatusBadRequest)
		return
	}

	redirectHost := redirectURL.Hostname()
	csp := w.Header().Get("Content-Security-Policy")
	csp = strings.ReplaceAll(csp, "form-action 'self';", fmt.Sprintf("form-action 'self' https: %s;", redirectHost))
	w.Header().Set("Content-Security-Policy", csp)
}
