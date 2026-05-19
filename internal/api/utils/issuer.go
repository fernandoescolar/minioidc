package utils

import "net/http"

func GetIssuer(defaultValue string, r *http.Request) string {
	if defaultValue != "" {
		return defaultValue
	}

	return r.URL.Scheme + "://" + r.URL.Hostname() + "/"
}
