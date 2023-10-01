package utils

import "net/http"

func GetReturnURL(req *http.Request) string {
	returnURL := req.URL.Query().Get("return_url")
	if returnURL == "" {
		returnURL = "/"
	}

	return returnURL
}
