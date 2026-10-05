package utils

import (
	"encoding/json"
	"log"
	"net/http"
)

const (
	InvalidRequest       = "invalid_request"
	InvalidClient        = "invalid_client"
	InvalidGrant         = "invalid_grant"
	UnsupportedGrantType = "unsupported_grant_type"
	InvalidScope         = "invalid_scope"
	UnauthorizedClient   = "unauthorized_client"
	UnsupportedResponse  = "unsupported_response_type"
	InvalidToken         = "invalid_token"
	ServerError          = "server_error"
	// AccessDenied is the error of the authorization endpoint when the user
	// cannot use the client (RFC 6749 section 4.1.2.1)
	AccessDenied = "access_denied"

	LoginRequired          = "login_required"
	InteractionRequired    = "interaction_required"
	RequestNotSupported    = "request_not_supported"
	RequestURINotSupported = "request_uri_not_supported"

	internalServerError = "internal_server_error"
	applicationJSON     = "application/json"
)

func JSON(w http.ResponseWriter, data []byte) {
	NoCache(w)
	w.Header().Set("Content-Type", applicationJSON)
	w.WriteHeader(http.StatusOK)

	_, err := w.Write(data)
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

// InternalServerError logs the error and writes a generic error, so internal
// details are never sent to the client.
func InternalServerError(w http.ResponseWriter, errorMsg string) {
	log.Printf("Error: %s", errorMsg)
	Error(w, internalServerError, "The server encountered an unexpected error", http.StatusInternalServerError)
}

func Error(w http.ResponseWriter, e, d string, statusCode int) {
	errJSON := map[string]string{
		"error":             e,
		"error_description": d,
	}
	resp, err := json.Marshal(errJSON)
	if err != nil {
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	NoCache(w)
	w.Header().Set("Content-Type", applicationJSON)
	w.WriteHeader(statusCode)

	_, err = w.Write(resp)
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func NoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
}
