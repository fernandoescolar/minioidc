package responses

import (
	"encoding/json"
	"net/http"
)

const (
	InvalidRequest       = "invalid_request"
	InvalidClient        = "invalid_client"
	InvalidGrant         = "invalid_grant"
	UnsupportedGrantType = "unsupported_grant_type"
	InvalidScope         = "invalid_scope"
	UnauthorizedClient   = "unauthorized_client"

	internalServerError = "internal_server_error"
	applicationJSON     = "application/json"
)

func JSON(w http.ResponseWriter, data []byte) {
	NoCache(w)
	w.Header().Set("Content-Type", applicationJSON)
	w.WriteHeader(http.StatusOK)

	_, err := w.Write(data)
	if err != nil {
		panic(err)
	}
}

func InternalServerError(w http.ResponseWriter, errorMsg string) {
	Error(w, internalServerError, errorMsg, http.StatusInternalServerError)
}

func Error(w http.ResponseWriter, error, description string, statusCode int) {
	errJSON := map[string]string{
		"error":             error,
		"error_description": description,
	}
	resp, err := json.Marshal(errJSON)
	if err != nil {
		http.Error(w, error, http.StatusInternalServerError)
	}

	NoCache(w)
	w.Header().Set("Content-Type", applicationJSON)
	w.WriteHeader(statusCode)

	_, err = w.Write(resp)
	if err != nil {
		panic(err)
	}
}

func NoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
}
