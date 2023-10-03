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

	internalServerError = "internal_server_error"
	applicationJSON     = "application/json"
)

func JSON(w http.ResponseWriter, data []byte) {
	NoCache(w)
	w.Header().Set("Content-Type", applicationJSON)
	w.WriteHeader(http.StatusOK)

	_, err := w.Write(data)
	if err != nil {
		log.Println("Error writing response: %w", err)
	}
}

func InternalServerError(w http.ResponseWriter, errorMsg string) {
	Error(w, internalServerError, errorMsg, http.StatusInternalServerError)
}

func Error(w http.ResponseWriter, e, d string, statusCode int) {
	errJSON := map[string]string{
		"error":             e,
		"error_description": d,
	}
	resp, err := json.Marshal(errJSON)
	if err != nil {
		http.Error(w, e, http.StatusInternalServerError)
	}

	NoCache(w)
	w.Header().Set("Content-Type", applicationJSON)
	w.WriteHeader(statusCode)

	_, err = w.Write(resp)
	if err != nil {
		log.Println("Error writing response: %w", err)
	}
}

func NoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
}
