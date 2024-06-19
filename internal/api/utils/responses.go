package utils

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

const (
	// known oidc errors
	InvalidRequest           = "invalid_request"
	InteractionRequired      = "interaction_required"
	LoginRequired            = "login_required"
	AccountSelectionRequired = "account_selection_required"
	ConsentRequired          = "consent_required"
	InvalidRequestUri        = "invalid_request_uri"
	InvalidateRequestObject  = "invalid_request_object"
	UnsupportedRequest       = "request_not_supported"
	UnsupportedRequestUri    = "request_uri_not_supported"
	UnsupportedRegistration  = "registration_not_supported"
	UnsupportedResponseType  = "unsupported_response_type"
	InvalidScope             = "invalid_scope"
	UnauthorizedClient       = "unauthorized_client"
	AccessDenied             = "access_denied"
	InvalidClient            = "invalid_client"
	InvalidGrant             = "invalid_grant"
	UnsupportedGrantType     = "unsupported_grant_type"
	InvalidDPoPProof         = "invalid_dpop_proof"

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

func ErrorMissingParameter(w http.ResponseWriter, param string) {
	Error(w, InvalidRequest, fmt.Sprintf("The request is missing the required parameter: %s", param), http.StatusBadRequest)
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
