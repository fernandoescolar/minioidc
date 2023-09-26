package handlers

import "net/http"

type WelcomeHandler struct {
	message string
}

func NewWelcomeHandler() *WelcomeHandler {
	return &WelcomeHandler{
		message: "Welcome to minioidc",
	}
}

func (h *WelcomeHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte(h.message))
}
