package handlers

import (
	"net/http"

	"github.com/fernandoescolar/minioidc/internal/api/utils"
)

type WelcomeHandler struct {
	message string
}

var _ http.Handler = (*WelcomeHandler)(nil)

func NewWelcomeHandler() *WelcomeHandler {
	return &WelcomeHandler{
		message: "Welcome to minioidc",
	}
}

func (h *WelcomeHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	_, err := w.Write([]byte(h.message))
	if err != nil {
		utils.InternalServerError(w, err.Error())
	}
}
