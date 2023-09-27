package router

import (
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/handlers"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	IssuerBase            = "/"
	AuthorizationEndpoint = "/connect/authorize"
	TokenEndpoint         = "/connect/token"
	UserinfoEndpoint      = "/connect/userinfo"
	JWKSEndpoint          = "/.well-known/jwks.json"
	DiscoveryEndpoint     = "/.well-known/openid-configuration"
	LoginEndpoint         = "/login"
)

func CreateMinioidcRoutes(mux *http.ServeMux, config *domain.Config, now func() time.Time) {
	discoveryHandler := handlers.NewDiscoveryHandler(config.Issuer, AuthorizationEndpoint, TokenEndpoint, JWKSEndpoint, UserinfoEndpoint)
	jwksHandler := handlers.NewJWKSHandler(config)
	authorizeHandler := handlers.NewAuthorizeHandler(config, now, LoginEndpoint)
	tokenHanlder := handlers.NewTokenHandler(config, now)
	userinfoHandler := handlers.NewUserinfoHandler(config, now)
	loginHandler := handlers.NewLoginHandler(config, now)
	welcomeHandler := handlers.NewWelcomeHandler()

	mux.Handle(DiscoveryEndpoint, discoveryHandler)
	mux.Handle(JWKSEndpoint, jwksHandler)
	mux.Handle(AuthorizationEndpoint, authorizeHandler)
	mux.Handle(TokenEndpoint, tokenHanlder)
	mux.Handle(UserinfoEndpoint, userinfoHandler)
	mux.Handle(LoginEndpoint, loginHandler)
	mux.Handle(IssuerBase, welcomeHandler)

	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
}
