package router

import (
	"net/http"
	"time"

	"github.com/fernandoescolar/minioidc/internal/api/handlers"
	"github.com/fernandoescolar/minioidc/internal/api/middlewares"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

const (
	IssuerBase            = "/"
	OAuthEndpoint         = "/connect/"
	WellKnownEndpoint     = "/.well-known/"
	AuthorizationEndpoint = OAuthEndpoint + "authorize"
	TokenEndpoint         = OAuthEndpoint + "token"
	UserinfoEndpoint      = OAuthEndpoint + "userinfo"
	JWKSEndpoint          = WellKnownEndpoint + "jwks.json"
	DiscoveryEndpoint     = WellKnownEndpoint + "openid-configuration"
	LoginEndpoint         = "/login"
	StaticEndpoint        = "/static/"
)

func CreateMinioidcRoutes(mux *http.ServeMux, config *domain.Config, now func() time.Time) http.Handler {
	loggerMiddleware := middlewares.NewLogger()
	sessionMiddleware := middlewares.NewSessionAuthorized(config, LoginEndpoint, []string{WellKnownEndpoint, TokenEndpoint, UserinfoEndpoint, StaticEndpoint, LoginEndpoint})

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
	mux.Handle(StaticEndpoint, http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	return createMiddlewareChain(mux, loggerMiddleware, sessionMiddleware)
}

func createMiddlewareChain(mux *http.ServeMux, middlewares ...domain.Middleware) http.Handler {
	var handler http.Handler
	handler = mux
	for _, middleware := range middlewares {
		handler = wrapHandlerWithMiddleware(handler, middleware)
	}

	return handler
}

func wrapHandlerWithMiddleware(handler http.Handler, middleware domain.Middleware) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.ServeHTTP(w, r, handler.ServeHTTP)
	})
}
