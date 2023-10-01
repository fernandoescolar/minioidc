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
	MFAEnpoint            = "/mfa"
	MFACreateEndpoint     = MFAEnpoint + "/create"
	MFAVerifyEndpoint     = MFAEnpoint + "/verify"
	LoginEndpoint         = "/login"
	StaticEndpoint        = "/static/"
)

func CreateMinioidcRoutes(mux *http.ServeMux, config *domain.Config, now func() time.Time) http.Handler {
	loggerMiddleware := middlewares.NewLogger()
	sessionMiddleware := middlewares.NewSessionAuthorized(config, now, LoginEndpoint, []string{WellKnownEndpoint, TokenEndpoint, UserinfoEndpoint, StaticEndpoint, LoginEndpoint})
	sessionMFARequired := middlewares.NewSessionMFARequired(config, MFACreateEndpoint, MFAVerifyEndpoint)
	updateSessionTTL := middlewares.NewUpdateSessionTTL(config, now)

	discoveryHandler := handlers.NewDiscoveryHandler(config.Issuer, AuthorizationEndpoint, TokenEndpoint, JWKSEndpoint, UserinfoEndpoint)
	jwksHandler := handlers.NewJWKSHandler(config)
	authorizeHandler := handlers.NewAuthorizeHandler(config, now, LoginEndpoint)
	tokenHanlder := handlers.NewTokenHandler(config, now)
	userinfoHandler := handlers.NewUserinfoHandler(config, now)
	loginHandler := handlers.NewLoginHandler(config, now)
	mfaCreateHandler := handlers.NewMfaCreateHandler(config)
	MFAVerifyHandler := handlers.NewMfaVerifyHandler(config)
	welcomeHandler := handlers.NewWelcomeHandler()

	mux.Handle(DiscoveryEndpoint, discoveryHandler)
	mux.Handle(JWKSEndpoint, jwksHandler)
	mux.Handle(AuthorizationEndpoint, authorizeHandler)
	mux.Handle(TokenEndpoint, tokenHanlder)
	mux.Handle(UserinfoEndpoint, userinfoHandler)
	mux.Handle(LoginEndpoint, loginHandler)
	mux.Handle(MFACreateEndpoint, mfaCreateHandler)
	mux.Handle(MFAVerifyEndpoint, MFAVerifyHandler)
	mux.Handle(IssuerBase, welcomeHandler)
	mux.Handle(StaticEndpoint, http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	return createMiddlewareChain(mux, loggerMiddleware, sessionMiddleware, sessionMFARequired, updateSessionTTL)
}

func createMiddlewareChain(mux *http.ServeMux, middlewares ...domain.Middleware) http.Handler {
	var handler http.Handler
	handler = mux

	// apply middlewares in reverse order
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = wrapHandlerWithMiddleware(handler, middlewares[i])
	}

	return handler
}

func wrapHandlerWithMiddleware(handler http.Handler, middleware domain.Middleware) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		middleware.ServeHTTP(w, r, handler.ServeHTTP)
	})
}
