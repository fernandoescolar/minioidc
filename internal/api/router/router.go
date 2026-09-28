package router

import (
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/admin"
	"github.com/fernandoescolar/minioidc/internal/api/handlers"
	"github.com/fernandoescolar/minioidc/internal/api/middlewares"
	"github.com/fernandoescolar/minioidc/internal/clientauth"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// clientJWKSTimeout is the timeout to download the JWKS of private_key_jwt clients
const clientJWKSTimeout = 5 * time.Second

const (
	IssuerBase            = "/"
	OAuthEndpoint         = "/"
	WellKnownEndpoint     = "/.well-known/"
	AuthorizationEndpoint = OAuthEndpoint + "authorize"
	TokenEndpoint         = OAuthEndpoint + "token"
	UserinfoEndpoint      = OAuthEndpoint + "userinfo"
	RevokeEndpoint        = OAuthEndpoint + "revoke"
	IntrospectionEndpoint = OAuthEndpoint + "introspect"
	JWKSEndpoint          = WellKnownEndpoint + "jwks.json"
	DiscoveryEndpoint     = WellKnownEndpoint + "openid-configuration"
	MFAEnpoint            = "/mfa/"
	MFACreateEndpoint     = MFAEnpoint + "create"
	MFAVerifyEndpoint     = MFAEnpoint + "verify"
	LoginEndpoint         = "/login"
	LogoutEndpoint        = "/logout"
	HealthEndpoint        = "/healthz"
	AdminEndpoint         = "/admin"
	AdminAPIEndpoint      = AdminEndpoint + "/api/"
	StaticEndpoint        = "/static/"
)

// CreateMinioidcRoutes registers the endpoints under the path of the issuer
// (e.g. https://host/auth/token when the issuer is https://host/auth)
func CreateMinioidcRoutes(mux *http.ServeMux, config *domain.Config, now func() time.Time) http.Handler {
	base := config.BasePath
	path := func(endpoint string) string { return base + endpoint }
	// the absolute URL of an endpoint (the issuer already has the base path)
	endpointURL := func(endpoint string) string { return strings.TrimSuffix(config.Issuer, "/") + endpoint }
	authenticator := clientauth.New(config.ClientStore, config.ClientAssertionStore, config.Issuer, endpointURL(TokenEndpoint), now, &http.Client{Timeout: clientJWKSTimeout})

	loggerMiddleware := middlewares.NewLogger(config)
	forwardedHeaders := middlewares.NewForwardedHeaders(config)
	hstsMiddleware := middlewares.NewHSTS(config)
	corsMiddleware := middlewares.NewCORS([]string{
		path(TokenEndpoint), path(UserinfoEndpoint), path(RevokeEndpoint), path(IntrospectionEndpoint), path(DiscoveryEndpoint), path(JWKSEndpoint),
	})
	cspMiddleware := middlewares.NewCSP(config)
	csrfMiddleware := middlewares.NewCSRF(config, now)
	// the authorization endpoint handles the session itself (prompt, max_age...)
	sessionMiddleware := middlewares.NewSessionAuthorized(config, now, path(LoginEndpoint), []string{
		path(WellKnownEndpoint), path(AuthorizationEndpoint), path(TokenEndpoint), path(UserinfoEndpoint), path(RevokeEndpoint), path(IntrospectionEndpoint),
		path(StaticEndpoint), path(LoginEndpoint), path(LogoutEndpoint), path(HealthEndpoint),
		// the admin API answers with JSON errors instead of redirecting to the login
		path(AdminAPIEndpoint),
	})
	sessionMFARequired := middlewares.NewSessionMFARequired(config, path(MFACreateEndpoint), path(MFAVerifyEndpoint))
	updateSessionTTL := middlewares.NewUpdateSessionTTL(config, now)

	// the discovery document builds the URLs from the issuer, that already has the base path
	discoveryHandler := handlers.NewDiscoveryHandler(config.Issuer, handlers.DiscoveryEndpoints{
		Authorization: AuthorizationEndpoint,
		Token:         TokenEndpoint,
		JWKS:          JWKSEndpoint,
		Userinfo:      UserinfoEndpoint,
		EndSession:    LogoutEndpoint,
		Revocation:    RevokeEndpoint,
		Introspection: IntrospectionEndpoint,
	})

	mux.Handle(path(DiscoveryEndpoint), discoveryHandler)
	mux.Handle(path(JWKSEndpoint), handlers.NewJWKSHandler(config))
	mux.Handle(path(AuthorizationEndpoint), handlers.NewAuthorizeHandler(config, now, path(LoginEndpoint), path(MFAVerifyEndpoint)))
	mux.Handle(path(TokenEndpoint), handlers.NewTokenHandler(config, now, authenticator, endpointURL(TokenEndpoint)))
	mux.Handle(path(UserinfoEndpoint), handlers.NewUserinfoHandler(config, now))
	mux.Handle(path(RevokeEndpoint), handlers.NewRevokeHandler(config, authenticator, endpointURL(RevokeEndpoint)))
	mux.Handle(path(IntrospectionEndpoint), handlers.NewIntrospectionHandler(config, now, authenticator, endpointURL(IntrospectionEndpoint)))
	mux.Handle(path(LoginEndpoint), handlers.NewLoginHandler(config, now))
	mux.Handle(path(LogoutEndpoint), handlers.NewLogoutHandler(config, now))
	mux.Handle(path(MFACreateEndpoint), handlers.NewMfaCreateHandler(config, now, path(MFAVerifyEndpoint)))
	mux.Handle(path(MFAVerifyEndpoint), handlers.NewMfaVerifyHandler(config, now, path(MFACreateEndpoint)))
	mux.Handle(path(HealthEndpoint), handlers.NewHealthHandler())
	if config.AdminEnabled {
		adminHandler, err := admin.NewHandler(config, now)
		if err != nil {
			// the builder validates the configuration of the admin web
			panic(err)
		}

		mux.Handle(path(AdminEndpoint)+"/", http.StripPrefix(path(AdminEndpoint), adminHandler))
	}
	mux.Handle(path(IssuerBase), handlers.NewWelcomeHandler())
	mux.Handle(path(StaticEndpoint), http.StripPrefix(path(StaticEndpoint), http.FileServer(http.Dir("static"))))

	return createMiddlewareChain(mux,
		loggerMiddleware,
		forwardedHeaders,
		hstsMiddleware,
		corsMiddleware,
		cspMiddleware,
		csrfMiddleware,
		sessionMiddleware,
		sessionMFARequired,
		updateSessionTTL)
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
