package router

import (
	"net/http"
	"strings"
	"time"

	"github.com/fernandoescolar/minioidc/internal/admin"
	"github.com/fernandoescolar/minioidc/internal/api/handlers"
	"github.com/fernandoescolar/minioidc/internal/api/middlewares"
	"github.com/fernandoescolar/minioidc/internal/clientauth"
	"github.com/fernandoescolar/minioidc/internal/passkeys"
	"github.com/fernandoescolar/minioidc/pkg/domain"
)

// clientJWKSTimeout is the timeout to download the JWKS of private_key_jwt clients
const clientJWKSTimeout = 5 * time.Second

const (
	IssuerBase                  = "/"
	OAuthEndpoint               = "/connect/"
	WellKnownEndpoint           = "/.well-known/"
	AuthorizationEndpoint       = OAuthEndpoint + "authorize"
	TokenEndpoint               = OAuthEndpoint + "token"
	UserinfoEndpoint            = OAuthEndpoint + "userinfo"
	RevokeEndpoint              = OAuthEndpoint + "revoke"
	IntrospectionEndpoint       = OAuthEndpoint + "introspect"
	EndSessionEndpoint          = OAuthEndpoint + "endsession"
	DeviceAuthorizationEndpoint = OAuthEndpoint + "deviceauthorization"
	DeviceEndpoint              = OAuthEndpoint + "device"
	JWKSEndpoint                = WellKnownEndpoint + "jwks.json"
	DiscoveryEndpoint           = WellKnownEndpoint + "openid-configuration"
	MFAEnpoint                  = "/mfa/"
	MFACreateEndpoint           = MFAEnpoint + "create"
	MFAVerifyEndpoint           = MFAEnpoint + "verify"
	LoginEndpoint               = "/login"
	ProfileEndpoint             = "/profile"
	ProfilePasswordEndpoint     = ProfileEndpoint + "/password"
	ProfileMFAEndpoint          = ProfileEndpoint + "/mfa"
	ProfilePasskeysEndpoint     = ProfileEndpoint + "/passkeys"
	PasskeyRegisterBegin        = ProfilePasskeysEndpoint + "/register/begin"
	PasskeyRegisterFinish       = ProfilePasskeysEndpoint + "/register/finish"
	PasskeyEndpoint             = "/passkey/"
	PasskeyLoginBegin           = PasskeyEndpoint + "login/begin"
	PasskeyLoginFinish          = PasskeyEndpoint + "login/finish"
	HealthEndpoint              = "/healthz"
	SetupEndpoint               = "/setup"
	ResetPasswordEndpoint       = "/reset-password"
	WelcomeEndpoint             = "/welcome"
	AdminEndpoint               = "/admin"
	AdminAPIEndpoint            = AdminEndpoint + "/api/"
	StaticEndpoint              = "/static/"
)

// CreateMinioidcRoutes registers the endpoints under the path of the issuer
// (e.g. https://host/auth/token when the issuer is https://host/auth)
func CreateMinioidcRoutes(mux *http.ServeMux, config *domain.Config, now func() time.Time) http.Handler {
	base := config.BasePath
	// the activity log uses the clock of the server
	config.Events = &domain.Recorder{Store: config.EventStore, Now: now}
	path := func(endpoint string) string { return base + endpoint }
	// the absolute URL of an endpoint (the issuer already has the base path)
	endpointURL := func(endpoint string) string { return strings.TrimSuffix(config.Issuer, "/") + endpoint }
	authenticator := clientauth.New(config.ClientStore, config.ClientAssertionStore, config.Issuer, endpointURL(TokenEndpoint), now, &http.Client{Timeout: clientJWKSTimeout})

	loggerMiddleware := middlewares.NewLogger(config)
	forwardedHeaders := middlewares.NewForwardedHeaders(config)
	hstsMiddleware := middlewares.NewHSTS(config)
	corsMiddleware := middlewares.NewCORS([]string{
		path(TokenEndpoint), path(UserinfoEndpoint), path(RevokeEndpoint), path(IntrospectionEndpoint), path(DeviceAuthorizationEndpoint),
		path(DiscoveryEndpoint), path(JWKSEndpoint),
	})
	cspMiddleware := middlewares.NewCSP(config)
	csrfMiddleware := middlewares.NewCSRF(config, now)
	// the authorization endpoint handles the session itself (prompt, max_age...)
	sessionMiddleware := middlewares.NewSessionAuthorized(config, now, path(LoginEndpoint), []string{
		path(WellKnownEndpoint), path(AuthorizationEndpoint), path(TokenEndpoint), path(UserinfoEndpoint), path(RevokeEndpoint), path(IntrospectionEndpoint),
		path(DeviceAuthorizationEndpoint), path(StaticEndpoint), path(LoginEndpoint), path(EndSessionEndpoint), path(HealthEndpoint),
		path(SetupEndpoint), path(PasskeyEndpoint), path(ResetPasswordEndpoint),
		// the admin API answers with JSON errors instead of redirecting to the login
		path(AdminAPIEndpoint),
	})
	sessionMFARequired := middlewares.NewSessionMFARequired(config, path(MFACreateEndpoint), path(MFAVerifyEndpoint))
	accountState := middlewares.NewAccountState(config, now, path(LoginEndpoint), path(ProfilePasswordEndpoint), []string{path(MFAEnpoint)})
	updateSessionTTL := middlewares.NewUpdateSessionTTL(config, now)

	// the discovery document builds the URLs from the issuer, that already has the base path
	discoveryHandler := handlers.NewDiscoveryHandler(config.Issuer, handlers.DiscoveryEndpoints{
		Authorization: AuthorizationEndpoint,
		Token:         TokenEndpoint,
		JWKS:          JWKSEndpoint,
		Userinfo:      UserinfoEndpoint,
		EndSession:    EndSessionEndpoint,
		Revocation:    RevokeEndpoint,
		Introspection: IntrospectionEndpoint,
		Device:        DeviceAuthorizationEndpoint,
	}, handlers.DiscoveryOptions{AllowImplicitFlow: config.AllowImplicitFlow, AllowPasswordGrant: config.AllowPasswordGrant})

	mux.Handle(path(DiscoveryEndpoint), discoveryHandler)
	mux.Handle(path(JWKSEndpoint), handlers.NewJWKSHandler(config))
	mux.Handle(path(AuthorizationEndpoint), handlers.NewAuthorizeHandler(config, now, path(LoginEndpoint), path(MFAVerifyEndpoint), path(ProfilePasswordEndpoint)))
	mux.Handle(path(TokenEndpoint), handlers.NewTokenHandler(config, now, authenticator, endpointURL(TokenEndpoint)))
	mux.Handle(path(UserinfoEndpoint), handlers.NewUserinfoHandler(config, now))
	mux.Handle(path(RevokeEndpoint), handlers.NewRevokeHandler(config, now, authenticator, endpointURL(RevokeEndpoint)))
	mux.Handle(path(IntrospectionEndpoint), handlers.NewIntrospectionHandler(config, now, authenticator, endpointURL(IntrospectionEndpoint)))
	// the onboarding, while there are no users
	setupHandler := handlers.NewSetupHandler(config, now, endpointURL(SetupEndpoint), path(LoginEndpoint), path(WelcomeEndpoint))
	mux.Handle(path(SetupEndpoint), setupHandler)
	mux.Handle(path(ResetPasswordEndpoint), handlers.NewResetPasswordHandler(config, now, path(LoginEndpoint)))
	mux.Handle(path(WelcomeEndpoint), setupHandler.Welcome())
	mux.Handle(path(LoginEndpoint), handlers.NewLoginHandler(config, now, setupHandler, path(SetupEndpoint)))
	if config.PasskeysEnabled {
		service, err := passkeys.New(config, now)
		if err != nil {
			// the builder validates the issuer
			panic(err)
		}

		passkeyLogin := handlers.NewPasskeyLoginHandler(config, now, service)
		mux.Handle(path(PasskeyLoginBegin), passkeyLogin.Begin())
		mux.Handle(path(PasskeyLoginFinish), passkeyLogin.Finish())
		profilePasskeys := handlers.NewProfilePasskeysHandler(config, now, service, path(ProfilePasskeysEndpoint), path(LoginEndpoint))
		mux.Handle(path(ProfilePasskeysEndpoint), profilePasskeys)
		mux.Handle(path(PasskeyRegisterBegin), profilePasskeys.RegisterBegin())
		mux.Handle(path(PasskeyRegisterFinish), profilePasskeys.RegisterFinish())
	}
	mux.Handle(path(EndSessionEndpoint), handlers.NewLogoutHandler(config, now))
	mux.Handle(path(DeviceAuthorizationEndpoint), handlers.NewDeviceAuthorizationHandler(config, now, authenticator, endpointURL(DeviceAuthorizationEndpoint), endpointURL(DeviceEndpoint)))
	mux.Handle(path(DeviceEndpoint), handlers.NewDeviceHandler(config, now))
	mux.Handle(path(ProfileEndpoint), handlers.NewProfileHandler(config))
	mux.Handle(path(ProfilePasswordEndpoint), handlers.NewProfilePasswordHandler(config, now))
	mux.Handle(path(ProfileMFAEndpoint), handlers.NewProfileMFAHandler(config, now, path(ProfileMFAEndpoint)))
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
	mux.Handle(path(IssuerBase), handlers.NewHomeHandler(config, path(ProfileEndpoint)))
	mux.Handle(path(StaticEndpoint), revalidate(http.StripPrefix(path(StaticEndpoint), http.FileServer(http.Dir("static")))))

	return createMiddlewareChain(mux,
		loggerMiddleware,
		forwardedHeaders,
		hstsMiddleware,
		corsMiddleware,
		cspMiddleware,
		csrfMiddleware,
		sessionMiddleware,
		sessionMFARequired,
		accountState,
		updateSessionTTL)
}

// revalidate makes the browsers check if the static files have changed (a
// cheap 304 when they have not), so they do not keep the files of an old version
func revalidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
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
