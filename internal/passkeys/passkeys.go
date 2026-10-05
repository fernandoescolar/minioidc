// Package passkeys runs the WebAuthn ceremonies of the passkeys: the
// registration of a passkey by a signed in user, and the login without a
// password (discoverable credentials). The relying party is the host of the
// issuer, so the passkeys only work in that domain.
package passkeys

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	// ChallengeTTL is the time to complete a ceremony
	ChallengeTTL = 5 * time.Minute
	// maxChallenges limits the memory used by the pending ceremonies: anyone
	// can start a login
	maxChallenges = 10000
	// maxUserHandle is the maximum length of the WebAuthn user handle (the subject)
	maxUserHandle = 64
	// MaxNameLength is the maximum length of the name of a passkey
	MaxNameLength = 64
)

var (
	ErrInvalidChallenge = errors.New("the passkey request has expired: try it again")
	ErrTooManyRequests  = errors.New("too many passkey requests: try it again later")
	ErrClonedPasskey    = errors.New("the passkey may have been cloned")
)

// Service keeps the challenges of the ceremonies in memory: they are single
// use and expire in ChallengeTTL.
type Service struct {
	webauthn *webauthn.WebAuthn
	store    domain.PasskeyStore
	users    domain.UserStore
	now      func() time.Time

	mu         sync.Mutex
	challenges map[string]challenge
}

type challenge struct {
	session webauthn.SessionData
	// userID is the user that registers a passkey (empty in the logins)
	userID    string
	expiresAt time.Time
}

// New creates the service for the issuer: the relying party ID is its host
// and the origin its scheme and host.
func New(config *domain.Config, now func() time.Time) (*Service, error) {
	issuer, err := url.Parse(config.Issuer)
	if err != nil || issuer.Hostname() == "" {
		return nil, fmt.Errorf("passkeys: invalid issuer %q", config.Issuer)
	}

	wa, err := webauthn.New(&webauthn.Config{
		RPID:          issuer.Hostname(),
		RPDisplayName: config.Name,
		RPOrigins:     []string{issuer.Scheme + "://" + issuer.Host},
	})
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}

	return &Service{
		webauthn:   wa,
		store:      config.PasskeyStore,
		users:      config.UserStore,
		now:        now,
		challenges: map[string]challenge{},
	}, nil
}

// BeginRegistration returns the options of navigator.credentials.create() to
// add a passkey to the user
func (s *Service) BeginRegistration(user domain.User) (*protocol.CredentialCreation, error) {
	if len(user.ID()) > maxUserHandle {
		return nil, fmt.Errorf("passkeys: the subject of the user is longer than %d bytes", maxUserHandle)
	}

	existing, err := s.credentials(user.ID())
	if err != nil {
		return nil, err
	}

	// an authenticator cannot have two passkeys of the same user
	exclusions := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, credential := range existing {
		exclusions = append(exclusions, credential.Descriptor())
	}

	options, session, err := s.webauthn.BeginRegistration(&webauthnUser{user: user, credentials: existing},
		webauthn.WithExclusions(exclusions),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}

	if err := s.saveChallenge(*session, user.ID()); err != nil {
		return nil, err
	}

	return options, nil
}

// FinishRegistration verifies the response of navigator.credentials.create()
// and stores the passkey of the user
func (s *Service) FinishRegistration(user domain.User, name string, body io.Reader) (domain.Passkey, error) {
	response, err := protocol.ParseCredentialCreationResponseBody(body)
	if err != nil {
		return domain.Passkey{}, fmt.Errorf("passkeys: %w", err)
	}

	ch, ok := s.takeChallenge(response.Response.CollectedClientData.Challenge)
	if !ok || ch.userID != user.ID() {
		return domain.Passkey{}, ErrInvalidChallenge
	}

	existing, err := s.credentials(user.ID())
	if err != nil {
		return domain.Passkey{}, err
	}

	credential, err := s.webauthn.CreateCredential(&webauthnUser{user: user, credentials: existing}, ch.session, response)
	if err != nil {
		return domain.Passkey{}, fmt.Errorf("passkeys: %w", err)
	}

	encoded, err := json.Marshal(credential)
	if err != nil {
		return domain.Passkey{}, err
	}

	passkey := domain.Passkey{
		ID:         base64.RawURLEncoding.EncodeToString(credential.ID),
		UserID:     user.ID(),
		Name:       CleanName(name, len(existing)+1),
		Credential: encoded,
		CreatedAt:  s.now(),
	}
	if err := s.store.AddPasskey(passkey); err != nil {
		return domain.Passkey{}, err
	}

	return passkey, nil
}

// BeginLogin returns the options of navigator.credentials.get() to sign in
// with any passkey (the browser shows the passkeys of the site)
func (s *Service) BeginLogin() (*protocol.CredentialAssertion, error) {
	options, session, err := s.webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}

	if err := s.saveChallenge(*session, ""); err != nil {
		return nil, err
	}

	return options, nil
}

// FinishLogin verifies the response of navigator.credentials.get() and
// returns the user of the passkey. With ErrClonedPasskey it returns the user
// too (for the activity log): the caller must not sign it in.
func (s *Service) FinishLogin(body io.Reader) (domain.User, error) {
	response, err := protocol.ParseCredentialRequestResponseBody(body)
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}

	ch, ok := s.takeChallenge(response.Response.CollectedClientData.Challenge)
	if !ok || ch.userID != "" {
		return nil, ErrInvalidChallenge
	}

	var user domain.User
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		u, err := s.users.GetUserByID(string(userHandle))
		if err != nil {
			return nil, err
		}

		credentials, err := s.credentials(u.ID())
		if err != nil {
			return nil, err
		}

		user = u
		return &webauthnUser{user: u, credentials: credentials}, nil
	}

	_, credential, err := s.webauthn.ValidatePasskeyLogin(handler, ch.session, response)
	if err != nil {
		return nil, fmt.Errorf("passkeys: %w", err)
	}

	// the sign count went back: the private key may have been copied
	if credential.Authenticator.CloneWarning {
		return user, ErrClonedPasskey
	}

	encoded, err := json.Marshal(credential)
	if err != nil {
		return nil, err
	}

	if err := s.store.UsePasskey(base64.RawURLEncoding.EncodeToString(credential.ID), encoded, s.now()); err != nil {
		return nil, err
	}

	return user, nil
}

// CleanName trims the name of a passkey, or gives a default one
func CleanName(name string, number int) string {
	name = strings.Join(strings.Fields(name), " ")
	if runes := []rune(name); len(runes) > MaxNameLength {
		name = string(runes[:MaxNameLength])
	}
	if name == "" {
		name = fmt.Sprintf("Passkey %d", number)
	}

	return name
}

// credentials are the WebAuthn credentials of the passkeys of a user
func (s *Service) credentials(userID string) ([]webauthn.Credential, error) {
	passkeys, err := s.store.ListPasskeys(userID)
	if err != nil {
		return nil, err
	}

	credentials := make([]webauthn.Credential, 0, len(passkeys))
	for _, passkey := range passkeys {
		var credential webauthn.Credential
		if err := json.Unmarshal(passkey.Credential, &credential); err != nil {
			return nil, fmt.Errorf("passkeys: invalid credential %s: %w", passkey.ID, err)
		}

		credentials = append(credentials, credential)
	}

	return credentials, nil
}

func (s *Service) saveChallenge(session webauthn.SessionData, userID string) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	for key, ch := range s.challenges {
		if now.After(ch.expiresAt) {
			delete(s.challenges, key)
		}
	}
	if len(s.challenges) >= maxChallenges {
		return ErrTooManyRequests
	}

	s.challenges[session.Challenge] = challenge{session: session, userID: userID, expiresAt: now.Add(ChallengeTTL)}
	return nil
}

// takeChallenge returns the challenge and removes it: each one can be used once
func (s *Service) takeChallenge(value string) (challenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.challenges[value]
	if !ok {
		return challenge{}, false
	}

	delete(s.challenges, value)
	return ch, !s.now().After(ch.expiresAt)
}

// webauthnUser is a user for the WebAuthn library: the user handle is the subject
type webauthnUser struct {
	user        domain.User
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte {
	return []byte(u.user.ID())
}

func (u *webauthnUser) WebAuthnName() string {
	data := u.user.Data()
	if data.PreferredUsername != "" {
		return data.PreferredUsername
	}

	return u.user.Username()
}

func (u *webauthnUser) WebAuthnDisplayName() string {
	if name := u.user.Data().Name; name != "" {
		return name
	}

	return u.WebAuthnName()
}

func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.credentials
}
