// Package ldapserver serves a read only LDAP directory with the users of
// minioidc, so applications that only support LDAP can use them.
//
//   - Bind: the service account (bind_dn), the users (uid=<username>,ou=users,<base dn>
//     or just the username) and anonymous binds. The users with MFA must add
//     their TOTP code to the end of the password (e.g. "secret123456").
//   - Search: base, one level and subtree searches with any filter.
//   - Extended operations: StartTLS.
//   - Add, modify, delete and compare are not supported: the directory is read only.
package ldapserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/internal/credentials"
	"github.com/fernandoescolar/minioidc/pkg/cryptography"
	"github.com/fernandoescolar/minioidc/pkg/domain"
	"github.com/go-ldap/ldap/v3"
	"github.com/jimlambrt/gldap"
)

const (
	startTimeout = 5 * time.Second
	ioTimeout    = 30 * time.Second
)

// Server is the LDAP server
type Server struct {
	config      domain.LDAPServerConfig
	baseDN      *ldap.DN
	usersDN     *ldap.DN
	serviceDN   *ldap.DN
	now         func() time.Time
	lister      domain.UserLister
	credentials *credentials.Checker
	states      domain.UserStateStore
	events      *domain.Recorder
	tlsConfig   *tls.Config

	mu          sync.Mutex
	connections map[int]*connection
	server      *gldap.Server
}

// connection is the state of a client connection
type connection struct {
	// dn of the bound identity ("" for anonymous)
	dn      string
	service bool
	tls     bool
}

// New validates the configuration and creates the server
func New(config *domain.Config, now func() time.Time) (*Server, error) {
	cfg := config.LDAPServer
	if cfg == nil {
		return nil, errors.New("ldap server: missing configuration")
	}

	lister, ok := config.UserStore.(domain.UserLister)
	if !ok {
		return nil, errors.New("ldap server: the users must be in SQLite or in the configuration file (not in LDAP)")
	}

	baseDN, err := ldap.ParseDN(cfg.BaseDN)
	if err != nil || len(baseDN.RDNs) == 0 {
		return nil, fmt.Errorf("ldap server: invalid base dn %q", cfg.BaseDN)
	}

	usersDN, _ := ldap.ParseDN("ou=users," + cfg.BaseDN)
	s := &Server{
		config:  *cfg,
		baseDN:  baseDN,
		usersDN: usersDN,
		now:     now,
		lister:  lister,
		states:  config.UserStateStore,
		events:  &domain.Recorder{Store: config.EventStore, Now: now},
		credentials: &credentials.Checker{
			Users:      config.UserStore,
			MFA:        config.MFACodeStore,
			Blocked:    config.UserBlockedStore,
			RequireMFA: config.RequireMFA,
			States:     config.UserStateStore,
		},
		connections: map[int]*connection{},
	}

	if cfg.BindDN != "" {
		if s.serviceDN, err = ldap.ParseDN(cfg.BindDN); err != nil {
			return nil, fmt.Errorf("ldap server: invalid bind dn %q", cfg.BindDN)
		}

		if cfg.BindPasswordHash == "" {
			return nil, errors.New("ldap server: bind_password_hash is required with bind_dn")
		}
	}

	switch cfg.TLSMode {
	case domain.LDAPTLSNone:
	case domain.LDAPTLSLDAPS, domain.LDAPTLSStartTLS:
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("ldap server: loading the TLS certificate: %w", err)
		}

		s.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	default:
		return nil, fmt.Errorf("ldap server: unsupported tls mode %q", cfg.TLSMode)
	}

	return s, nil
}

// Start listens in the background. It returns when the server is ready.
func (s *Server) Start() error {
	server, err := gldap.NewServer(
		gldap.WithOnClose(s.forget),
		gldap.WithReadTimeout(ioTimeout),
		gldap.WithWriteTimeout(ioTimeout),
	)
	if err != nil {
		return err
	}

	mux, err := gldap.NewMux()
	if err != nil {
		return err
	}

	routes := []error{
		mux.Bind(s.bind),
		mux.Search(s.search),
		mux.Unbind(func(*gldap.ResponseWriter, *gldap.Request) {}),
		// the directory is read only: each operation answers with its response type
		mux.Add(s.readOnly(gldap.ApplicationAddResponse)),
		mux.Modify(s.readOnly(gldap.ApplicationModifyResponse)),
		mux.Delete(s.readOnly(gldap.ApplicationDelResponse)),
		mux.DefaultRoute(s.readOnly(gldap.ApplicationExtendedResponse)),
	}
	if s.config.TLSMode == domain.LDAPTLSStartTLS {
		routes = append(routes, mux.ExtendedOperation(s.startTLS, gldap.ExtendedOperationStartTLS))
	}

	for _, err := range append(routes, server.Router(mux)) {
		if err != nil {
			return err
		}
	}

	var options []gldap.Option
	if s.config.TLSMode == domain.LDAPTLSLDAPS {
		options = append(options, gldap.WithTLSConfig(s.tlsConfig))
	}

	errs := make(chan error, 1)
	go func() {
		errs <- server.Run(s.config.Address, options...)
	}()

	deadline := time.After(startTimeout)
	for !server.Ready() {
		select {
		case err := <-errs:
			return fmt.Errorf("ldap server: %w", err)
		case <-deadline:
			return errors.New("ldap server: timeout starting")
		case <-time.After(10 * time.Millisecond):
		}
	}

	s.server = server
	if s.config.TLSMode == domain.LDAPTLSNone {
		log.Printf("WRN the LDAP server has no TLS: the passwords are sent in clear text")
	}
	log.Printf("LDAP server listening on %s (base dn %s)", s.config.Address, s.config.BaseDN)
	return nil
}

// Stop closes the listener and the connections
func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}

	return s.server.Stop()
}

func (s *Server) conn(id int) *connection {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.connections[id]
	if !ok {
		c = &connection{}
		s.connections[id] = c
	}

	return c
}

// state returns a copy of the connection state
func (s *Server) state(id int) connection {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c, ok := s.connections[id]; ok {
		return *c
	}

	return connection{}
}

func (s *Server) setIdentity(id int, dn string, service bool) {
	c := s.conn(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	c.dn, c.service = dn, service
}

func (s *Server) forget(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.connections, id)
}

// ---------- Bind ----------

func (s *Server) bind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer func() { _ = w.Write(resp) }()

	m, err := r.GetSimpleBindMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}

	// a new bind always resets the identity of the connection
	s.setIdentity(r.ConnectionID(), "", false)

	name := strings.TrimSpace(m.UserName)
	password := string(m.Password)
	if name == "" && password == "" {
		resp.SetResultCode(gldap.ResultSuccess)
		return
	}

	if s.config.TLSMode == domain.LDAPTLSStartTLS && !s.state(r.ConnectionID()).tls {
		resp.SetResultCode(gldap.ResultConfidentialityRequired)
		resp.SetDiagnosticMessage("use StartTLS before sending credentials")
		return
	}

	// a name without password is an unauthenticated bind (RFC 4513 section 5.1.2)
	if password == "" {
		return
	}

	if dn, err := ldap.ParseDN(name); err == nil && s.serviceDN != nil && dn.EqualFold(s.serviceDN) {
		if cryptography.CheckPasswordHash(password, s.config.BindPasswordHash) {
			s.setIdentity(r.ConnectionID(), s.config.BindDN, true)
			resp.SetResultCode(gldap.ResultSuccess)
		}
		return
	}

	username, ok := s.username(name)
	if !ok {
		return
	}

	if s.authenticate(username, password) {
		s.setIdentity(r.ConnectionID(), userDN(username, s.config.BaseDN), false)
		resp.SetResultCode(gldap.ResultSuccess)
	}
}

// username returns the username of a user DN (uid=<username>,ou=users,<base dn>).
// A plain username is accepted too.
func (s *Server) username(name string) (string, bool) {
	if !strings.Contains(name, "=") {
		return name, true
	}

	dn, err := ldap.ParseDN(name)
	if err != nil || len(dn.RDNs) != len(s.usersDN.RDNs)+1 {
		return "", false
	}

	parent := &ldap.DN{RDNs: dn.RDNs[1:]}
	first := dn.RDNs[0].Attributes
	if !parent.EqualFold(s.usersDN) || len(first) != 1 || !strings.EqualFold(first[0].Type, "uid") {
		return "", false
	}

	return first[0].Value, true
}

// authenticate checks the password (and the TOTP code at its end, when the
// user has MFA) with the same brute force protection of the login page
func (s *Server) authenticate(username, password string) bool {
	user, _, err := s.credentials.Authenticate(username, password, s.now())
	if err != nil {
		// gldap does not give the address of the client
		s.events.Record(nil, domain.Event{Type: domain.EventLoginLDAP, Result: domain.ResultFailure, Username: username, Detail: err.Error()})
		if errors.Is(err, credentials.ErrLockout) {
			s.events.Record(nil, domain.Event{Type: domain.EventLoginLockout, Result: domain.ResultFailure, Username: username, Detail: "the LDAP server"})
		}
		return false
	}

	s.events.RecordUser(nil, domain.EventLoginLDAP, domain.ResultSuccess, user, "")
	return true
}

// ---------- Search ----------

func (s *Server) search(w *gldap.ResponseWriter, r *gldap.Request) {
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	defer func() { _ = w.Write(done) }()

	m, err := r.GetSearchMessage()
	if err != nil {
		done.SetResultCode(gldap.ResultProtocolError)
		return
	}

	filter, err := compileFilter(m.Filter)
	if err != nil {
		done.SetResultCode(gldap.ResultProtocolError)
		done.SetDiagnosticMessage("invalid filter")
		return
	}

	// the root DSE describes the server and it is always public
	if strings.TrimSpace(m.BaseDN) == "" && m.Scope == gldap.BaseObject {
		root := s.rootDSE()
		if matches(filter, root) {
			s.writeEntry(w, r, root, m)
		}
		return
	}

	conn := s.state(r.ConnectionID())
	if conn.dn == "" && !s.config.AllowAnonymous {
		done.SetResultCode(gldap.ResultInsufficientAccessRights)
		return
	}

	base, err := ldap.ParseDN(m.BaseDN)
	if err != nil {
		done.SetResultCode(gldap.ResultInvalidDNSyntax)
		return
	}

	users, err := s.lister.ListUsers()
	if err != nil {
		log.Printf("ldap server: listing users: %v", err)
		done.SetResultCode(gldap.ResultOperationsError)
		return
	}

	// the disabled accounts are not in the directory
	active := users[:0]
	for _, u := range users {
		if state, err := s.states.GetUserState(u.Subject); err == nil && !state.Disabled {
			active = append(active, u)
		}
	}

	dir := buildDirectory(s.config.BaseDN, active)
	if !dir.exists(base) {
		done.SetResultCode(gldap.ResultNoSuchObject)
		done.SetMatchedDN(s.config.BaseDN)
		return
	}

	// the users can only read their own entry, unless users_can_search is enabled
	var own *ldap.DN
	if conn.dn != "" && !conn.service && !s.config.UsersCanSearch {
		own, _ = ldap.ParseDN(conn.dn)
	}

	sent := int64(0)
	for _, e := range dir.entries {
		if !inScope(base, e.parsedDN, m.Scope) || (own != nil && !own.EqualFold(e.parsedDN)) || !matches(filter, e) {
			continue
		}

		if m.SizeLimit > 0 && sent >= m.SizeLimit {
			done.SetResultCode(gldap.ResultSizeLimitExceeded)
			return
		}

		s.writeEntry(w, r, e, m)
		sent++
	}
}

func (d *directory) exists(dn *ldap.DN) bool {
	for _, e := range d.entries {
		if e.parsedDN.EqualFold(dn) {
			return true
		}
	}

	return false
}

func inScope(base, dn *ldap.DN, scope gldap.Scope) bool {
	switch scope {
	case gldap.BaseObject:
		return base.EqualFold(dn)
	case gldap.SingleLevel:
		return len(dn.RDNs) == len(base.RDNs)+1 && base.AncestorOfFold(dn)
	default:
		return base.EqualFold(dn) || base.AncestorOfFold(dn)
	}
}

// writeEntry sends an entry with the requested attributes: all of them when
// the list is empty or has "*", none with "1.1" (RFC 4511 section 4.5.1.8)
func (s *Server) writeEntry(w *gldap.ResponseWriter, r *gldap.Request, e *entry, m *gldap.SearchMessage) {
	all := len(m.Attributes) == 0
	requested := map[string]bool{}
	for _, a := range m.Attributes {
		if a == "*" {
			all = true
		}
		requested[strings.ToLower(a)] = true
	}

	attributes := map[string][]string{}
	for name, values := range e.attributes {
		if !all && !requested[strings.ToLower(name)] {
			continue
		}

		if m.TypesOnly {
			values = []string{}
		}
		attributes[name] = values
	}

	if err := w.Write(r.NewSearchResponseEntry(e.dn, gldap.WithAttributes(attributes))); err != nil {
		log.Printf("ldap server: writing entry: %v", err)
	}
}

func (s *Server) rootDSE() *entry {
	extensions := []string{}
	if s.config.TLSMode == domain.LDAPTLSStartTLS {
		extensions = append(extensions, string(gldap.ExtendedOperationStartTLS))
	}

	return &entry{
		dn:       "",
		parsedDN: &ldap.DN{},
		attributes: map[string][]string{
			"objectClass":          {"top"},
			"namingContexts":       {s.config.BaseDN},
			"supportedLDAPVersion": {"3"},
			"supportedExtension":   extensions,
			"vendorName":           {"minioidc"},
		},
	}
}

// ---------- Extended operations ----------

func (s *Server) startTLS(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewExtendedResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	resp.SetResponseName(gldap.ExtendedOperationStartTLS)
	if s.state(r.ConnectionID()).tls {
		resp.SetResultCode(gldap.ResultOperationsError)
		resp.SetDiagnosticMessage("TLS is already established")
		_ = w.Write(resp)
		return
	}

	if err := w.Write(resp); err != nil {
		return
	}

	if err := r.StartTLS(s.tlsConfig); err != nil {
		log.Printf("ldap server: StartTLS: %v", err)
		return
	}

	c := s.conn(r.ConnectionID())
	s.mu.Lock()
	c.tls = true
	s.mu.Unlock()
}

// readOnly answers the operations that change the directory
func (s *Server) readOnly(applicationCode int) gldap.HandlerFunc {
	return func(w *gldap.ResponseWriter, r *gldap.Request) {
		_ = w.Write(r.NewResponse(
			gldap.WithApplicationCode(applicationCode),
			gldap.WithResponseCode(gldap.ResultUnwillingToPerform),
			gldap.WithDiagnosticMessage("the minioidc directory is read only"),
		))
	}
}
