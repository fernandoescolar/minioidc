package domain

type MFACodeStore interface {
	NewMFACode(id string, user User, secret, method string) (MFACode, error)
	UserHasMFACodes(userID string) (bool, error)
	GetMFACodeByUserID(userID string) ([]MFACode, error)
	DeleteUserMFACodes(userID string)
}

type MFACode interface {
	ID() string
	User() User
	Secret() string
	Method() string
}

type mfaCode struct {
	id     string
	user   User
	secret string
	method string
}

func NewMFACode(id string, user User, secret, method string) MFACode {
	return MFACode(&mfaCode{
		id:     id,
		user:   user,
		secret: secret,
		method: method,
	})
}

func (m *mfaCode) ID() string {
	return m.id
}

func (m *mfaCode) User() User {
	return m.user
}

func (m *mfaCode) Secret() string {
	return m.secret
}

func (m *mfaCode) Method() string {
	return m.method
}
