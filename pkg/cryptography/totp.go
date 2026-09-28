package cryptography

import (
	"fmt"
	"net/url"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// TOTPMethod is the RFC 6238 default (SHA1) supported by every authenticator app
	TOTPMethod = "totp"
	// LegacyTOTPMethod is the SHA256 variant used by enrollments created with older versions
	LegacyTOTPMethod = "topt"

	totpPeriod     = 30
	totpSkew       = 1
	totpSecretSize = 20
)

// NewTOTPSecret generates a random base32 TOTP secret
func NewTOTPSecret() (string, error) {
	return RandomPassword(totpSecretSize)
}

// TOTPURI builds the otpauth:// URI used to enroll a secret in an authenticator app
func TOTPURI(issuer, account, secret string) string {
	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", "SHA1")
	params.Set("digits", "6")
	params.Set("period", fmt.Sprint(totpPeriod))

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: params.Encode(),
	}

	return u.String()
}

// VerifyTOTP validates a TOTP code for the secret, allowing one period of clock skew
func VerifyTOTP(method, secret, code string, now time.Time) bool {
	algorithm := otp.AlgorithmSHA1
	if method == LegacyTOTPMethod {
		algorithm = otp.AlgorithmSHA256
	}

	valid, err := totp.ValidateCustom(code, secret, now.UTC(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpSkew,
		Digits:    otp.DigitsSix,
		Algorithm: algorithm,
	})

	return err == nil && valid
}
