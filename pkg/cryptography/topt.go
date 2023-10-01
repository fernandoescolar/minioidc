package cryptography

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

// / The specifications for this are found in RFC 6238
// / http://tools.ietf.org/html/rfc6238
type TOTP struct {
	secret    string
	secretKey []byte
	step      int
	digits    int
}

func NewTOTPDefault(secret string) *TOTP {
	return NewTOTP(secret, 30, 6)
}

// NewTOTP creates a new TOTP instance with the provided parameters.
func NewTOTP(secret string, step, digits int) *TOTP {
	if step <= 0 || digits <= 0 || digits > 10 {
		panic("Invalid step or digits")
	}

	secretKey := secret
	missingPadding := len(secret) % 8
	if missingPadding != 0 {
		secretKey = secretKey + strings.Repeat("=", 8-missingPadding)
	}

	secretBytes, err := base32.StdEncoding.DecodeString(secretKey)
	if err != nil {
		panic("decode secret failed")
	}

	return &TOTP{
		secret:    secret,
		secretKey: secretBytes,
		step:      step,
		digits:    digits,
	}
}

func (t *TOTP) Uri(issuer, account string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		issuer,
		account,
		t.secret,
		issuer,
		"SHA256",
		t.digits,
		t.step,
	)

}

// Compute generates a TOTP code based on the current time.
func (t *TOTP) Compute() string {
	return t.ComputeAt(time.Now())
}

func (t *TOTP) ComputeAt(time time.Time) string {
	counter := t.calculateTimeStepFromTimestamp(time)
	return t.compute(counter)
}

// Verify checks if the provided valueToVerify is a valid TOTP code for the current time or a time range.
func (t *TOTP) Verify(valueToVerify string, from, to int) bool {
	return t.VerifyAt(valueToVerify, time.Now(), from, to)
}

func (t *TOTP) VerifyAt(valueToVerify string, time time.Time, from, to int) bool {
	counter := t.calculateTimeStepFromTimestamp(time)
	for i := from; i <= to; i++ {
		if t.valuesEqual(t.compute(counter+int64(i)), valueToVerify) {
			return true
		}
	}

	return false
}

func (t *TOTP) compute(counter int64) string {
	data := t.getBigEndianBytes(counter)
	otp := t.calculateOTP(data)

	return t.digitsFormat(otp, t.digits)
}

func (t *TOTP) calculateOTP(data []byte) int {
	hmacComputedHash := t.calculateHMAC(data)
	offset := int(hmacComputedHash[len(hmacComputedHash)-1] & 0x0F)
	return int(hmacComputedHash[offset]&0x7f)<<24 |
		int(hmacComputedHash[offset+1]&0xff)<<16 |
		int(hmacComputedHash[offset+2]&0xff)<<8 |
		int(hmacComputedHash[offset+3]&0xff)%1000000
}

func (t *TOTP) calculateHMAC(data []byte) []byte {
	h := hmac.New(func() hash.Hash {
		return sha256.New()
	}, t.secretKey)
	h.Write(data)
	return h.Sum(nil)
}

func (t *TOTP) valuesEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}
	return result == 0
}

func (t *TOTP) calculateTimeStepFromTimestamp(timestamp time.Time) int64 {
	unixTimestamp := timestamp.Unix()
	window := unixTimestamp / int64(t.step)
	return window
}

func (t *TOTP) getBigEndianBytes(input int64) []byte {
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(input & 0xff)
		input = input >> 8
	}

	return byteArr
}

func (t *TOTP) digitsFormat(input int, digitCount int) string {
	truncatedValue := input % int(math.Pow10(digitCount))
	format := fmt.Sprintf("%%0%dd", digitCount)
	return fmt.Sprintf(format, truncatedValue)
}
