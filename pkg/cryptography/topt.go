package cryptography

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"time"
)

// / The specifications for this are found in RFC 6238
// / http://tools.ietf.org/html/rfc6238
type TOTP struct {
	secretKey []byte
	step      int
	digits    int
}

// NewTOTP creates a new TOTP instance with the provided parameters.
func NewTOTP(secretKey []byte, step, digits int) *TOTP {
	if step <= 0 || digits <= 0 || digits > 10 {
		panic("Invalid step or digits")
	}
	paddedKeyLength := int(math.Ceil(float64(len(secretKey))/16.0) * 16)
	secretKeyPadded := make([]byte, paddedKeyLength)
	copy(secretKeyPadded, secretKey)

	return &TOTP{
		secretKey: secretKeyPadded,
		step:      step,
		digits:    digits,
	}
}

func (t *TOTP) Uri(issuer, account string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		issuer,
		account,
		t.secretKey,
		issuer,
		"SHA256",
		t.digits,
		t.step,
	)

}

// Compute generates a TOTP code based on the current time.
func (t *TOTP) Compute() string {
	counter := t.calculateTimeStepFromTimestamp(time.Now())
	return t.compute(counter)
}

// Verify checks if the provided valueToVerify is a valid TOTP code for the current time or a time range.
func (t *TOTP) Verify(valueToVerify string, from, to int) bool {
	counter := t.calculateTimeStepFromTimestamp(time.Now())
	for i := from; i <= to; i++ {
		if t.valuesEqual(t.compute(counter+int64(i)), valueToVerify) {
			return true
		}
	}

	return false
}

// VerifyHash checks if the provided hashToVerify is a valid TOTP code (after applying the hashAction) for the current time or a time range.
func (t *TOTP) VerifyHash(hashToVerify string, hashAction func(string) string, from, to int) bool {
	counter := t.calculateTimeStepFromTimestamp(time.Now())
	for i := from; i <= to; i++ {
		code := t.compute(counter + int64(i))
		actual := hashAction(code)
		if t.valuesEqual(actual, hashToVerify) {
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
	binary.BigEndian.PutUint32(hmacComputedHash[offset:], binary.BigEndian.Uint32(hmacComputedHash[offset:])&0x7FFFFFFF)

	return int(hmacComputedHash[offset])<<24 |
		int(hmacComputedHash[offset+1])<<16 |
		int(hmacComputedHash[offset+2])<<8 |
		int(hmacComputedHash[offset+3])%1000000
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
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(input))
	return data
}

func (t *TOTP) digitsFormat(input int, digitCount int) string {
	truncatedValue := input % int(math.Pow(10, float64(digitCount)))
	format := fmt.Sprintf("%%0%dd", digitCount)
	return fmt.Sprintf(format, truncatedValue)
}
