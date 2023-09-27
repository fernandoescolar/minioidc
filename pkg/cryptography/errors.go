package cryptography

import "errors"

func tokenKidError() error {
	return errors.New("token kid does not match or is not present")
}

func unkownChallengeMethodError(method string) error {
	return errors.New("unknown challenge method: " + method)
}

func nullKeyError() error {
	return errors.New("key cannot be nil")
}
