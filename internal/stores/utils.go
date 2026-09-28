package stores

import "github.com/google/uuid"

func CreateUID() string {
	return uuid.New().String()
}
