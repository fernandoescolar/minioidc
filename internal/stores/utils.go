package stores

import (
	"strings"

	"github.com/google/uuid"
)

func CreateUID() string {
	return uuid.New().String()
}

func CreateComplexUID() string {
	id := uuid.New().String() + uuid.New().String()
	return strings.ReplaceAll(id, "-", "")
}
