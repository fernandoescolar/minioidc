package utils

import (
	"strconv"
	"strings"
)

func ParsePtrUint(s string) (*uint, error) {
	if s == "" {
		return nil, nil
	}

	ui64, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, err
	}

	ui32 := uint(ui64)
	return &ui32, nil
}

func ParseSpaceSeparatedString(s string) []string {
	if s == "" {
		return []string{}
	}

	return strings.Split(s, " ")
}
