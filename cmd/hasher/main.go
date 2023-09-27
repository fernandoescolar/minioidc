package main

import (
	"os"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

const Arguments = 2

func main() {
	if len(os.Args) < Arguments {
		println("Usage: hasher <plaintext>")
		os.Exit(1)
	}

	plaintext := os.Args[1]
	hashed, err := cryptography.HashPassword(plaintext)
	if err != nil {
		println(err.Error())
		os.Exit(1)
	}

	println(hashed)
}
