package main

import (
	"log"
	"net/http"
	"os"

	"github.com/fernandoescolar/minioidc/api"
	"github.com/fernandoescolar/minioidc/pkg/builder"
)

func main() {
	configfile := os.Getenv("MINIOIDC_CONFIG")
	if configfile == "" {
		log.Fatal("MINIOIDC_CONFIG environment variable not set")
	}

	addr := os.Getenv("MINIOIDC_ADDR")
	if addr == "" {
		addr = ":8000"
	}

	builder := builder.NewYamlBuilder(configfile)
	config := builder.Build()
	minioidc, err := api.NewMinioidc(config)
	if err != nil {
		log.Fatal(err)
	}

	handler := http.NewServeMux()
	minioidc.Add(handler)

	log.Printf("Listening http://%v", addr)
	err = http.ListenAndServe(addr, handler)
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
