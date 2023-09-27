package main

import (
	"errors"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/api"
)

const timeout = 5 * time.Second

func main() {
	configfile := os.Getenv("MINIOIDC_CONFIG")
	if configfile == "" {
		log.Fatal("MINIOIDC_CONFIG environment variable not set")
	}

	addr := os.Getenv("MINIOIDC_ADDR")
	if addr == "" {
		addr = ":8000"
	}

	builder, err := api.NewYamlBuilder(configfile)
	if err != nil {
		log.Fatal(err)
	}

	minioidc, err := builder.Build()
	if err != nil {
		log.Fatal(err)
	}

	handler := http.NewServeMux()
	minioidc.Add(handler)

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: timeout,
	}

	log.Printf("Listening http://%v", addr)
	err = server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
