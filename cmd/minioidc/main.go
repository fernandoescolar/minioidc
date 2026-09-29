package main

import (
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/api"
	"github.com/joho/godotenv"
)

const timeout = 5 * time.Second

func main() {
	err := godotenv.Load()
	if err == nil {
		log.Println("Using .env file to load environment variables")
	}

	addr := getenv("MINIOIDC_ADDR", ":8000")

	var builder *api.Builder
	if configfile := os.Getenv("MINIOIDC_CONFIG"); configfile != "" {
		builder, err = api.NewYamlBuilder(configfile)
	} else {
		// without a configuration file: everything in SQLite, in the data directory
		dataDir := getenv("MINIOIDC_DATA", "data")
		issuer := getenv("MINIOIDC_ISSUER", defaultIssuer(addr))
		log.Printf("MINIOIDC_CONFIG is not set: using the default configuration (issuer %s, data in %s)", issuer, dataDir)
		builder, err = api.NewDefaultBuilder(dataDir, issuer)
	}
	if err != nil {
		log.Fatal(err)
	}

	// the code to create the first administrator (random if it is not set)
	builder.SetupCode = os.Getenv("MINIOIDC_SETUP_CODE")

	minioidc, err := builder.Build()
	if err != nil {
		log.Fatal(err)
	}

	handler := minioidc.Handler()
	defer minioidc.Close()

	if err := minioidc.StartLDAPServer(); err != nil {
		log.Fatal(err)
	}

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

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

// defaultIssuer is the local URL of the server (e.g. http://localhost:8000/)
func defaultIssuer(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		port = "8000"
	}

	return "http://localhost:" + port + "/"
}
