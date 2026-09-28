package clientauth

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/fernandoescolar/minioidc/pkg/cryptography"
)

const (
	jwksCacheTTL        = 10 * time.Minute
	jwksRefreshInterval = time.Minute
	maxJWKSSize         = 1 << 20
)

// jwksCache keeps the JWKS of the clients. It downloads them again when they
// expire or when an assertion uses an unknown key (the client rotated its keys).
type jwksCache struct {
	mu      sync.Mutex
	client  *http.Client
	now     func() time.Time
	entries map[string]*jwksEntry
}

type jwksEntry struct {
	keys      []cryptography.PublicJWK
	fetchedAt time.Time
}

func newJWKSCache(client *http.Client, now func() time.Time) *jwksCache {
	return &jwksCache{client: client, now: now, entries: map[string]*jwksEntry{}}
}

// Get returns the keys of the JWKS. If kid is not found, the JWKS is
// downloaded again (at most once per minute).
func (c *jwksCache) Get(uri, kid string) ([]cryptography.PublicJWK, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	entry, ok := c.entries[uri]
	fresh := ok && now.Sub(entry.fetchedAt) < jwksCacheTTL
	if fresh && (kid == "" || hasKey(entry.keys, kid) || now.Sub(entry.fetchedAt) < jwksRefreshInterval) {
		return entry.keys, nil
	}

	keys, err := c.fetch(uri)
	if err != nil {
		if ok {
			log.Printf("WRN using cached JWKS of %s: %v", uri, err)
			return entry.keys, nil
		}

		return nil, err
	}

	c.entries[uri] = &jwksEntry{keys: keys, fetchedAt: now}
	return keys, nil
}

func (c *jwksCache) fetch(uri string) ([]cryptography.PublicJWK, error) {
	resp, err := c.client.Get(uri)
	if err != nil {
		return nil, fmt.Errorf("downloading JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("downloading JWKS: status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSSize+1))
	if err != nil {
		return nil, fmt.Errorf("downloading JWKS: %w", err)
	}

	if len(data) > maxJWKSSize {
		return nil, errors.New("downloading JWKS: too big")
	}

	return cryptography.ParseJWKS(data)
}

func hasKey(keys []cryptography.PublicJWK, kid string) bool {
	for _, k := range keys {
		if k.KeyID == kid {
			return true
		}
	}

	return false
}
