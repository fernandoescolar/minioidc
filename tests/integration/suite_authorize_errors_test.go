package integration

import (
	"net/url"
	"testing"
)

// expectAuthorizeRedirectError sends an authorization request that must be
// rejected with an error redirected to the client (RFC 6749 section 4.1.2.1):
// the test client cannot connect to the callback, so it returns a url.Error.
func expectAuthorizeRedirectError(t *testing.T, req *ClientRequest, oauthError string) url.Values {
	t.Helper()
	resp, err := req.Send()
	urlErr, ok := err.(*url.Error)
	if !ok {
		if resp != nil && resp.r != nil {
			resp.Close()
			t.Fatalf("expected a redirect to the callback with error %s, got status %d", oauthError, resp.StatusCode())
		}
		t.Fatalf("expected a redirect to the callback with error %s, got %v", oauthError, err)
	}

	callback, parseErr := url.Parse(urlErr.URL)
	if parseErr != nil {
		t.Fatalf("cannot parse callback URL %q: %v", urlErr.URL, parseErr)
	}

	params := callback.Query()
	if fragment, err := url.ParseQuery(callback.Fragment); err == nil {
		for key, values := range fragment {
			params[key] = values
		}
	}

	if params.Get("error") != oauthError {
		t.Fatalf("expected error %s in the callback, got %s", oauthError, callback)
	}

	if params.Get("code") != "" || params.Get("access_token") != "" || params.Get("id_token") != "" {
		t.Fatalf("expected no credentials in an error callback: %s", callback)
	}

	return params
}
