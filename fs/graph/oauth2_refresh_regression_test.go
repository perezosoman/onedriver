package graph

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// invalidGrantServer returns an httptest.Server whose /token POST handler
// responds with HTTP 400 and a JSON body that EXPLICITLY clears both
// access_token and refresh_token. On unfixed oauth2 code, json.Unmarshal
// leaves auth.AccessToken = "", which drives Refresh() into the newAuth()
// branch (and thus the getAuthCodeHeadless() URL prompt). On the fixed
// code, the CI/mock guard short-circuits before newAuth is reached, so
// the goroutine in each test returns within the 5s timeout.
func invalidGrantServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"invalid_grant","error_description":"Refresh token expired","access_token":"","refresh_token":""}`))
	}))
}

// TestRefresh_NoNewAuthInCIMode is the regression test for the CI failure
// where stale tokens in .auth_tokens.json caused Refresh() to cascade from
// a failed Microsoft response into newAuth() → getAuthCodeHeadless() → URL
// prompt → stdin hang → process timeout.
//
// Without the fix, Refresh() in CI mode would block on stdin while waiting
// for the user to paste the OAuth redirect URL. With the fix, Refresh() in
// CI mode returns promptly without prompting.
func TestRefresh_NoNewAuthInCIMode(t *testing.T) {
	t.Setenv("CI", "true")
	t.Setenv("ONEDRIVER_MOCK", "")

	server := invalidGrantServer(t)
	defer server.Close()

	auth := &Auth{
		AuthConfig: AuthConfig{
			ClientID:    "test-client",
			TokenURL:    server.URL + "/token",
			CodeURL:     "http://localhost",
			RedirectURL: "http://localhost",
		},
		AccessToken:  "original-access-token",
		RefreshToken: "original-refresh-token",
		ExpiresAt:    time.Now().Unix() - 3600, // expired
	}

	// Run Refresh() in a goroutine so we can detect a stdin hang with a
	// timeout. If the CI guard works, the goroutine returns quickly.
	done := make(chan struct{})
	go func() {
		auth.Refresh()
		close(done)
	}()
	select {
	case <-done:
		// Refresh() returned without prompting — fix is working.
	case <-time.After(5 * time.Second):
		t.Fatal("Refresh() blocked — likely triggered an OAuth prompt in CI mode")
	}
}

// TestRefresh_NoNewAuthInMockMode covers ONEDRIVER_MOCK=1: mock-mode test
// binaries must also refuse interactive auth when the mock token endpoint
// reports a refresh error.
func TestRefresh_NoNewAuthInMockMode(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("ONEDRIVER_MOCK", "1")

	server := invalidGrantServer(t)
	defer server.Close()

	auth := &Auth{
		AuthConfig: AuthConfig{
			ClientID:    "test-client",
			TokenURL:    server.URL + "/token",
			CodeURL:     "http://localhost",
			RedirectURL: "http://localhost",
		},
		AccessToken:  "original-access-token",
		RefreshToken: "original-refresh-token",
		ExpiresAt:    time.Now().Unix() - 3600,
	}

	done := make(chan struct{})
	go func() {
		auth.Refresh()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Refresh() blocked in mock mode — likely triggered an OAuth prompt")
	}
}

// TestRefresh_NoNewAuthWhenBothCIAndMockSet covers the case where both env
// vars are set simultaneously (e.g. a CI workflow with ONEDRIVER_MOCK=1).
func TestRefresh_NoNewAuthWhenBothCIAndMockSet(t *testing.T) {
	t.Setenv("CI", "true")
	t.Setenv("ONEDRIVER_MOCK", "1")

	server := invalidGrantServer(t)
	defer server.Close()

	auth := &Auth{
		AuthConfig: AuthConfig{
			ClientID:    "test-client",
			TokenURL:    server.URL + "/token",
			CodeURL:     "http://localhost",
			RedirectURL: "http://localhost",
		},
		AccessToken:  "original-access-token",
		RefreshToken: "original-refresh-token",
		ExpiresAt:    time.Now().Unix() - 3600,
	}

	done := make(chan struct{})
	go func() {
		auth.Refresh()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Refresh() blocked with CI+ONEDRIVER_MOCK set")
	}
}

// TestRefresh_NoopWhenNotExpired verifies that Refresh() is a no-op when
// the token is still valid (sanity check to ensure we did not break the
// happy path with the new CI guard).
func TestRefresh_NoopWhenNotExpired(t *testing.T) {
	t.Setenv("CI", "")
	t.Setenv("ONEDRIVER_MOCK", "")

	// TokenURL intentionally unreachable; if Refresh() tries to POST to it,
	// the test will fail with a timeout.
	auth := &Auth{
		AuthConfig: AuthConfig{
			ClientID:    "test-client",
			TokenURL:    "http://127.0.0.1:1", // unreachable
			CodeURL:     "http://localhost",
			RedirectURL: "http://localhost",
		},
		AccessToken:  "valid-token",
		RefreshToken: "valid-refresh",
		ExpiresAt:    time.Now().Unix() + 3600, // valid (future)
	}

	done := make(chan struct{})
	go func() {
		auth.Refresh()
		close(done)
	}()
	select {
	case <-done:
		// Good: Refresh() is a no-op for non-expired tokens.
	case <-time.After(2 * time.Second):
		t.Fatal("Refresh() unexpectedly executed network call for a non-expired token")
	}

	if auth.AccessToken != "valid-token" || auth.RefreshToken != "valid-refresh" {
		t.Fatalf("Refresh() mutated non-expired token: access=%q refresh=%q",
			auth.AccessToken, auth.RefreshToken)
	}
}
