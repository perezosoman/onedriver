package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jstaf/onedriver/fs/graph/mock"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// hasValidAuthTokens verifies if .auth_tokens.json contains valid credentials
func hasValidAuthTokens(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	content := strings.TrimSpace(string(data))
	if content == "" || content == "{}" || len(content) < 50 {
		return false
	}

	return true
}

// AuthAvailable is set by TestMain and indicates whether valid OneDrive
// credentials were found. Tests that require authentication should call
// t.Skip() when this is false.
var AuthAvailable bool
var authTokenPath string = ".auth_tokens.json"

func TestMain(m *testing.M) {
	os.Chdir("../..")

	// When ONEDRIVER_MOCK is set, use a local mock server instead of the real
	// Microsoft Graph API. Uses a separate file to avoid overwriting real credentials.
	authTokenPath = ".auth_tokens.json"
	var mockServer *mock.Server
	if os.Getenv("ONEDRIVER_MOCK") == "1" {
		mockServer = mock.NewServer()
		SetGraphURL(mockServer.URL())
		mockAuth := fmt.Sprintf(
			`{"access_token":"mock-token","refresh_token":"mock-refresh",`+
				`"expires_at":9999999999,"account":"test@mock.local",`+
				`"config":{"tokenURL":"%s/token"}}`,
			mockServer.URL(),
		)
		os.WriteFile(".auth_tokens_mock.json", []byte(mockAuth), 0600)
		authTokenPath = ".auth_tokens_mock.json"
		fmt.Println("Mock enabled, GraphURL:", mockServer.URL())
	}

	f, _ := os.OpenFile("fusefs_tests.log", os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0644)
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: f, TimeFormat: "15:04:05"})
	defer f.Close()

	// Check if we have valid auth tokens
	if hasValidAuthTokens(authTokenPath) {
		AuthAvailable = true
	} else if os.Getenv("CI") != "" || os.Getenv("ONEDRIVER_MOCK") == "1" {
		// CI/mock mode: skip authenticated tests (no interactive login available)
		fmt.Println("⚠️  OneDrive credentials not available — authenticated tests will be skipped")
	} else {
		// Local mode: let Authenticate() show the OAuth dialog
		fmt.Println("No credentials found — starting OAuth flow to obtain them...")
		AuthAvailable = true
	}

	if AuthAvailable && os.Getenv("CI") == "" {
		auth := Authenticate(AuthConfig{}, authTokenPath, false)
		user, _ := GetUser(context.Background(), auth)
		drive, _ := GetDrive(context.Background(), auth)
		log.Info().
			Str("account", user.UserPrincipalName).
			Str("type", drive.DriveType).
			Msg("Starting tests")
	}

	// CI mode: refresh tokens if expired, but never open GUI/headless prompt.
	// Track whether refresh succeeded so we don't cascade a failed refresh
	// into Request() → Refresh() → newAuth() → URL prompt, which would hang
	// CI waiting for interactive stdin input.
	if AuthAvailable && os.Getenv("CI") != "" {
		refreshSucceeded := false
		auth := &Auth{}
		if err := auth.FromFile(authTokenPath); err == nil {
			// FromFile skips keyring in test binaries to avoid dbus hangs.
			// In CI we need the refresh token — load it from keyring explicitly.
			if auth.RefreshToken == "" {
				if token, err := keyringGet(authTokenPath); err == nil {
					auth.RefreshToken = token
				}
			}
			if auth.RefreshToken != "" {
				data := url.Values{
					"client_id":     {auth.ClientID},
					"redirect_uri":  {auth.RedirectURL},
					"refresh_token": {auth.RefreshToken},
					"grant_type":    {"refresh_token"},
				}
				resp, err := http.Post(auth.TokenURL,
					"application/x-www-form-urlencoded",
					strings.NewReader(data.Encode()))
				switch {
				case err != nil:
					log.Warn().Err(err).Msg("Token refresh failed in CI — tests will be skipped")
				case resp.StatusCode < 200 || resp.StatusCode >= 300:
					// Microsoft returns 400 (invalid_grant) for expired refresh
					// tokens. Reading the body here is safe — we discard it
					// without unmarshalling into auth, so stale fields cannot
					// "look like" a successful refresh.
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					log.Warn().
						Int("status", resp.StatusCode).
						Bytes("body", body).
						Msg("Token refresh returned non-2xx status in CI — tests will be skipped")
				default:
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					oldTime := auth.ExpiresAt
					json.Unmarshal(body, &auth)
					if auth.ExpiresAt == oldTime {
						auth.ExpiresAt = time.Now().Unix() + auth.ExpiresIn
					}
					if auth.AccessToken != "" && auth.RefreshToken != "" {
						auth.ToFile(authTokenPath)
						refreshSucceeded = true
						log.Info().Msg("Tokens refreshed successfully in CI")
					} else {
						log.Warn().Msg("2xx response but missing token fields in CI — tests will be skipped")
					}
				}
			}
		} else {
			log.Warn().Err(err).Msg("Failed to load auth tokens from disk in CI — tests will be skipped")
		}

		// Only attempt to validate tokens against the live Graph API if the
		// refresh succeeded. Otherwise, calling GetUser/GetDrive would cascade
		// into Refresh() → newAuth() → OAuth URL prompt, hanging CI. Setting
		// AuthAvailable=false causes gated tests to skip cleanly with t.Skip().
		if refreshSucceeded {
			user, _ := GetUser(context.Background(), auth)
			drive, _ := GetDrive(context.Background(), auth)
			log.Info().
				Str("account", user.UserPrincipalName).
				Str("type", drive.DriveType).
				Msg("Starting tests (CI, headless)")
		} else if AuthAvailable {
			log.Warn().Msg("Disabling auth tests in CI — credentials unavailable or refresh failed")
			AuthAvailable = false
		}
	}

	code := m.Run()
	if mockServer != nil {
		mockServer.Close()
	}
	os.Exit(code)
}

// keyringGet wraps keyring.Get to avoid direct imports in test setup.
func keyringGet(path string) (string, error) {
	return keyringGetImpl(path)
}
