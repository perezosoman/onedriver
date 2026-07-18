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

	// CI mode: refresh tokens if expired, but never open GUI/headless prompt
	if AuthAvailable && os.Getenv("CI") != "" {
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
				if err != nil {
					log.Warn().Err(err).Msg("Token refresh failed in CI — tests may fail with expired tokens")
				} else {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					oldTime := auth.ExpiresAt
					json.Unmarshal(body, &auth)
					if auth.ExpiresAt == oldTime {
						auth.ExpiresAt = time.Now().Unix() + auth.ExpiresIn
					}
					if auth.AccessToken != "" && auth.RefreshToken != "" {
						auth.ToFile(authTokenPath)
						log.Info().Msg("Tokens refreshed successfully in CI")
					} else {
						log.Warn().Msg("Token refresh returned invalid tokens in CI")
					}
				}
			}
			user, _ := GetUser(context.Background(), auth)
			drive, _ := GetDrive(context.Background(), auth)
			log.Info().
				Str("account", user.UserPrincipalName).
				Str("type", drive.DriveType).
				Msg("Starting tests (CI, headless)")
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
