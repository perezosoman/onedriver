package graph

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

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

func TestMain(m *testing.M) {
	os.Chdir("../..")

	// When ONEDRIVER_MOCK is set, use a local mock server instead of the real
	// Microsoft Graph API.
	if os.Getenv("ONEDRIVER_MOCK") == "1" {
		mockServer := mock.NewServer()
		SetGraphURL(mockServer.URL())
		mockAuth := fmt.Sprintf(
			`{"access_token":"mock-token","refresh_token":"mock-refresh",`+
				`"expires_at":9999999999,"account":"test@mock.local",`+
				`"config":{"tokenURL":"%s/token"}}`,
			mockServer.URL(),
		)
		os.WriteFile(".auth_tokens.json", []byte(mockAuth), 0600)
		fmt.Println("Mock enabled, GraphURL:", mockServer.URL())
		_ = mockServer
	}

	f, _ := os.OpenFile("fusefs_tests.log", os.O_TRUNC|os.O_CREATE|os.O_RDWR, 0644)
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: f, TimeFormat: "15:04:05"})
	defer f.Close()

	// Check if we have valid auth tokens
	authTokenPath := ".auth_tokens.json"
	if hasValidAuthTokens(authTokenPath) {
		AuthAvailable = true
	} else if os.Getenv("CI") == "1" || os.Getenv("ONEDRIVER_MOCK") == "1" {
		// CI/mock mode: skip authenticated tests (no interactive login available)
		fmt.Println("⚠️  OneDrive credentials not available — authenticated tests will be skipped")
	} else {
		// Local mode: let Authenticate() show the OAuth dialog
		fmt.Println("No credentials found — starting OAuth flow to obtain them...")
		AuthAvailable = true
	}

	if AuthAvailable && os.Getenv("CI") != "1" {
		auth := Authenticate(AuthConfig{}, authTokenPath, false)
		user, _ := GetUser(context.Background(), auth)
		drive, _ := GetDrive(context.Background(), auth)
		log.Info().
			Str("account", user.UserPrincipalName).
			Str("type", drive.DriveType).
			Msg("Starting tests")
	}

	os.Exit(m.Run())
}
